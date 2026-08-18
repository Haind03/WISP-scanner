#!/usr/bin/env python3
"""Class-agnostic patch geometry for localization scoring.

This module replaces the ad-hoc, class-gated scoring in `eval/testset/scan_testset.py::_score`
and the `in_file`/`in_fn` logic in `eval/ladder.py`. Two things were wrong there and are fixed here:

1. Geometry was computed only *after* a class check
   (`if path not in gt or cls not in finding_classes: continue`), so "class + file",
   "class + function", and "class + hunk" were entangled and no pure geometric ladder existed.
   Here every geometric field is computed with NO reference to the class, and `class_match` is a
   separate field. A class relabel cannot change any geometric field.

2. A +/-N line window was called a "hunk", and inserted code was scored as if a vulnerable line had
   changed. Here `on_exact_changed_line`, `within_N_changed_lines`, and `same_diff_hunk` are three
   distinct metrics, and insertion-only edits are reported via `near_insertion_boundary`, never as a
   changed vulnerable line.

Deleted vulnerable files are treated as patch-changed (their whole content is a removed region), not
silently skipped. Added patched files are recorded but cannot host a finding on vulnerable input.

The public entry points:
    build_patchmap_from_files(...)   -> PatchMap  (pure; used by unit tests)
    build_patchmap_from_archives(row) -> PatchMap (unzips the corpus archives)
    finding_geometry(patchmap, finding) -> dict   (all class-agnostic geometric fields + class_match)
    validate_nesting(geom) -> list[str]            (nesting invariants; empty == OK)
    finding_uid(...), record_uid(...), run_uid(...), blinded_packet_id(...)

Nothing here mutates production scoring; callers opt in.
"""
from __future__ import annotations
import os, sys, json, hashlib, hmac, uuid, difflib, tempfile, shutil, zipfile
from dataclasses import dataclass, field, asdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

NORMALIZATION_VERSION = "pg1"
DIFF_ALGORITHM = "difflib.SequenceMatcher(autojunk=False)"
DIFF_CONTEXT = 3
# a fixed namespace so uuid5 ids are stable across machines and runs
_NS = uuid.UUID("6f0b2f9a-2c1e-5d6a-9f34-1c7e2a4b8d10")
PROXIMITIES = (2, 5, 10)


# --------------------------------------------------------------------------- paths
def normalize_path(p: str) -> str:
    """Canonical match key: forward slashes, no leading/trailing slash, case-folded.

    Findings and the GT already have the version-carrying top directory stripped (see
    scan_testset._keyof / localize._php_map), so this does NOT strip a component. It only makes
    slash and case consistent."""
    if not p:
        return ""
    s = p.replace("\\", "/").strip("/")
    return s.casefold()


def _is_php(path: str) -> bool:
    return path.casefold().endswith(".php")


# --------------------------------------------------------------------------- scopes
def callable_ranges_from_text(text: str) -> list[tuple[int, int]]:
    """(start_line, end_line) 1-based for each function/method, via the engine parser.

    Kept behind a temp file so we reuse localize._fn_ranges verbatim (same ranges the old scorer
    used), and so a caller can also pass ranges in directly for a pure unit test."""
    from eval.localize import _fn_ranges
    d = tempfile.mkdtemp(prefix="pg_scope_")
    try:
        fp = os.path.join(d, "f.php")
        with open(fp, "w", encoding="utf-8") as fh:
            fh.write(text)
        return _fn_ranges(fp)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def scope_of(line: int, ranges: list[tuple[int, int]], path: str):
    """Lexical scope id of a line. A named function/method is its own scope; code outside every
    function is the file's single TOPLEVEL scope. Two lines share a scope iff this returns the
    same value for both."""
    if not line:
        return None
    best = None
    for s, e in ranges:
        if s <= line <= e and (best is None or (e - s) < (best[1] - best[0])):
            best = (s, e)
    if best is None:
        return ("TOPLEVEL", path)
    return ("FN", path, best[0], best[1])


# --------------------------------------------------------------------------- per-file diff
@dataclass
class FileDiff:
    path: str                                   # normalized
    is_php: bool
    status: str                                 # "modified" | "deleted" | "added"
    vuln_lines: int = 0
    patched_lines: int = 0
    changed_vuln_lines: list[int] = field(default_factory=list)   # replace/delete (1-based)
    patched_side_changed_lines: list[int] = field(default_factory=list)
    insertion_boundaries: list[int] = field(default_factory=list) # vuln-side positions of pure inserts
    hunks: list[dict] = field(default_factory=list)               # per unified-diff hunk, vuln-side span
    callable_ranges: list[tuple[int, int]] = field(default_factory=list)
    top_level_changed_lines: list[int] = field(default_factory=list)


def _diff_file(path: str, vtext: str | None, ptext: str | None, status: str) -> FileDiff:
    is_php = _is_php(path)
    fd = FileDiff(path=path, is_php=is_php, status=status)

    if status == "added":
        fd.patched_lines = len((ptext or "").split("\n"))
        return fd

    a = (vtext or "").split("\n")
    fd.vuln_lines = len(a)
    fd.callable_ranges = callable_ranges_from_text(vtext) if (is_php and vtext) else []

    if status == "deleted":
        # Evaluation Contract v1 s2: a deleted file counts at FILE level only. It no longer exists in
        # the patched tree, so no vulnerable-side line is "the changed line"; we credit no line-,
        # callable-, or hunk-level endpoint for it. in_patched_file still holds because the file is in
        # the changed-file set (patch_changed_php_files includes deleted files).
        fd.changed_vuln_lines = []
        fd.hunks = []
    else:  # modified
        b = (ptext or "").split("\n")
        fd.patched_lines = len(b)
        sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
        changed, pchanged, ins = set(), set(), []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ("replace", "delete"):
                changed.update(range(i1 + 1, i2 + 1))            # vuln-side changed lines
            if tag in ("replace", "insert"):
                pchanged.update(range(j1 + 1, j2 + 1))           # patched-side changed lines
            if tag == "insert":
                ins.append(i1)                                   # inserted BETWEEN vuln line i1 and i1+1
        fd.changed_vuln_lines = sorted(changed)
        fd.patched_side_changed_lines = sorted(pchanged)
        fd.insertion_boundaries = sorted(set(ins))
        # unified-diff hunks (with context) define same_diff_hunk; vuln-side span per hunk
        for group in sm.get_grouped_opcodes(DIFF_CONTEXT):
            v_start = group[0][1] + 1
            v_end = group[-1][2]                                 # inclusive, 1-based
            has_change = any(tag != "equal" for tag, *_ in group)
            fd.hunks.append({"vuln_start": v_start, "vuln_end": max(v_start, v_end),
                             "kind": "modify" if has_change else "context"})

    ranges = fd.callable_ranges
    fd.top_level_changed_lines = [
        c for c in fd.changed_vuln_lines if scope_of(c, ranges, path)[0] == "TOPLEVEL"]
    return fd


# --------------------------------------------------------------------------- PatchMap
@dataclass
class PatchMap:
    record_uid: str
    slug: str
    cve: str
    vulnerable_archive_sha256: str
    patched_archive_sha256: str
    changed_files: list[str]
    deleted_files: list[str]
    added_files: list[str]
    renamed_files_if_detected: list[dict]
    per_file: dict                                   # normalized path -> FileDiff (as dict)
    diff_algorithm: str = DIFF_ALGORITHM
    diff_context: int = DIFF_CONTEXT
    normalization_version: str = NORMALIZATION_VERSION
    notes: list[str] = field(default_factory=list)

    # convenience views -----------------------------------------------------
    @property
    def patch_changed_php_files(self) -> set[str]:
        """PHP files that a finding on vulnerable input could land in: modified or deleted (both
        exist in the vulnerable archive). Added files are excluded."""
        return {p for p, fd in self.per_file.items()
                if fd["is_php"] and fd["status"] in ("modified", "deleted")}

    def file(self, norm_path: str):
        return self.per_file.get(norm_path)

    def hash(self) -> str:
        return _patchmap_hash(self)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["patchmap_hash"] = self.hash()
        return d


def _canonical_for_hash(pm: PatchMap) -> str:
    """Everything that must be byte-identical on a re-run, in a stable order. Excludes the hash
    itself and any archive-path detail."""
    per = {p: {k: pm.per_file[p][k] for k in (
                "is_php", "status", "vuln_lines", "patched_lines", "changed_vuln_lines",
                "patched_side_changed_lines", "insertion_boundaries", "hunks",
                "callable_ranges", "top_level_changed_lines")}
           for p in sorted(pm.per_file)}
    return json.dumps({
        "slug": pm.slug, "cve": pm.cve,
        "vuln_sha256": pm.vulnerable_archive_sha256, "patched_sha256": pm.patched_archive_sha256,
        "changed_files": sorted(pm.changed_files), "deleted_files": sorted(pm.deleted_files),
        "added_files": sorted(pm.added_files), "renamed": pm.renamed_files_if_detected,
        "per_file": per, "diff_algorithm": pm.diff_algorithm, "diff_context": pm.diff_context,
        "normalization_version": pm.normalization_version,
    }, sort_keys=True, separators=(",", ":"))


def _patchmap_hash(pm: PatchMap) -> str:
    return hashlib.sha256(_canonical_for_hash(pm).encode()).hexdigest()


def build_patchmap_from_files(slug: str, cve: str,
                              vuln_files: dict[str, str], patched_files: dict[str, str],
                              vulnerable_archive_sha256: str = "",
                              patched_archive_sha256: str = "") -> PatchMap:
    """Pure builder: vuln_files / patched_files map normalized-path -> file text. Used by unit
    tests and by the archive builder below."""
    vkeys = {normalize_path(k): v for k, v in vuln_files.items()}
    pkeys = {normalize_path(k): v for k, v in patched_files.items()}

    changed, deleted, added = [], [], []
    per_file: dict[str, dict] = {}
    notes: list[str] = []

    for path in sorted(set(vkeys) | set(pkeys)):
        in_v, in_p = path in vkeys, path in pkeys
        if in_v and in_p:
            if vkeys[path] == pkeys[path]:
                continue                                    # unchanged file, not in the patch
            fd = _diff_file(path, vkeys[path], pkeys[path], "modified")
            changed.append(path)
        elif in_v and not in_p:
            fd = _diff_file(path, vkeys[path], None, "deleted")   # NOT skipped
            deleted.append(path)
        else:
            fd = _diff_file(path, None, pkeys[path], "added")
            added.append(path)
        if not fd.is_php:
            notes.append(f"non-php changed file kept in metadata, excluded from localization metric: {path}")
        per_file[path] = asdict(fd)

    # rename detection: we do not claim renames we cannot verify. A deleted+added pair is left as
    # exactly that and flagged, per the brief (treated_as_delete_plus_add).
    renamed: list[dict] = []
    if deleted and added:
        notes.append(f"treated_as_delete_plus_add: {len(deleted)} deleted + {len(added)} added file(s) "
                     "not matched as renames (no reliable rename detection)")

    return PatchMap(
        record_uid=record_uid(slug, cve), slug=slug, cve=cve,
        vulnerable_archive_sha256=vulnerable_archive_sha256,
        patched_archive_sha256=patched_archive_sha256,
        changed_files=changed, deleted_files=deleted, added_files=added,
        renamed_files_if_detected=renamed, per_file=per_file, notes=notes)


def _sha256_file(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_text_map(root: str) -> dict[str, str]:
    """normalized-path -> file text, for PHP files, stripping the single top version dir (matches
    localize._php_map keyspace, then case-folds)."""
    out: dict[str, str] = {}
    for r, _, files in os.walk(root):
        for fn in files:
            if not fn.endswith(".php"):
                continue
            ap = os.path.join(r, fn)
            rel = os.path.relpath(ap, root)
            parts = rel.split(os.sep)
            key = "/".join(parts[1:]) if len(parts) > 1 else rel
            try:
                out[normalize_path(key)] = open(ap, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
    return out


def build_patchmap_from_archives(row: dict) -> PatchMap:
    """Build a PatchMap from a load_rows() record (needs vuln_zip / patched_zip on disk)."""
    from eval.localize import _unzip
    vzip, pzip = row["vuln_zip"], row["patched_zip"]
    vroot = proot = None
    try:
        vroot, proot = _unzip(vzip), _unzip(pzip)
        if not (vroot and proot):
            raise RuntimeError(f"archive_extract_error: {row['slug']}|{row['cve']}")
        vfiles, pfiles = _extract_text_map(vroot), _extract_text_map(proot)
        pm = build_patchmap_from_files(
            row["slug"], row["cve"], vfiles, pfiles,
            vulnerable_archive_sha256=_sha256_file(vzip),
            patched_archive_sha256=_sha256_file(pzip))
        return pm
    finally:
        for d in (vroot, proot):
            if d:
                shutil.rmtree(d, ignore_errors=True)


# --------------------------------------------------------------------------- geometry per finding
def finding_geometry(pm: PatchMap, finding: dict, advisory_class: str,
                     proximities=PROXIMITIES) -> dict:
    """All geometric fields for one finding, computed with NO reference to class, plus the separate
    `class_match`. `finding` needs at least {file, line, reported_classes}."""
    path = normalize_path(finding.get("file", ""))
    line = int(finding.get("line") or 0)
    reported = [c for c in (finding.get("reported_classes") or []) if c]

    fd = pm.per_file.get(path)
    in_patch = path in pm.patch_changed_php_files

    geom = {
        "in_patched_file": bool(in_patch),
        "same_callable_as_change": False,
        "on_exact_changed_line": False,
        "distance_to_nearest_changed_line": None,
        "within_2_changed_lines": False,
        "within_5_changed_lines": False,
        "within_10_changed_lines": False,
        "same_diff_hunk": False,
        "near_insertion_boundary": False,
        "finding_at_top_level": False,
        "change_at_top_level": False,
    }

    if in_patch and fd is not None:
        ranges = [tuple(r) for r in fd["callable_ranges"]]
        changed = fd["changed_vuln_lines"]
        f_scope = scope_of(line, ranges, path)
        geom["finding_at_top_level"] = bool(f_scope and f_scope[0] == "TOPLEVEL")
        geom["change_at_top_level"] = bool(fd["top_level_changed_lines"])

        if changed:
            geom["on_exact_changed_line"] = line in changed
            dist = min(abs(line - c) for c in changed) if line else None
            geom["distance_to_nearest_changed_line"] = dist
            for n in proximities:
                geom[f"within_{n}_changed_lines"] = dist is not None and dist <= n
            changed_scopes = {scope_of(c, ranges, path) for c in changed}
            geom["same_callable_as_change"] = f_scope is not None and f_scope in changed_scopes

        if fd["insertion_boundaries"] and line:
            geom["near_insertion_boundary"] = any(
                abs(line - b) <= 5 or abs(line - (b + 1)) <= 5 for b in fd["insertion_boundaries"])

        for h in fd["hunks"]:
            if line and h["vuln_start"] <= line <= h["vuln_end"]:
                geom["same_diff_hunk"] = True
                break

    # class is a SEPARATE field, never gating the geometry above
    geom["class_match"] = bool(advisory_class and advisory_class in reported)

    # explicit geometric vs class-gated ladder rungs (the split the brief asks for)
    geom["geometric_file"] = geom["in_patched_file"]
    geom["geometric_callable"] = geom["same_callable_as_change"]
    geom["geometric_exact_line"] = geom["on_exact_changed_line"]
    geom["geometric_proximity_5"] = geom["within_5_changed_lines"]
    geom["class_file"] = geom["in_patched_file"] and geom["class_match"]
    geom["class_callable"] = geom["same_callable_as_change"] and geom["class_match"]
    geom["class_exact_line"] = geom["on_exact_changed_line"] and geom["class_match"]
    geom["class_proximity_5"] = geom["within_5_changed_lines"] and geom["class_match"]
    return geom


def validate_nesting(geom: dict) -> list[str]:
    """Return the nesting invariants a geometry dict violates (empty list == valid).

    Every geometric refinement must imply the file rung, and proximity/exact must nest."""
    v = []
    file_ = geom["in_patched_file"]
    for k in ("on_exact_changed_line", "same_callable_as_change", "same_diff_hunk",
              "within_2_changed_lines", "within_5_changed_lines", "within_10_changed_lines"):
        if geom.get(k) and not file_:
            v.append(f"{k} True but in_patched_file False")
    if geom.get("on_exact_changed_line") and not geom.get("within_2_changed_lines"):
        v.append("on_exact_changed_line True but within_2_changed_lines False")
    if geom.get("within_2_changed_lines") and not geom.get("within_5_changed_lines"):
        v.append("within_2 True but within_5 False")
    if geom.get("within_5_changed_lines") and not geom.get("within_10_changed_lines"):
        v.append("within_5 True but within_10 False")
    if geom.get("on_exact_changed_line") and not geom.get("same_diff_hunk"):
        v.append("on_exact_changed_line True but same_diff_hunk False")
    return v


# --------------------------------------------------------------------------- identifiers
def record_uid(slug: str, cve: str) -> str:
    return str(uuid.uuid5(_NS, f"record|{slug}|{cve}"))


def run_uid(tool_config_hash: str, record_uids: list[str]) -> str:
    """Deterministic per input set: identical inputs -> identical run_uid, so a re-run reproduces
    every finding_uid. Changes when the config or the record set changes."""
    h = hashlib.sha256(("|".join(sorted(record_uids))).encode()).hexdigest()
    return str(uuid.uuid5(_NS, f"run|{tool_config_hash}|{h}|{NORMALIZATION_VERSION}"))


def finding_uid(run_uid_: str, record_uid_: str, tool: str, rank: int,
                normalized_path: str, line: int, reported_classes: list[str],
                occurrence_index: int) -> str:
    """Full uuid5 (not a truncated SHA-1). Includes occurrence_index so even identical
    (tool, rank, path, line, classes) tuples get distinct ids."""
    cls = ",".join(sorted(reported_classes or []))
    key = "|".join([run_uid_, record_uid_, tool, str(rank), normalized_path,
                    str(line), cls, str(occurrence_index)])
    return str(uuid.uuid5(_NS, "finding|" + key))


def blinded_packet_id(finding_uid_: str, secret: str) -> str:
    """Reviewer-facing id. HMAC-SHA256 under a secret the reviewer never sees, so the tool cannot be
    inferred from the id and packets are never joined by row position. Keep the
    finding_uid -> packet_id mapping private."""
    return hmac.new(secret.encode(), finding_uid_.encode(), hashlib.sha256).hexdigest()


def tool_config_hash(descriptor: dict) -> str:
    return hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
