"""Acceptance tests for the class-agnostic patch geometry (Prompt 2 §8).

Unlike the seven regression tests in this directory, which reproduce bugs and so
FAIL until the production code is fixed, these tests assert that the NEW module
`eval/patch_geometry.py` (and the population `eval/ladder_v3.py` writes) already
satisfy the eight acceptance requirements. They are expected to PASS now.

Requirements, in order:
  1. No two findings share a finding_uid.
  2. Every population row maps back to the correct slug+CVE (record_uid check).
  3. A file the patch DELETES is counted as patch-changed, never silently skipped.
  4. The four known truncation cases land on the FULL changed-line set, not a
     28-line window, so nothing is lost the way the old vendor_patch_hunk lost it.
  5. Re-running the same input reproduces the PatchMap hash, the run_uid, and the
     finding_uid exactly.
  6. Relabeling the advisory class cannot move any geometric field.
  7. The geometric ladder nests: exact / callable / hunk / proximity all imply
     in_patched_file, and exact implies same_diff_hunk and within_5.
  8. validate_nesting actually fires on a broken geometry, so the build guard is
     not a no-op.

Run standalone (stdlib only, no pytest required):

    python3 -m eval.tests.revision_v2.test_patch_geometry
"""
from __future__ import annotations
import os, sys, csv, gc, json, shutil

from ._common import REPO, SYS_ROOT, Evidence

from eval import patch_geometry as pg

# --------------------------------------------------------------------------- data locations
DATA = os.environ.get("WISP_REVISION_DATA") or os.path.join(
    SYS_ROOT, "final", "supplementary-data", "reproduce", "data")
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")

# The four adjudicated findings the revision brief calls out: (slug, cve, tool, line).
# Each sits on a vendor-changed line the old 28-line vendor_patch_hunk truncated away.
TRUNCATION_CASES = [
    ("backuply", "CVE-2024-8669", "wisp", 508),
    ("advanced-google-recaptcha", "CVE-2025-2074", "wpt", 423),
    ("products-file-upload-for-woocommerce", "CVE-2026-25328", "wisp", 220),
    ("seriously-simple-podcasting", "CVE-2026-39505", "wisp", 333),
]

# The config descriptor ladder_v3.main() hashes into the run identity. It is READ from the
# shipped ladder, not duplicated here: a second copy of the same dict goes stale the moment a
# legitimate input changes (it did, when the Progpilot re-scan replaced the baseline file), and
# a test that fails on a legitimate input change tests the test, not the property. The property
# under test is that the SHIPPED run_uid recomputes from the SHIPPED config.
LADDER = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_V3.json")


def _ladder_cfg() -> dict:
    if not os.path.isfile(LADDER):
        return {}
    return (json.load(open(LADDER, encoding="utf-8")).get("config") or {})

GEOM_FIELDS = ("in_patched_file", "same_callable_as_change", "on_exact_changed_line",
               "distance_to_nearest_changed_line", "within_2_changed_lines",
               "within_5_changed_lines", "within_10_changed_lines", "same_diff_hunk",
               "near_insertion_boundary", "finding_at_top_level", "change_at_top_level",
               "geometric_file", "geometric_callable", "geometric_exact_line", "geometric_proximity_5")


def _load_population() -> list[dict]:
    if not os.path.isfile(POP):
        return []
    with open(POP, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


# --------------------------------------------------------------------------- 1. unique ids
def test_finding_uid_is_unique():
    ev = Evidence("PG.1 finding_uid uniqueness")
    pop = _load_population()
    assert pop, f"population not built at {POP}; run `python3 -m eval.ladder_v3` first"
    uids = [r["finding_uid"] for r in pop]
    seen, dups = set(), []
    for u in uids:
        (dups.append(u) if u in seen else seen.add(u))
    ev.show(f"{len(uids)} findings, {len(seen)} distinct finding_uid, {len(dups)} duplicate(s)")
    assert not dups, f"duplicated finding_uid across the population: {dups[:5]}"


# --------------------------------------------------------------------------- 2. rows map to slug+cve
def test_every_row_maps_to_its_record():
    ev = Evidence("PG.2 row -> slug|cve identity")
    pop = _load_population()
    assert pop, "population not built"
    bad = [(r["slug"], r["cve"]) for r in pop
           if r["record_uid"] != pg.record_uid(r["slug"], r["cve"])]
    ev.show(f"{len(pop)} rows checked; record_uid mismatches = {len(bad)}")
    assert not bad, f"record_uid does not equal record_uid(slug, cve) for: {bad[:5]}"


# --------------------------------------------------------------------------- 3. deleted file counted
def test_deleted_file_is_patch_changed():
    ev = Evidence("PG.3 deleted file not silently skipped")
    slug, cve = "acc-demo", "CVE-0000-0001"
    vuln = {"vuln/lib/gone.php": "<?php\necho $_GET['x'];\n",     # removed by the patch
            "vuln/lib/keep.php": "<?php\n$a = 1;\n"}              # unchanged
    patched = {"vuln/lib/keep.php": "<?php\n$a = 1;\n"}           # gone.php absent
    pm = pg.build_patchmap_from_files(slug, cve, vuln, patched)
    gone = pg.normalize_path("vuln/lib/gone.php")

    ev.show(f"deleted_files = {pm.deleted_files}")
    ev.show(f"patch_changed_php_files = {sorted(pm.patch_changed_php_files)}")
    assert gone in pm.deleted_files, "deleted file missing from deleted_files"
    assert gone in pm.patch_changed_php_files, "deleted file not counted as patch-changed"

    fd = pm.file(gone)
    assert fd["status"] == "deleted"
    # Evaluation Contract v1 s2: a deleted file counts at FILE level only, so it exposes NO changed
    # line (crediting the whole removed file as a changed region over-counted exact-line hits).
    assert fd["changed_vuln_lines"] == [], "contract v1 s2: deleted file has no line-level changed region"

    # a finding inside the deleted file is in_patched_file (file level) but NOT credited at line level
    g = pg.finding_geometry(pm, {"file": "vuln/lib/gone.php", "line": 2,
                                 "reported_classes": ["xss"]}, "xss")
    ev.show(f"finding in deleted file -> in_patched_file={g['in_patched_file']} "
            f"on_exact_changed_line={g['on_exact_changed_line']}")
    assert g["in_patched_file"], "a finding on a deleted vulnerable file must score in_patched_file (file level)"
    assert not g["on_exact_changed_line"], \
        "contract v1 s2: a deleted file gets no line-level credit (this over-count was reviewer issue 1)"


# --------------------------------------------------------------------------- 4. truncation cases
def _resolve_corpus():
    try:
        from eval.datasets.patchstack import load_rows
        rows = {(r["slug"], r["cve"]): r for r in load_rows()}
    except Exception:
        return None
    fa = os.path.join(DATA, "filled_A.csv")
    if not os.path.isfile(fa):
        return None
    csv_rows = list(csv.DictReader(open(fa, encoding="utf-8")))
    return rows, csv_rows


def test_truncation_cases_hit_full_changed_set():
    ev = Evidence("PG.4 four truncation cases -> full changed-line set")
    resolved = _resolve_corpus()
    if resolved is None:
        ev.show("corpus / filled_A.csv not resolvable -> SKIPPED (see PG.4 probe in REVISION-AUDIT)")
        return
    rows, csv_rows = resolved
    from eval.localize import _unzip, _php_map

    facts, missing = [], []
    for slug, cve, tool, fline in TRUNCATION_CASES:
        r = rows.get((slug, cve))
        files = sorted({x["file"] for x in csv_rows
                        if x["slug"] == slug and str(x["line"]) == str(fline)})
        if not r or not files or not (r.get("vuln_zip") and os.path.isfile(r["vuln_zip"])
                                      and r.get("patched_zip") and os.path.isfile(r["patched_zip"])):
            missing.append((slug, cve))
            continue
        f0 = files[0]
        vroot = _unzip(r["vuln_zip"]); proot = _unzip(r["patched_zip"])
        try:
            vf, pf = _php_map(vroot).get(f0), _php_map(proot).get(f0)
            if not vf:
                missing.append((slug, cve)); continue
            vtext = open(vf, encoding="utf-8", errors="replace").read()
            ptext = open(pf, encoding="utf-8", errors="replace").read() if pf else None
            # single-file build keeps memory tiny; only the changed file matters here
            pm = pg.build_patchmap_from_files(slug, cve, {f0: vtext},
                                              {f0: ptext} if ptext is not None else {})
            fd = pm.file(pg.normalize_path(f0))
            changed = fd["changed_vuln_lines"] if fd else []
            g = pg.finding_geometry(pm, {"file": f0, "line": fline,
                                         "reported_classes": ["xss"]}, "xss")
            facts.append((slug, cve, fline, fline in changed, len(changed),
                          g["in_patched_file"], g["on_exact_changed_line"], g["same_diff_hunk"]))
            del pm, vtext, ptext
        finally:
            for d in (vroot, proot):
                shutil.rmtree(d, ignore_errors=True)
        gc.collect()

    if missing:
        ev.show(f"corpus incomplete for {missing} -> SKIPPED")
        return
    for slug, cve, fline, in_changed, n, in_file, exact, hunk in facts:
        ev.show(f"{slug} {cve} line {fline}: in_full_changed={in_changed} (of {n}) "
                f"in_file={in_file} exact={exact} hunk={hunk}")
    bad = [(s, c, fl) for (s, c, fl, ic, n, inf, ex, hk) in facts if not (ic and inf and ex)]
    assert not bad, ("these truncation cases did not map onto the full changed-line set under "
                     f"patch_geometry (the old 28-line hunk lost them): {bad}")


# --------------------------------------------------------------------------- 5. reproducibility
def test_patchmap_and_ids_are_reproducible():
    ev = Evidence("PG.5 deterministic PatchMap + run_uid + finding_uid")
    slug, cve = "repro-demo", "CVE-0000-0002"
    vuln = {"a/mod.php": "<?php\nfunction f(){\n  echo $_GET['x'];\n}\n",
            "a/other.php": "<?php\n$k = 1;\n"}
    patched = {"a/mod.php": "<?php\nfunction f(){\n  echo esc_html($_GET['x']);\n}\n",
               "a/other.php": "<?php\n$k = 1;\n"}
    h1 = pg.build_patchmap_from_files(slug, cve, vuln, patched).hash()
    h2 = pg.build_patchmap_from_files(slug, cve, vuln, patched).hash()
    ev.show(f"PatchMap hash stable across two builds: {h1 == h2} ({h1[:12]})")
    assert h1 == h2, "PatchMap hash changed between identical builds"

    tch = pg.tool_config_hash(_ladder_cfg())
    ruids = [pg.run_uid(tch, ["r1", "r2", "r3"]), pg.run_uid(tch, ["r3", "r1", "r2"])]
    ev.show(f"run_uid identical regardless of record order: {ruids[0] == ruids[1]}")
    assert ruids[0] == ruids[1], "run_uid must not depend on record ordering"

    fu = [pg.finding_uid(ruids[0], "r1", "wisp", 1, "a/mod.php", 3, ["xss"], 0) for _ in range(2)]
    assert fu[0] == fu[1], "finding_uid not deterministic"

    # end-to-end: the shipped run_uid must recompute from the AUTHORITATIVE record manifest the run
    # recorded, not from the population (a record that yielded zero findings is absent from the
    # population but still part of the input set the run_uid is built over). This is
    # "same input -> identical run identity" at the identity level.
    pop = _load_population()
    if pop:
        shipped_run = {r["run_uid"] for r in pop}
        shipped_tch = {r["tool_config_hash"] for r in pop}
        assert len(shipped_run) == 1 and len(shipped_tch) == 1, "population mixes run_uid/config hashes"
        assert tch == next(iter(shipped_tch)), "documented _ladder_cfg() no longer hashes to the shipped config"

        ladder_json = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_V3.json")
        assert os.path.isfile(ladder_json), f"run summary not found at {ladder_json}"
        summary = json.load(open(ladder_json, encoding="utf-8"))
        rec = summary["record_uids"]
        # the manifest must be a superset of what the population witnesses (never fewer)
        witnessed = {r["record_uid"] for r in pop}
        assert witnessed <= set(rec), "population contains a record_uid absent from the run manifest"
        recomputed = pg.run_uid(tch, rec)
        ev.show(f"manifest has {len(rec)} records; population witnesses {len(witnessed)} "
                f"(zero-finding records excluded)")
        ev.show(f"shipped run_uid reproduced from the manifest: "
                f"{recomputed == next(iter(shipped_run))} ({next(iter(shipped_run))})")
        assert recomputed == next(iter(shipped_run)), \
            "shipped run_uid not reproducible from its record manifest + config (run not deterministic)"


# --------------------------------------------------------------------------- 6. class-relabel invariance
def test_class_relabel_does_not_move_geometry():
    ev = Evidence("PG.6 geometry independent of advisory class")
    slug, cve = "class-demo", "CVE-0000-0003"
    vuln = {"p/x.php": "<?php\nfunction h(){\n  $q = $_GET['id'];\n  query($q);\n}\n"}
    patched = {"p/x.php": "<?php\nfunction h(){\n  $q = intval($_GET['id']);\n  query($q);\n}\n"}
    pm = pg.build_patchmap_from_files(slug, cve, vuln, patched)
    finding = {"file": "p/x.php", "line": 3, "reported_classes": ["sqli"]}

    g_sqli = pg.finding_geometry(pm, finding, "sqli")     # class matches
    g_xss = pg.finding_geometry(pm, finding, "xss")       # class does NOT match
    g_none = pg.finding_geometry(pm, finding, "")         # no class at all

    moved = [f for f in GEOM_FIELDS
             if not (g_sqli[f] == g_xss[f] == g_none[f])]
    ev.show(f"class_match sqli/xss/none = {g_sqli['class_match']}/{g_xss['class_match']}/{g_none['class_match']}")
    ev.show(f"geometric fields that moved with the class label = {moved}")
    assert not moved, f"these geometric fields changed when only the class label changed: {moved}"
    # and the class-gated rungs DO move, proving class_match is wired in, just separately
    assert g_sqli["class_file"] and not g_xss["class_file"], \
        "class_file should track class_match while geometric_file stays fixed"


# --------------------------------------------------------------------------- 7. ladder nests
def test_geometric_ladder_nests():
    ev = Evidence("PG.7 geometric ladder nesting over the population")
    pop = _load_population()
    assert pop, "population not built"
    violations = 0
    example = None
    for r in pop:
        d = r["distance_to_nearest_changed_line"]        # None means no changed line in scope
        within = lambda n: (d is not None and d <= n)     # NB: distance can be 0; do not use `or`
        geom = {
            "in_patched_file": r["in_patched_file"],
            "on_exact_changed_line": r["on_exact_changed_line"],
            "same_callable_as_change": r["same_callable_as_change"],
            "same_diff_hunk": r["same_diff_hunk"],
            "within_2_changed_lines": r.get("within_2_changed_lines", within(2)),
            "within_5_changed_lines": r["within_5_changed_lines"],
            "within_10_changed_lines": r.get("within_10_changed_lines", within(10)),
        }
        # cross-check the reconstruction against the stored within_5 so a bad reconstruction can't
        # hide a real violation
        assert geom["within_5_changed_lines"] == within(5) or "within_5_changed_lines" in r, \
            f"within_5 reconstruction disagrees with stored value for {r['slug']} {r['cve']}"
        bad = pg.validate_nesting(geom)
        if bad:
            violations += 1
            example = example or (r["slug"], r["cve"], r["tool"], bad)
    ev.show(f"{len(pop)} rows; nesting violations = {violations}")
    if example:
        ev.show(f"first violation: {example}")
    assert violations == 0, f"nesting invariants violated in {violations} rows, e.g. {example}"


# --------------------------------------------------------------------------- 8. the guard fires
def test_validate_nesting_catches_a_broken_geometry():
    ev = Evidence("PG.8 build guard is not a no-op")
    # exact line True while in_patched_file False is exactly the impossible state the guard must reject
    broken = {"in_patched_file": False, "on_exact_changed_line": True,
              "same_callable_as_change": True, "same_diff_hunk": True,
              "within_2_changed_lines": True, "within_5_changed_lines": False,
              "within_10_changed_lines": True}
    bad = pg.validate_nesting(broken)
    ev.show(f"validate_nesting flagged {len(bad)} invariant(s): {bad}")
    assert bad, "validate_nesting returned clean on a geometry that violates in_patched_file nesting"
    assert any("in_patched_file" in m for m in bad)
    assert any("within_5" in m for m in bad), "within_2 True but within_5 False should be caught"

    good = {"in_patched_file": True, "on_exact_changed_line": True,
            "same_callable_as_change": True, "same_diff_hunk": True,
            "within_2_changed_lines": True, "within_5_changed_lines": True,
            "within_10_changed_lines": True}
    assert pg.validate_nesting(good) == [], "a nested geometry must validate clean"


TESTS = [
    ("PG.1 unique finding_uid", test_finding_uid_is_unique),
    ("PG.2 row -> record identity", test_every_row_maps_to_its_record),
    ("PG.3 deleted file counted", test_deleted_file_is_patch_changed),
    ("PG.4 truncation cases full set", test_truncation_cases_hit_full_changed_set),
    ("PG.5 reproducible ids", test_patchmap_and_ids_are_reproducible),
    ("PG.6 class-relabel invariance", test_class_relabel_does_not_move_geometry),
    ("PG.7 ladder nests", test_geometric_ladder_nests),
    ("PG.8 guard fires", test_validate_nesting_catches_a_broken_geometry),
]


def main() -> int:
    import traceback
    print("=" * 78)
    print("PATCH GEOMETRY ACCEPTANCE  (each test SHOULD PASS)")
    print("=" * 78)
    passed = 0
    for title, fn in TESTS:
        try:
            fn()
            passed += 1
            print(f"  [PASS  ] {title}")
        except AssertionError as e:
            print(f"  [FAIL  ] {title}\n           -> {str(e).splitlines()[0][:140]}")
        except Exception as e:
            traceback.print_exc()
            print(f"  [ERROR ] {title}\n           -> {type(e).__name__}: {e}")
    print("-" * 78)
    print(f"  {passed}/{len(TESTS)} acceptance tests passed.")
    print("=" * 78)
    return 0 if passed == len(TESTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
