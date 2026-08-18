#!/usr/bin/env python3
"""Tier 1 of adjudication v3: build EMPTY defect-card templates + the context two experts read.

Before any scanner finding is seen, two independent experts characterize what the vendor patch
actually fixed. This script prepares only what they read (advisory metadata, CVE/CWE hint, versions,
the FULL uncut diff, the changelog when the plugin ships one, and a mechanical build/vendor-noise
hint) and the EMPTY sheets they fill. It writes NO labels. A human must fill every reviewer field.

Outputs under revision-cns-v2/adjudication/tier1/:
  context/<record_uid>.md          human-readable advisory + full diff for each record
  DEFECT_CARDS_CONTEXT.json        machine copy of the same context (no human fields)
  reviewer_A_defect_cards.json     empty per-record card fields for expert A
  reviewer_B_defect_cards.json     empty per-record card fields for expert B
  resolution.json                  empty A-vs-B resolution, filled in a third step
  REVIEWER_METADATA_TEMPLATE.json  empty expertise / independence / COI form
  MANIFEST.json                    schema version + content hash of every file above

    python3 -m eval.build_defect_cards_v3
"""
from __future__ import annotations
import os, sys, glob, shutil, difflib, zipfile, hashlib, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows, PS_DIR
from eval.localize import _unzip
from eval import patch_geometry as pg
from eval import adjudication_v3_common as C


def _xlsx_metadata() -> dict:
    """(slug, cve) -> advisory metadata columns from the Patchstack label sheets."""
    out: dict = {}
    try:
        import openpyxl
    except Exception:
        return out
    for xf in sorted(glob.glob(os.path.join(PS_DIR, "patchstack_*.xlsx"))):
        try:
            wb = openpyxl.load_workbook(xf, read_only=True)
        except Exception:
            continue
        ws = wb.active
        it = ws.iter_rows(values_only=True)
        header = [str(h).strip() if h is not None else "" for h in next(it)]
        idx = {h: i for i, h in enumerate(header)}

        def cell(row, name):
            i = idx.get(name)
            return row[i] if i is not None and i < len(row) else None
        for row in it:
            slug, cve = cell(row, "Slug"), cell(row, "CVE")
            if not slug or not cve:
                continue
            out[(str(slug), str(cve))] = {
                "plugin_name": cell(row, "Plugin"), "advisory_type_label": cell(row, "Vulnerability Type"),
                "cvss": cell(row, "CVSS"), "affected_range": cell(row, "Affected (Patchstack)"),
                "disclosure_date": str(cell(row, "Disclosure") or ""),
                "active_installs": cell(row, "Active Installs"),
                "patchstack_reference": cell(row, "Patchstack Reference"),
            }
        wb.close()
    return out


def _rel_fileset(root: str) -> dict:
    """top-dir-stripped relative path -> (sha256, is_text) for every file in an extracted archive."""
    out: dict = {}
    for r, _, files in os.walk(root):
        for fn in files:
            ap = os.path.join(r, fn)
            rel = os.path.relpath(ap, root).replace(os.sep, "/")
            parts = rel.split("/")
            key = "/".join(parts[1:]) if len(parts) > 1 else rel
            try:
                data = open(ap, "rb").read()
            except OSError:
                continue
            is_text = fn.lower().endswith((".php", ".inc", ".phtml"))
            out[key] = (hashlib.sha256(data).hexdigest(),
                        data.decode("utf-8", "ignore") if is_text else None)
    return out


def _full_diff(vtext: str, ptext: str) -> str:
    """The vendor's complete change for one file, uncut (all hunks, standard context)."""
    v, p = vtext.split("\n"), ptext.split("\n")
    return "\n".join(l for l in difflib.unified_diff(v, p, lineterm="", n=3)
                     if not l.startswith(("---", "+++")))


def _changelog(pzip: str) -> str:
    """Best-effort changelog excerpt from the patched plugin's readme.txt. Empty when absent."""
    try:
        z = zipfile.ZipFile(pzip)
    except Exception:
        return ""
    names = [n for n in z.namelist() if n.lower().endswith("readme.txt")]
    names.sort(key=len)                                   # top-level readme first
    for n in names:
        try:
            txt = z.read(n).decode("utf-8", "replace")
        except Exception:
            continue
        low = txt.lower()
        i = low.find("== changelog")
        if i != -1:
            return txt[i:i + 1500].strip()
    return ""


def _context_for_record(row: dict, meta: dict) -> dict:
    """The full read-only context for one advisory. Mechanical only, no security judgment."""
    slug, cve = row["slug"], row["cve"]
    ruid = pg.record_uid(slug, cve)
    vroot = proot = None
    diffs, changed_files, deleted_files, added_files, noise = [], [], [], [], []
    try:
        vroot, proot = _unzip(row["vuln_zip"]), _unzip(row["patched_zip"])
        vset, pset = _rel_fileset(vroot), _rel_fileset(proot)
        for path in sorted(set(vset) | set(pset)):
            inv, inp = path in vset, path in pset
            vh = vset[path][0] if inv else None
            ph = pset[path][0] if inp else None
            if inv and inp:
                if vh == ph:
                    continue                              # unchanged
                changed_files.append(path)
                if vset[path][1] is not None and pset[path][1] is not None:
                    d = _full_diff(vset[path][1], pset[path][1])
                    if d:
                        diffs.append({"file": path, "diff": d,
                                      "possibly_non_security": C.non_security_hint(path)})
            elif inv and not inp:
                deleted_files.append(path)
            else:
                added_files.append(path)
            if C.non_security_hint(path):
                noise.append(path)
    finally:
        for d in (vroot, proot):
            if d:
                shutil.rmtree(d, ignore_errors=True)

    m = meta.get((slug, cve), {})
    return {
        "record_uid": ruid, "slug": slug, "cve": cve,
        "advisory_class": row["cls"], "advisory_type_label": row.get("type") or m.get("advisory_type_label"),
        "derived_cwe_hint": C.CLASS_TO_CWE.get(row["cls"], ""),
        "derived_cwe_note": "CWE derived from the class label only; the reviewer confirms it.",
        "plugin_name": m.get("plugin_name"), "cvss": m.get("cvss"),
        "affected_range": m.get("affected_range"), "disclosure_date": m.get("disclosure_date"),
        "active_installs": m.get("active_installs"), "patchstack_reference": m.get("patchstack_reference"),
        "vulnerable_version": row.get("vuln_version"), "patched_version": row.get("patched_version"),
        "vulnerable_archive_sha256": pg._sha256_file(row["vuln_zip"]),
        "patched_archive_sha256": pg._sha256_file(row["patched_zip"]),
        "changed_files": changed_files, "deleted_files": deleted_files, "added_files": added_files,
        "heuristic_possibly_non_security_paths": sorted(set(noise)),
        "heuristic_note": "Mechanical build/vendor/asset guess only; NOT a security judgment. The "
                          "reviewer decides which files/hunks are security-relevant.",
        "full_diff_uncut": diffs,
        "vendor_changelog_excerpt": _changelog(row["patched_zip"]),
    }


def _empty_card_fields(fields) -> dict:
    return {k: "" for k in fields}


def _context_md(ctx: dict) -> str:
    """Human-readable page a Tier-1 reviewer reads. Advisory facts + full uncut diff, no labels."""
    L = [f"# Defect card context — {ctx['slug']} {ctx['cve']}",
         "",
         f"- record_uid: `{ctx['record_uid']}`",
         f"- advisory class (dataset label): **{ctx['advisory_class']}**  "
         f"(type: {ctx['advisory_type_label']})",
         f"- derived CWE hint: {ctx['derived_cwe_hint'] or 'n/a'}  ({ctx['derived_cwe_note']})",
         f"- plugin: {ctx['plugin_name']}   CVSS: {ctx['cvss']}   affected: {ctx['affected_range']}",
         f"- vulnerable version: {ctx['vulnerable_version']}   patched version: {ctx['patched_version']}",
         f"- disclosure: {ctx['disclosure_date']}   reference: {ctx['patchstack_reference']}",
         f"- vulnerable archive sha256: `{ctx['vulnerable_archive_sha256']}`",
         f"- patched archive sha256: `{ctx['patched_archive_sha256']}`",
         "",
         f"## Files the patch touched",
         f"- changed: {ctx['changed_files'] or 'none'}",
         f"- deleted: {ctx['deleted_files'] or 'none'}",
         f"- added: {ctx['added_files'] or 'none'}",
         f"- heuristic possibly-non-security paths (consider, do not trust): "
         f"{ctx['heuristic_possibly_non_security_paths'] or 'none'}",
         "",
         "## Vendor changelog excerpt",
         "```",
         ctx["vendor_changelog_excerpt"] or "(none shipped in readme.txt)",
         "```",
         "",
         "## Full patch diff (uncut)",
         ""]
    if not ctx["full_diff_uncut"]:
        L.append("_(no PHP text diff; see the file list above)_")
    for d in ctx["full_diff_uncut"]:
        tag = "  [heuristic: possibly non-security]" if d["possibly_non_security"] else ""
        L += [f"### {d['file']}{tag}", "```diff", d["diff"], "```", ""]
    L += ["---",
          "You are labeling the PATCH, not any scanner output. You do not see tool names, rankings,",
          "or scanner findings. Fill your own defect-card sheet. Leave a field blank if unknown."]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", default="", help="optional file of slug|cve keys; default = geometry manifest")
    a = ap.parse_args()

    keys = ([l.strip() for l in open(a.records) if l.strip()] if a.records
            else C.load_manifest_records())
    keyset = set(keys)
    meta = _xlsx_metadata()
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    missing = [k for k in keyset if k not in rows]
    if missing:
        sys.exit(f"{len(missing)} manifest record(s) not in the corpus, e.g. {missing[:3]}")

    os.makedirs(os.path.join(C.TIER1_DIR, "context"), exist_ok=True)
    contexts, card_a, card_b, resolution = [], {}, {}, {}
    for i, key in enumerate(sorted(keyset), 1):
        ctx = _context_for_record(rows[key], meta)
        contexts.append(ctx)
        ruid = ctx["record_uid"]
        with open(os.path.join(C.TIER1_DIR, "context", f"{ruid}.md"), "w", encoding="utf-8") as fh:
            fh.write(_context_md(ctx))
        card_a[ruid] = _empty_card_fields(C.DEFECT_CARD_REVIEWER_FIELDS)
        card_b[ruid] = _empty_card_fields(C.DEFECT_CARD_REVIEWER_FIELDS)
        resolution[ruid] = _empty_card_fields(C.DEFECT_CARD_RESOLUTION_FIELDS)
        if i % 20 == 0:
            print(f"  ...{i}/{len(keyset)} contexts", flush=True)

    ctx_payload = {"records": sorted(keyset), "cards": contexts}
    files = {
        "DEFECT_CARDS_CONTEXT.json": C.envelope("tier1_defect_card_context", ctx_payload),
        "reviewer_A_defect_cards.json": C.envelope(
            "tier1_reviewer_sheet", {"reviewer": "A", "fields": C.DEFECT_CARD_REVIEWER_FIELDS,
                                     "cards": card_a}),
        "reviewer_B_defect_cards.json": C.envelope(
            "tier1_reviewer_sheet", {"reviewer": "B", "fields": C.DEFECT_CARD_REVIEWER_FIELDS,
                                     "cards": card_b}),
        "resolution.json": C.envelope(
            "tier1_resolution", {"fields": C.DEFECT_CARD_RESOLUTION_FIELDS, "cards": resolution}),
        "REVIEWER_METADATA_TEMPLATE.json": C.envelope(
            "reviewer_metadata", {"fields": C.REVIEWER_METADATA_FIELDS,
                                  "reviewer_A": _empty_card_fields(C.REVIEWER_METADATA_FIELDS),
                                  "reviewer_B": _empty_card_fields(C.REVIEWER_METADATA_FIELDS)}),
    }
    for name, env in files.items():
        C.write_json(os.path.join(C.TIER1_DIR, name), env)

    manifest = C.envelope("tier1_manifest", {
        "tier": 1, "n_records": len(keyset),
        "files": {name: env["content_hash"] for name, env in files.items()},
        "human_labels_present": False,
        "note": "Tier 1 is empty. Two experts fill reviewer_A/reviewer_B; a third step fills "
                "resolution.json. Nothing here was labeled by a program.",
    })
    C.write_json(os.path.join(C.TIER1_DIR, "MANIFEST.json"), manifest)

    print(f"\ntier1: {len(keyset)} defect-card contexts -> {C.TIER1_DIR}")
    print("  reviewer sheets are EMPTY; humans must fill them before Tier 2 labeling begins.")


if __name__ == "__main__":
    main()
