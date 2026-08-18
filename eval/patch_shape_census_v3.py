#!/usr/bin/env python3
"""Patch-shape census and the exact-line sensitivity the Evaluation Contract requires.

Contract v1 s2 asks for two things that were specified and then never computed:

  * "the count of records in each category (modified-only, has-deleted, has-added,
    has-rename, pure-insertion) on every dataset";
  * "every headline endpoint, recomputed with and without deleted-file records" and
    "with and without pure-insertion records".

Why it matters. The exact-line rung credits a finding only when its line is on the
vulnerable side of a `delete` or `replace` block (eval/patch_geometry.py:135-142). Two
common patch shapes therefore have NO exact-line target at all, yet their records stay
in the denominator:

  * a patch that only inserts (the archetypal WordPress fix: add a capability check or
    an escaping call before an otherwise unchanged sink), and
  * a file the patch deletes outright, which contract s2 scores at file level only.

Findings on those records can never be exact-line hits. Reporting the rung without
saying how much of the denominator is structurally unhittable overstates how much of
the drop is a tool property. This script measures it.

    python3 -m eval.patch_shape_census_v3                      # all datasets
    python3 -m eval.patch_shape_census_v3 --dataset matched-100

Writes revision-cns-v2/out/PATCH_SHAPE_CENSUS_V3.json (per-dataset counts + per-record
rows) and, for matched-100, the exact-line sensitivity over the shipped top-3 finding
population.
"""
from __future__ import annotations
import os, sys, json, argparse, time
from collections import Counter, defaultdict
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.datasets.patchstack import load_rows
from eval.testset.scan_testset import classify_type
from eval import patch_geometry as pg

OUT_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
OUT = os.path.join(OUT_DIR, "PATCH_SHAPE_CENSUS_V3.json")
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
MATCHED_SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
TOPK = 3
BOOT_REPS = 10000
BOOT_SEED = 20260730


# --------------------------------------------------------------------------- record shapes
def shape_of(pm) -> dict:
    """Classify one record's patch by the shape of its PHP changed-file set.

    Every count below is over PHP files only, because a finding is a PHP location: a
    changed .js or .css file can never host one, so counting it would understate the
    share of records whose PHP surface is unhittable.
    """
    php = {p: fd for p, fd in pm.per_file.items() if fd["is_php"]}
    scored = {p: fd for p, fd in php.items() if fd["status"] in ("modified", "deleted")}
    deleted = [p for p, fd in scored.items() if fd["status"] == "deleted"]
    modified = [p for p, fd in scored.items() if fd["status"] == "modified"]
    added = [p for p, fd in php.items() if fd["status"] == "added"]

    # a modified file with no vulnerable-side changed line is a pure insertion: the patch
    # only added lines to it, so no line of the vulnerable tree is "the changed line".
    pure_ins = [p for p in modified if not scored[p]["changed_vuln_lines"]
                and scored[p]["insertion_boundaries"]]
    anchored = [p for p in modified if scored[p]["changed_vuln_lines"]]

    cats = []
    if deleted:
        cats.append("has-deleted")
    if added:
        cats.append("has-added")
    if pm.renamed_files_if_detected:
        cats.append("has-rename")
    if pure_ins:
        cats.append("has-pure-insertion")
    if not cats and modified:
        cats.append("modified-only")

    return {
        "n_php_scored_files": len(scored),
        "n_php_modified": len(modified),
        "n_php_deleted": len(deleted),
        "n_php_added": len(added),
        "n_php_renamed": len(pm.renamed_files_if_detected or []),
        "n_php_pure_insertion": len(pure_ins),
        "n_php_anchored": len(anchored),
        # the record-level question the sensitivity turns on: does ANY changed PHP file
        # offer at least one vulnerable-side changed line for a finding to land on?
        "has_exact_line_target": bool(anchored),
        "categories": cats,
        "n_changed_vuln_lines": sum(len(scored[p]["changed_vuln_lines"]) for p in modified),
        "unanchorable_php_files": sorted(deleted + pure_ins),
    }


def _one(row):
    key = row["slug"] + "|" + row["cve"]
    try:
        pm = pg.build_patchmap_from_archives(row)
    except Exception as exc:
        return {"key": key, "slug": row["slug"], "cve": row["cve"],
                "error": f"{type(exc).__name__}: {exc}"}
    s = shape_of(pm)
    # The per-record changed-PHP-file list doubles as the diff-based ground truth the
    # Zenodo record is supposed to ship (its ground_truth.csv is an unrelated engine
    # development fixture), so it is emitted here rather than derived a second time.
    s.update({"key": key, "slug": row["slug"], "cve": row["cve"],
              "cls": row.get("cls", ""),
              "vuln_version": row.get("vuln_version", ""),
              "changed_php_files": sorted(pm.patch_changed_php_files),
              "patchmap_hash": pm.hash(), "error": ""})
    return s


# --------------------------------------------------------------------------- datasets
def _manifest_rows(path, plugins_dir):
    """A manifest in scan_testset shape -> the row shape build_patchmap_from_archives wants."""
    from eval.testset.scan_testset import _resolve_archive
    mdir = os.path.dirname(os.path.abspath(path))
    rows = []
    for rec in json.load(open(path)):
        vz = _resolve_archive(rec.get("vuln_zip"), mdir, plugins_dir, rec["slug"])
        pz = _resolve_archive(rec.get("patched_zip"), mdir, plugins_dir, rec["slug"])
        rows.append({"slug": rec["slug"], "cve": rec.get("cve") or "-",
                     "cls": classify_type(rec.get("vuln_type")),
                     "vuln_zip": vz, "patched_zip": pz})
    return rows


def datasets(which):
    ps = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    out = {}
    if which in ("all", "full-1108"):
        out["full-1108"] = list(ps.values())
    if which in ("all", "matched-100"):
        keys = [l.strip() for l in open(MATCHED_SAMPLE) if l.strip()]
        out["matched-100"] = [ps[k] for k in keys if k in ps]
    if which in ("all", "wordfence-100"):
        out["wordfence-100"] = _manifest_rows(
            os.path.join(SYS_ROOT, "100-CVE-testset", "testset_manifest.json"),
            os.path.join(SYS_ROOT, "100-CVE-testset", "plugins"))
    if which in ("all", "testset-325"):
        base = os.path.join(SYS_ROOT, "2026-07-12", "testset-untouched")
        out["testset-325"] = _manifest_rows(os.path.join(base, "testset_manifest.json"),
                                            os.path.join(base, "plugins"))
    return out


def census(rows, workers):
    with Pool(workers) as pool:
        recs = pool.map(_one, rows, chunksize=1)
    ok = [r for r in recs if not r["error"]]
    cat = Counter()
    for r in ok:
        for c in r["categories"]:
            cat[c] += 1
    n = len(ok)
    no_target = sum(1 for r in ok if not r["has_exact_line_target"])
    return {
        "n_records": len(recs),
        "n_scored": n,
        "n_errors": len(recs) - n,
        "categories": dict(sorted(cat.items())),
        "records_with_no_exact_line_target": no_target,
        "records_with_no_exact_line_target_rate": round(no_target / n, 4) if n else None,
        "php_files": {
            "scored": sum(r["n_php_scored_files"] for r in ok),
            "modified": sum(r["n_php_modified"] for r in ok),
            "deleted": sum(r["n_php_deleted"] for r in ok),
            "added": sum(r["n_php_added"] for r in ok),
            "pure_insertion": sum(r["n_php_pure_insertion"] for r in ok),
            "anchored": sum(r["n_php_anchored"] for r in ok),
        },
        "records": recs,
    }


# --------------------------------------------------------------------------- sensitivity
def _boot_rate(units, key, slug_of, reps=BOOT_REPS, seed=BOOT_SEED):
    """Plugin-clustered bootstrap CI, the same unit and seed as every other interval."""
    import numpy as np
    if not units:
        return None, None, None
    by = defaultdict(list)
    for u in units:
        by[slug_of(u)].append(1 if u[key] else 0)
    slugs = sorted(by)
    point = sum(sum(by[s]) for s in slugs) / sum(len(by[s]) for s in slugs)
    rng = np.random.default_rng(seed)
    idx = np.arange(len(slugs))
    vals = []
    for _ in range(reps):
        pick = rng.choice(idx, size=len(slugs), replace=True)
        num = den = 0
        for i in pick:
            v = by[slugs[i]]
            num += sum(v); den += len(v)
        if den:
            vals.append(num / den)
    lo, hi = (float(x) for x in __import__("numpy").percentile(vals, [2.5, 97.5]))
    return round(point, 4), round(lo, 4), round(hi, 4)


def exact_line_sensitivity(shape_rows):
    """Recompute the exact-line rung on matched-100 under the arms contract s2 asks for.

    The record-level arms turn out to be near no-ops: almost every record has SOME file with
    an anchorable line, so dropping whole records barely moves the denominator. The effect is
    at file level. On matched-100, 1041 of 3093 patch-changed PHP files were deleted and 221
    more were modified by insertion only, so 41% of the file surface a finding could land in
    has no exact-line target at all. The arm that actually measures the endpoint's ceiling is
    therefore finding-level: restrict to findings that landed in a file with a changed line.
    """
    if not os.path.isfile(POP):
        return {"status": "SKIPPED", "reason": f"{POP} not found"}
    shape = {r["key"]: r for r in shape_rows if not r["error"]}
    # Per-finding rates, so the "kept" arm, matching the geometric ladder this sensitivity
    # is a sensitivity OF. Applying rule 3 here would measure two things at once.
    pop = []
    for ln in open(POP):
        g = json.loads(ln)
        if g["rank"] <= TOPK:
            pop.append(g)

    def unanchorable(g):
        s = shape.get(g["slug"] + "|" + g["cve"])
        return bool(s) and g.get("file") in set(s.get("unanchorable_php_files") or [])

    # (name, record filter, finding filter)
    arms = [
        ("all_records", lambda s: True, lambda g: True),
        ("drop_records_without_exact_line_target",
         lambda s: s["has_exact_line_target"], lambda g: True),
        ("drop_records_with_any_deleted_php_file",
         lambda s: s["n_php_deleted"] == 0, lambda g: True),
        ("drop_records_with_any_pure_insertion_php_file",
         lambda s: s["n_php_pure_insertion"] == 0, lambda g: True),
        # the informative one: a finding in a deleted or insert-only file can never be an
        # exact-line hit, so this is the rate over findings that had a target to hit.
        ("drop_findings_in_unanchorable_files",
         lambda s: True, lambda g: not unanchorable(g)),
    ]
    out = {}
    for arm, keep_rec, keep_find in arms:
        per_tool = {}
        for tool in ("wisp", "semgrep", "wpt", "progpilot"):
            us = [g for g in pop if g["tool"] == tool
                  and g["slug"] + "|" + g["cve"] in shape
                  and keep_rec(shape[g["slug"] + "|" + g["cve"]])
                  and keep_find(g)]
            if not us:
                continue
            e_pt, e_lo, e_hi = _boot_rate(us, "on_exact_changed_line", lambda u: u["slug"])
            f_pt, f_lo, f_hi = _boot_rate(us, "in_patched_file", lambda u: u["slug"])
            per_tool[tool] = {
                "n_findings": len(us),
                "n_records": len({g["slug"] + "|" + g["cve"] for g in us}),
                "in_patched_file": {"rate": f_pt, "ci": [f_lo, f_hi]},
                "on_exact_changed_line": {"rate": e_pt, "ci": [e_lo, e_hi]},
            }
        out[arm] = per_tool

    # how many in-file findings sat in a file with no possible exact-line target
    infile = [g for g in pop if g["in_patched_file"] and g["slug"] + "|" + g["cve"] in shape]
    out["unanchorable_file_share"] = {
        "n_top3_findings": len(pop),
        "n_in_patched_file": len(infile),
        "n_in_unanchorable_file": sum(1 for g in infile if unanchorable(g)),
        "share_of_in_file_findings": round(
            sum(1 for g in infile if unanchorable(g)) / len(infile), 4) if infile else None,
        "note": "a finding here is in a patch-changed file that the patch either deleted or "
                "only inserted into, so it is in the exact-line denominator and can never be "
                "in its numerator",
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="all",
                    choices=["all", "matched-100", "full-1108", "wordfence-100", "testset-325"])
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    result = {
        "schema_version": "patch-shape-census-v3",
        "contract": "EVALUATION-CONTRACT.md v1 s2 (required sensitivity reports)",
        "definition": {
            "exact_line_target": "a vulnerable-side line inside a difflib replace/delete opcode "
                                 "(eval/patch_geometry.py:_diff_file); a patch that only inserts "
                                 "and a file the patch deleted both yield none",
            "unit": "record (slug|cve); PHP files only",
        },
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "datasets": {},
    }
    ds = datasets(a.dataset)
    for name, rows in ds.items():
        t = time.time()
        print(f"[{name}] {len(rows)} records ...", flush=True)
        result["datasets"][name] = census(rows, a.workers)
        result["datasets"][name]["elapsed_s"] = round(time.time() - t, 1)
        c = result["datasets"][name]
        print(f"  scored {c['n_scored']}/{c['n_records']}  categories={c['categories']}  "
              f"no-exact-target={c['records_with_no_exact_line_target']}", flush=True)

    if "matched-100" in result["datasets"]:
        result["exact_line_sensitivity_matched_100"] = exact_line_sensitivity(
            result["datasets"]["matched-100"]["records"])

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(result, open(a.out, "w"), indent=1, sort_keys=True)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
