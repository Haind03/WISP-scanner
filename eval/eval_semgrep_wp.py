#!/usr/bin/env python3
"""Vocabulary-controlled experiment (reviewer question 3): run Semgrep with the
WordPress source/sink/guard vocabulary transplanted from WISP (semgrep_wp_rules.yaml,
built by gen_semgrep_wp.py) on the matched-100 sample, scored with the SAME
diff-based class+file / patch-file @K harness as every other tool.

The comparison this enables:
  * Semgrep-generic : p/php + p/security-audit  (existing baseline)
  * Semgrep-WP      : WISP vocabulary in Semgrep's own taint engine  (this script)
  * WISP             : WISP vocabulary in WISP's engine
Holding the vocabulary fixed between Semgrep-WP and WISP isolates the engine.

Class of a Semgrep-WP finding = the rule's own id suffix (wisp-wp-<class>), since
each rule is class-tagged by construction.

Usage: python3 eval_semgrep_wp.py --sample sample_100.txt --out out_sgwp_cf100.json
"""
from __future__ import annotations
import os, sys, json, argparse, subprocess
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WISP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WISP)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip
from eval import patch_geometry as pg

WP_CONFIG = os.path.join(os.path.dirname(__file__), "semgrep_wp_rules.yaml")
KS = (1, 3, 5, 10)
_SEV = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def _gt_files(vroot, proot, slug, cve):
    """Contract v1 file set: PHP files a finding on vulnerable input could land in.

    Until 2026-08-11 this was computed here from localize._changed_lines and required the file to be
    present in BOTH trees, which silently dropped every file the patch deleted. The four columns this
    one is printed beside credit a deleted file at the file level (Contract v1 s2), so the transplant
    column was scored against a smaller ground truth than the tools it is compared with, and the
    difference ran against the transplant. Two scoring semantics in one table is the defect; which
    way the correction moves the number is not a reason to keep it. This now builds the same PatchMap
    every other column is scored against."""
    pm = pg.build_patchmap_from_files(
        slug, cve, pg._extract_text_map(vroot), pg._extract_text_map(proot))
    return pm.patch_changed_php_files


def _keyof(p, root):
    rel = os.path.relpath(p, root)
    parts = rel.split(os.sep)
    return os.sep.join(parts[1:]) if len(parts) > 1 else rel


def _class_of(check_id):
    # check_id looks like "semgrep_wp_rules.wisp-wp-xss"; take the class suffix
    tail = check_id.split(".")[-1]
    return tail.replace("wisp-wp-", "") if tail.startswith("wisp-wp-") else "other"


def _semgrep_wp_ranked(vroot):
    cmd = ["semgrep", "--config", WP_CONFIG, "--json", "--quiet", "--metrics=off",
           "--jobs", "1", "--timeout", "20", "--max-target-bytes", "2000000", vroot]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return None
    if not p.stdout.strip():
        return []
    try:
        data = json.loads(p.stdout)
    except json.JSONDecodeError:
        return None
    rows = []
    for r in data.get("results", []):
        sev = _SEV.get(r.get("extra", {}).get("severity", "INFO"), 1)
        rows.append((r.get("path", ""), _class_of(r.get("check_id", "")), sev))
    rows.sort(key=lambda x: x[2], reverse=True)
    return [(pp, c) for pp, c, _ in rows]


def _one(r):
    zp, patched = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(zp) and os.path.isfile(patched)):
        return None
    vroot, proot = _unzip(zp), _unzip(patched)
    if not vroot or not proot:
        return None
    try:
        gt = _gt_files(vroot, proot, r["slug"], r["cve"])
        ranked = _semgrep_wp_ranked(vroot)
        if ranked is None:
            return {"slug": r["slug"], "cve": r["cve"], "cls": r["cls"], "err": "timeout",
                    "pf": {str(k): 0 for k in KS}, "cf": {str(k): 0 for k in KS},
                    "findings": 0}
        # normalize_path case-folds; the PatchMap keyspace is case-folded, so the finding keys must
        # be too or every comparison silently misses on a case-different path.
        norm = [(pg.normalize_path(
                    _keyof(os.path.join(vroot, p) if not os.path.isabs(p) else p, vroot)), c)
                for p, c in ranked]
        pf, cf = {}, {}
        for k in KS:
            top = norm[:k]
            pf[str(k)] = 1 if any(f in gt for f, _ in top) else 0
            cf[str(k)] = 1 if any(f in gt and c == r["cls"] for f, c in top) else 0
        # class-level recall: expected class appears in ANY finding of the plugin
        classes = {c for _, c in norm}
        return {"slug": r["slug"], "cve": r["cve"], "cls": r["cls"], "err": "",
                "hit": int(r["cls"] in classes),
                "pf": pf, "cf": cf, "findings": len(norm)}
    finally:
        import shutil
        shutil.rmtree(vroot, ignore_errors=True)
        shutil.rmtree(proot, ignore_errors=True)


def main():
    global WP_CONFIG
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=os.path.join(os.path.dirname(__file__),
                                                     "sample_100.txt"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--config", default=WP_CONFIG,
                    help="Semgrep ruleset; use semgrep_wp_taint_only.yaml for taint-only")
    a = ap.parse_args()
    WP_CONFIG = os.path.abspath(a.config)
    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want
            and os.path.exists(r["vuln_zip"])]
    print(f"semgrep-wp: {len(rows)} plugins", flush=True)
    with Pool(a.workers) as pool:
        det = [d for d in pool.map(_one, rows) if d]
    n = len(det)
    agg = {"tool": "semgrep-wp", "n": n,
           "errors": sum(1 for d in det if d["err"]),
           "class_recall": round(sum(d.get("hit", 0) for d in det) / n, 4),
           "classfile_at_k": {str(k): round(sum(d["cf"][str(k)] for d in det) / n, 4) for k in KS},
           "patchfile_at_k": {str(k): round(sum(d["pf"][str(k)] for d in det) / n, 4) for k in KS},
           "details": det}
    json.dump(agg, open(a.out, "w"), indent=1)
    print(json.dumps({k: agg[k] for k in ("tool", "n", "errors", "class_recall",
                                          "classfile_at_k", "patchfile_at_k")}, indent=1))


if __name__ == "__main__":
    main()
