#!/usr/bin/env python3
"""Rescore the matched-100 baseline run against the correct advisory class.

The 2026-07-13 run was driven by a manifest that carried no vuln_type, and
scan_testset mapped the missing label through classify_type(None), which returns
"other". Every record therefore carried cls="other", and every class-dependent
metric asked "did the tool report the class other?" instead of "did the tool
report the advisory's class?". WISP was scored from a different file that has the
right classes, so the damage is one-sided: it lands only on the baselines.

The tools do not need to run again. Their complete ranked findings are stored in
the run (n equals len(findings) for every record), so only the scoring was wrong.
This re-derives the diff ground truth from the archives, re-runs the same _score
over the stored findings with the correct class, and diffs the result.

The check that matters is pf: patch-file success is class-agnostic, so it must
come out bit-identical. If it moves, this rescoring is unfaithful and its other
numbers cannot be trusted either.

    python3 -m eval.rescore_matched100 --out out/paired_20260717/MATCHED100_RESCORED.json
"""
from __future__ import annotations
import os, sys, json, shutil, argparse
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows, classify_type
from eval.localize import _unzip
from eval.testset.scan_testset import _gt, _score, KS

RUN = "out/corrected_20260713/matched_100_baselines_final.json"
TOOLS = ("semgrep", "progpilot", "wpt")


def one(task):
    rec, stored, window = task
    key = rec["slug"] + "|" + rec["cve"]
    # load_rows() emits the already-classified 'cls'; scan_testset took its class
    # from a manifest's 'vuln_type' instead, which is where the run went wrong.
    cls = rec.get("cls")
    if not cls:
        return {"key": key, "err": "canonical dataset row has no cls"}
    vroot = proot = None
    try:
        vroot, proot = _unzip(rec["vuln_zip"]), _unzip(rec["patched_zip"])
        if not (vroot and proot):
            return {"key": key, "err": "archive_extract_error"}
        gt = _gt(vroot, proot)
        out = {"key": key, "cls_correct": cls, "cls_stored": stored["cls"], "tools": {}}
        for t in TOOLS:
            b = stored.get(t) or {}
            if b.get("err"):
                out["tools"][t] = {"err": b["err"]}
                continue
            ranked = [{"file": f["file"], "line": f.get("line") or 0,
                       "classes": f.get("classes") or []}
                      for f in (b.get("findings") or [])]
            hit, pf, cf, ch, cfn = _score(ranked, gt, cls, window)
            out["tools"][t] = {"hit": hit,
                               "pf": {str(k): pf[k] for k in KS},
                               "cf": {str(k): cf[k] for k in KS},
                               "ch": {str(k): ch[k] for k in KS},
                               "cfn": {str(k): cfn[k] for k in KS},
                               "stored_hit": b.get("hit"),
                               "stored_pf": {str(k): (b.get("pf") or {}).get(str(k), 0) for k in KS}}
        return out
    finally:
        for r in (vroot, proot):
            if r:
                shutil.rmtree(r, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    run = json.load(open(RUN))
    window = run["summary"].get("window", 5)
    stored = {d["slug"] + "|" + d["cve"]: d for d in run["details"]}
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    tasks = [(rows[k], stored[k], window) for k in stored if k in rows]
    print(f"rescoring {len(tasks)}/{len(stored)} records at window={window}")

    res = []
    with Pool(a.workers) as pool:
        for i, d in enumerate(pool.imap_unordered(one, tasks, chunksize=1), 1):
            res.append(d)
            if i % 20 == 0:
                print(f"  ...{i}/{len(tasks)}", flush=True)

    ok = [d for d in res if not d.get("err")]
    n = len(ok)
    print(f"\nrescored {n} records; {len(res)-n} failed")
    for d in res:
        if d.get("err"):
            print(f"  FAILED {d['key']}: {d['err']}")
            break
    if n < len(res):
        sys.exit(f"{len(res)-n} record(s) failed to rescore; fix that before "
                 f"reading any number below")

    # faithfulness gate: pf is class-agnostic and must reproduce exactly. An empty
    # comparison is not a pass, so count what was actually checked.
    drift = checked = 0
    for d in ok:
        for t, v in d["tools"].items():
            if "err" in v:
                continue
            checked += 1
            if v["pf"] != v["stored_pf"]:
                drift += 1
                print(f"  PF DRIFT {d['key']} {t}: {v['stored_pf']} -> {v['pf']}")
    if drift or checked == 0:
        sys.exit(f"\n{drift} drift(s) over {checked} comparison(s). The rescoring is "
                 f"unfaithful or vacuous; do not use its numbers.")
    print(f"pf reproduces exactly over {checked} record/tool comparisons: "
          f"rescoring is faithful\n")

    rep = {"source": RUN, "n": n, "window": window,
           "root_cause": "manifest without vuln_type; classify_type(None) -> 'other'",
           "tools": {}}
    print(f"{'tool':10} {'metric':14} {'published':>10} {'corrected':>10}")
    print("-" * 48)
    for t in TOOLS:
        rows_t = [d["tools"][t] for d in ok if "err" not in d["tools"][t]]
        pub = run["summary"][t]
        cur = {"class_emission": round(sum(r["hit"] for r in rows_t) / n, 4),
               "pf_at_k": {k: round(sum(r["pf"][k] for r in rows_t) / n, 4) for k in map(str, KS)},
               "cf_at_k": {k: round(sum(r["cf"][k] for r in rows_t) / n, 4) for k in map(str, KS)},
               "ch_at_k": {k: round(sum(r["ch"][k] for r in rows_t) / n, 4) for k in map(str, KS)},
               "cfn_at_k": {k: round(sum(r["cfn"][k] for r in rows_t) / n, 4) for k in map(str, KS)},
               "answered": pub.get("answered")}
        rep["tools"][t] = {"published": {k: pub.get(k) for k in
                                         ("class_emission", "pf_at_k", "cf_at_k", "ch_at_k", "cfn_at_k")},
                           "corrected": cur}
        print(f"{t:10} {'class emission':14} {pub['class_emission']:>10} {cur['class_emission']:>10}")
        for k in ("1", "3", "5", "10"):
            print(f"{'':10} {'cf@'+k:14} {pub['cf_at_k'][k]:>10} {cur['cf_at_k'][k]:>10}")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
