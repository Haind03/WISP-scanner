#!/usr/bin/env python3
"""[SUPERSEDED 2026-07-29 by eval/ladder_v3.py — kept for provenance, do not extend]

Superseded because its rungs entangle geometry with the advisory class and it inherits
scan_testset._score's `if path not in gt or cls not in finding_classes: continue`, so no pure
geometric ladder exists here, and it calls a +/-window a "function"/"defect" match. The
class-agnostic replacement is eval/patch_geometry.py + eval/ladder_v3.py, which compute every
geometric field independently of class and keep class_match separate. This file is left runnable
only to reproduce the earlier numbers.

The granularity ladder, one unit, every tool: file -> function -> defect.

The paper's headline endpoint counts a finding as correct when it lands in a file
the vendor patched. The blinded audit says that almost none of those findings
point at the defect the vendor actually fixed. The distance between those two
statements is the paper's real result, but it can only be read if every rung is
measured in the same unit, over the same findings.

Unit: a single finding, drawn from each tool's top-3 on matched-100. That is
exactly the population the adjudication sampled, so the defect rung is the
design-weighted rate from eval/adjudication_weighted.py and the two rungs above
it are computed over the whole population it was drawn from.

  in a patched file      the finding's file is one the patch touched
  in the patched function the enclosing function of the finding's line contains a
                         line the patch changed
  at the defect          two blinded reviewers agree the finding points at the
                         defect the advisory describes

Only WISP and wp-taint-scan were adjudicated, so only they carry the third rung.
Semgrep and Progpilot get the first two, which is still worth printing: the claim
is about what the endpoint measures, not about which tool wins.

    python3 -m eval.ladder --out out/paired_20260717/LADDER.json
"""
from __future__ import annotations
import os, sys, json, shutil, argparse, random
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows

# The engine-backed helpers below are only needed to regenerate the ladder cache
# from the plugin archives. They are imported lazily inside one() so that a reader
# who only recomputes the bootstrap from the shipped cache does not need the engine
# or the archives installed (reviewer 7: reproduce from cached intermediates).

_RD = os.environ.get("WISP_REPRO_DATA")


def _rp(path):
    """Resolve an input path against the standalone data dir when one is set."""
    return os.path.join(_RD, os.path.basename(path)) if _RD else path


WISP_CAP = _rp("out/fill_20260714/train_cap.json")
WPT_RUN = _rp("out/corrected_20260713/matched_100_baselines_final.json")
ADJ = _rp("out/paired_20260717/ADJ_WEIGHTED.json")
TOPK = 3


def top3(stored, wisp_rec, tool):
    """Each tool's top-3 findings for one record, as (file, line) in rank order."""
    if tool == "wisp":
        return [(f["file"], f.get("line") or 0) for f in (wisp_rec or {}).get("findings", [])[:TOPK]]
    b = (stored or {}).get(tool) or {}
    fs = sorted(b.get("findings") or [], key=lambda x: x.get("rank") or 0)[:TOPK]
    return [(f.get("file") or "", f.get("line") or 0) for f in fs]


def one(task):
    from eval.localize import _unzip
    from eval.testset.scan_testset import _gt, _enclosing_fn
    rec, stored, wisp_rec = task
    key = rec["slug"] + "|" + rec["cve"]
    vroot = proot = None
    try:
        vroot, proot = _unzip(rec["vuln_zip"]), _unzip(rec["patched_zip"])
        if not (vroot and proot):
            return {"key": key, "err": "archive_extract_error"}
        gt = _gt(vroot, proot)
        out = {"key": key, "tools": {}}
        for tool in ("wisp", "semgrep", "progpilot", "wpt"):
            rows = []
            for path, line in top3(stored, wisp_rec, tool):
                in_file = path in gt
                in_fn = False
                if in_file and line:
                    changed, ranges = gt[path]
                    enc = _enclosing_fn(line, ranges)
                    if enc:
                        in_fn = any(enc[0] <= c <= enc[1] for c in changed)
                rows.append({"in_file": bool(in_file), "in_fn": bool(in_fn)})
            out["tools"][tool] = rows
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

    wisp = {r["slug"] + "|" + r["cve"]: r for r in json.load(open(WISP_CAP))}
    stored = {d["slug"] + "|" + d["cve"]: d for d in json.load(open(WPT_RUN))["details"]}
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = sorted(k for k in wisp if k in stored and k in rows)
    print(f"ladder over the top-{TOPK} findings of {len(keys)} matched records")

    res = []
    with Pool(a.workers) as pool:
        for i, d in enumerate(pool.imap_unordered(
                one, [(rows[k], stored[k], wisp[k]) for k in keys], chunksize=1), 1):
            res.append(d)
            if i % 20 == 0:
                print(f"  ...{i}/{len(keys)}", flush=True)
    bad = [d for d in res if d.get("err")]
    if bad:
        sys.exit(f"{len(bad)} record(s) failed: {bad[0]}")

    adj = json.load(open(ADJ))["tools"]
    defect = {"wisp": adj["wisp"], "wpt": adj["wpt"]}

    rep = {"unit": "one finding, from each tool's top-3 on matched-100",
           "n_records": len(res), "tools": {}}
    print(f"\n{'tool':11} {'findings':>9} {'in file':>9} {'in function':>12} {'at defect':>11}   overstatement")
    print("-" * 74)
    for tool in ("wisp", "wpt", "semgrep", "progpilot"):
        fs = [r for d in res for r in d["tools"][tool]]
        n = len(fs)
        if not n:
            continue
        f_file = sum(1 for r in fs if r["in_file"]) / n
        f_fn = sum(1 for r in fs if r["in_fn"]) / n
        d = defect.get(tool)
        rung3 = d["weighted_rate"] if d else None
        rep["tools"][tool] = {
            "findings": n,
            "in_patched_file": round(f_file, 4),
            "in_patched_function": round(f_fn, 4),
            "at_defect_weighted": rung3,
            "at_defect_ci95": d["ci95_weighted"] if d else None,
            "file_over_defect": round(f_file / rung3, 1) if rung3 else None}
        ds = f"{rung3:.3f}" if rung3 is not None else "not audited"
        ov = f"{f_file / rung3:.0f}x" if rung3 else ""
        print(f"{tool:11} {n:>9} {f_file:>9.3f} {f_fn:>12.3f} {ds:>11}   {ov}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
