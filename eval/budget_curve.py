#!/usr/bin/env python3
"""Coverage and quality against a shared time budget, on the full corpus.

The paper caps each baseline at the budget its authors suggest (Semgrep 300 s,
Progpilot 25 s, wp-taint-scan 60 s) and lets WISP run uncapped, and its only
equal-budget evidence is a sweep over the 100-record matched sample. The reviewer
is right that this cannot support a corpus-scale comparison.

Running every tool at every budget would be one full-corpus pass per (tool,
budget). It is not necessary. If a run records how long the tool itself took on
each record, then a run at a generous cap contains every smaller budget already:
a record the tool finished in 40 s would also have finished under a 60 s cap, and
one that took 200 s would have been killed. These tools either return a complete
result or are killed, with no partial output, which is what makes the derivation
sound. So one timed pass per tool answers the whole curve.

Two honest caveats, both stated in the paper rather than buried:
  * the timings carry contention from the worker pool, so a derived budget is
    slightly pessimistic. Every tool is measured under the same pool.
  * a tool killed at B seconds is scored failure-as-miss, matching the protocol
    used everywhere else here.

    python3 -m eval.budget_curve --out out/paired_20260717/BUDGET_CURVE.json
"""
from __future__ import annotations
import os, sys, json, glob, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

KS = ("1", "3", "5", "10")
BUDGETS = (25, 60, 120, 300)


def load_tool(path):
    d = json.load(open(path))
    det = d["details"]
    if any(r.get("tool_seconds") is None and not r.get("err") for r in det):
        sys.exit(f"{path} has no per-record timings; rerun eval.fullcorpus_atk "
                 f"after the timing patch")
    return d["tool"], det


def at_budget(det, B):
    """Score the run as if the cap had been B seconds. A record whose tool call
    exceeded B, or that already failed, is a miss."""
    tp = {k: 0 for k in KS}
    n = {k: 0 for k in KS}
    hits = answered = 0
    for r in det:
        secs = r.get("tool_seconds")
        killed = bool(r["err"]) or (secs is not None and secs > B)
        if killed:
            continue
        answered += 1 if r["findings"] else 0
        hits += 1 if r["hit"] else 0
        for k in KS:
            tp[k] += r["topk_tp"][k]
            n[k] += r["topk_n"][k]
    total = len(det)
    return {"budget_s": B,
            "class_recall": round(hits / total, 4),
            "records_with_findings": answered,
            "coverage": round(answered / total, 4),
            "prec_at_k": {k: (round(tp[k] / n[k], 4) if n[k] else None) for k in KS}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", nargs="*", default=sorted(glob.glob("out/budget_20260717/atk_*.json")))
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not a.runs:
        sys.exit("no timed runs found; run eval.fullcorpus_atk into out/budget_20260717/")

    rep = {"budgets_s": list(BUDGETS),
           "method": "derived from one timed pass per tool: a record whose tool call "
                     "exceeded the budget is scored failure-as-miss",
           "caveat": "timings carry worker-pool contention, so derived budgets are "
                     "slightly pessimistic; all tools measured under the same pool",
           "tools": {}}
    for p in a.runs:
        tool, det = load_tool(p)
        rep["tools"][tool] = {"n_records": len(det),
                              "curve": [at_budget(det, B) for B in BUDGETS]}
        print(f"=== {tool} ({len(det)} records) ===")
        print(f"  {'budget':>7} {'coverage':>9} {'class recall':>13} {'pf@1':>7}")
        for c in rep["tools"][tool]["curve"]:
            p1 = c["prec_at_k"]["1"]
            print(f"  {c['budget_s']:>6}s {c['coverage']:>9.3f} {c['class_recall']:>13.3f} "
                  f"{(f'{p1:.3f}' if p1 is not None else 'n/a'):>7}")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
