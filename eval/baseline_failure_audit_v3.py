#!/usr/bin/env python3
"""Split every baseline failure on the full corpus into its kind, and bound what is unverified.

We disclosed that our harness had discarded Progpilot records that exited non-zero while printing a
valid findings array. A reviewer then asked the obvious follow-up: what were the other tools'
failures, and were they audited the same way. Reporting one aggregate count per tool does not
answer that, so this splits the count by the error the harness recorded.

The split does not by itself clear a tool. A record that exited non-zero is exactly what the
Progpilot defect looked like from the harness side, and the stored record carries the harness's
view rather than the tool's raw output. So the non-zero-exit records are reported separately as
the only place that defect could still hide, with the coverage they would return if every one of
them were a false miss. That bound is what we can support from shipped data.

    python3 -m eval.baseline_failure_audit_v3
"""
from __future__ import annotations
import os, sys, json, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "BASELINE_FAILURE_AUDIT_V3.json")

SOURCES = {
    "semgrep": "out/fill_20260714/atk_sg_1108.json",
    "progpilot": "out/fill_20260714/atk_pp_1108.json",
    "wpt": "out/fill_20260714/atk_wpt_1108.json",
}
# A timeout is the tool running out of its budget, which the failure policy already charges as a
# miss on purpose. Anything else is the harness reading the tool, which is where our own defect was.
BUDGET_KINDS = {"timeout"}


def main():
    tools = {}
    for tool, rel in SOURCES.items():
        p = os.path.join(ROOT, rel)
        if not os.path.isfile(p):
            sys.exit(f"missing full-corpus scan for {tool}: {rel}")
        det = json.load(open(p, encoding="utf-8"))["details"]
        kinds = collections.Counter()
        for r in det:
            e = r.get("err") or ""
            if e:
                kinds[e.split(":")[0]] += 1
        n = len(det)
        failures = sum(kinds.values())
        budget = sum(v for k, v in kinds.items() if k in BUDGET_KINDS)
        harness = failures - budget
        tools[tool] = {
            "n_records": n,
            "failures": failures,
            "by_kind": dict(sorted(kinds.items())),
            "budget_exhaustion": budget,
            "harness_read_failures": harness,
            "harness_read_share_of_corpus": round(harness / n, 4),
            "coverage_as_scored": round((n - failures) / n, 4),
            "coverage_upper_bound_if_all_harness_failures_were_false": round(
                (n - budget) / n, 4),
        }
    res = {
        "schema_version": "baseline-failure-audit-v3",
        "script": "eval/baseline_failure_audit_v3.py",
        "sources": SOURCES,
        "note": ("failures split into budget exhaustion, which the failure policy charges as a "
                 "miss by design, and failures where the harness could not read the tool, which "
                 "is the class our Progpilot defect belonged to. The stored records carry the "
                 "harness's view rather than the tool's raw stdout, so a harness-read failure is "
                 "reported as an upper bound on unverified misses rather than as a cleared one"),
        "tools": tools,
    }
    json.dump(res, open(OUT, "w"), indent=1, sort_keys=True)
    print(f"wrote {OUT}")
    for t, v in tools.items():
        print(f"  {t:10} {v['failures']:4} failures = {v['budget_exhaustion']:4} budget "
              f"+ {v['harness_read_failures']:3} harness-read   "
              f"coverage {v['coverage_as_scored']:.3f}, upper bound "
              f"{v['coverage_upper_bound_if_all_harness_failures_were_false']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
