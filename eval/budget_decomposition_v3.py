#!/usr/bin/env python3
"""Split the equal-budget result into the two things it actually measures.

At corpus scale under an equal per-plugin budget a baseline beats WISP on patch-file success@1, and
the paper reports that against itself. What the paper does not say is what the number is made of.

Success@1 under failure-as-miss is a product of two independent quantities:

    success@1  =  (records completed / records) x (records with a hit / records completed)

The first factor is throughput. The second is accuracy on the work actually finished. Reporting only
their product invites the reader to attribute a throughput result to analysis quality, which is the
same conflation this paper criticises at the localization endpoint, so it is separated here.

The decomposition also carries a confound the reader is entitled to: wp-taint-scan is a compiled Go
binary and WISP is Python driving tree-sitter. An equal wall-clock budget is therefore not an equal
computational budget, and the throughput factor is the factor that difference acts on. Naming it is
not an excuse for the result, it is a statement of what the result can and cannot establish.

    python3 -m eval.budget_decomposition_v3
"""
from __future__ import annotations
import os, sys, json, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

OUTD = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
MATRIX = os.path.join(OUTD, "BASELINE_MATRIX_V3_full1108.json")
OUT = os.path.join(OUTD, "BUDGET_DECOMPOSITION_V3.json")
TOOLS = ("wisp", "wpt", "semgrep", "progpilot")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", default=MATRIX)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    cells = json.load(open(a.matrix, encoding="utf-8"))["cells"]
    per_budget: dict = {}
    for key, c in cells.items():
        tool, _, budget = key.partition("@")
        if tool not in TOOLS:
            continue
        n = c["dataset_n"]
        completed = c["completed"]
        s1 = c["patch_file_success_at_1"]
        # success@1 counts over the full denominator under failure-as-miss, so the number of records
        # with a hit is s1 * n, and dividing by completed gives accuracy on finished work.
        hits = s1 * n
        per_budget.setdefault(budget, {})[tool] = {
            "n_records": n,
            "completed": completed,
            "timeouts": c.get("timeouts"),
            "non_converged": c.get("non_converged"),
            "throughput": round(completed / n, 4),
            "success_at_1": round(s1, 4),
            "accuracy_on_completed": round(hits / completed, 4) if completed else None,
            "median_elapsed_s": c.get("median_elapsed_s"),
        }

    # The counterfactual the decomposition licenses: hold WISP's accuracy on finished work and give
    # it the leading baseline's throughput. This is arithmetic on measured quantities, not a claim
    # that the engineering to reach that throughput exists.
    counterfactual = {}
    for budget, row in per_budget.items():
        w = row.get("wisp")
        if not w or not w["accuracy_on_completed"]:
            continue
        rival = max((t for t in row if t != "wisp"), key=lambda t: row[t]["success_at_1"])
        r = row[rival]
        counterfactual[budget] = {
            "leading_baseline": rival,
            "baseline_success_at_1": r["success_at_1"],
            "baseline_throughput": r["throughput"],
            "wisp_success_at_1": w["success_at_1"],
            "wisp_accuracy_on_completed": w["accuracy_on_completed"],
            "baseline_accuracy_on_completed": r["accuracy_on_completed"],
            "wisp_at_baseline_throughput": round(
                w["accuracy_on_completed"] * r["throughput"], 4),
            "wisp_more_accurate_on_completed": (
                w["accuracy_on_completed"] > r["accuracy_on_completed"]),
        }

    res = {
        "schema_version": "budget-decomposition-v3",
        "source": os.path.relpath(a.matrix, SYS_ROOT),
        "identity": "success@1 = throughput x accuracy_on_completed, under failure-as-miss",
        "confound": ("wp-taint-scan is a compiled Go binary and WISP is Python driving tree-sitter, "
                     "so an equal wall-clock budget is not an equal computational budget. The "
                     "difference acts on the throughput factor, not on accuracy_on_completed."),
        "per_budget": per_budget,
        "counterfactual": counterfactual,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    for b in sorted(per_budget, key=lambda x: int(x)):
        print(f"budget {b}s")
        for t in TOOLS:
            r = per_budget[b].get(t)
            if r:
                print(f"  {t:10s} throughput={r['throughput']:.4f}  "
                      f"acc_on_completed={r['accuracy_on_completed']}  s@1={r['success_at_1']:.4f}")
        c = counterfactual.get(b)
        if c:
            print(f"  -> WISP at {c['leading_baseline']}'s throughput would be "
                  f"{c['wisp_at_baseline_throughput']:.4f} against {c['baseline_success_at_1']:.4f}")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
