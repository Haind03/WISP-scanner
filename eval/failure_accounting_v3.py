#!/usr/bin/env python3
"""One table that accounts for every record, for every tool, at every budget.

The paper reports precision conditioned on the records a tool answered, and reports coverage
separately. A reviewer asked for the two next to each other, with the reasons a record went missing
broken out, because a precision computed on an answered subset is only readable against the size and
composition of that subset. The numbers already exist in the per-cell files; nothing here is a new
measurement, only an accounting that adds up.

The invariant this enforces is that the parts sum to the whole. For every cell,

    completed + timeouts + mem_capped + other_err + non_converged == dataset_n

and the module refuses to write if any cell fails it, because an accounting that does not close is
worse than no accounting: it looks like one.

`non_converged` is WISP-only by construction, since it is the contract's rule-3 failure and no
baseline has an analysis-completeness signal. That is stated per row rather than left as a column of
zeros a reader has to interpret.

    python3 -m eval.failure_accounting_v3
"""
from __future__ import annotations
import os, sys, json, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CELLS = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "cells")
ARCHIVED = ("CONTAMINATED", "NOT-REPORTED")
PARTS = ("completed", "timeouts", "mem_capped", "other_err", "non_converged")


def main() -> int:
    rows, problems = {}, []
    for p in sorted(glob.glob(os.path.join(CELLS, "*.json"))):
        base = os.path.basename(p)
        if any(a in base for a in ARCHIVED):
            continue
        c = json.load(open(p, encoding="utf-8"))
        tool, budget = c.get("tool"), c.get("budget_s")
        if tool is None or budget is None:
            continue
        dataset = "full-1108" if base.startswith("full-1108") else "matched-100"
        n = int(c.get("dataset_n") or 0)
        got = {k: int(c.get(k) or 0) for k in PARTS}
        total = sum(got.values())
        if total != n:
            problems.append(f"{dataset} {tool}@{budget}: parts sum to {total}, dataset_n is {n} "
                            f"({got})")
        eng = (c.get("provenance") or {}).get("wisp_config") or {}
        rows.setdefault(dataset, {})[f"{tool}@{budget}"] = {
            "tool": tool, "budget_s": budget, "n_records": n,
            **got,
            "answered": got["completed"],
            "answered_share": round(got["completed"] / n, 4) if n else None,
            "patch_file_success_at_1": c.get("patch_file_success_at_1"),
            "class_emission_failure_as_miss": c.get("class_emission_failure_as_miss"),
            "non_converged_applies": (tool == "wisp"),
            "engine_tag": eng.get("engine_tag") if tool == "wisp" else None,
            "peak_rss_mb_max": c.get("peak_rss_mb_max"),
        }
    if problems:
        print("REFUSING to write: the accounting does not close")
        for x in problems:
            print("  x " + x)
        return 2

    doc = {"schema_version": "failure-accounting-v3",
           "question": ("for every tool at every budget: how many records were answered, and where "
                        "did the rest go"),
           "invariant": "completed + timeouts + mem_capped + other_err + non_converged == n_records",
           "non_converged_note": ("WISP-only by construction: it is the contract's rule-3 failure "
                                  "and no baseline exposes an analysis-completeness signal"),
           "engine_note": ("engine_tag is per row and is null for a baseline, whose result does "
                           "not depend on the WISP engine. A WISP row measured on an engine other "
                           "than the shipped one is a cell the paper does not report, kept here so "
                           "the accounting covers what exists rather than only what is quoted"),
           "precision_note": ("patch_file_success_at_1 is over the full denominator under "
                             "failure-as-miss, so it is already charged for everything in this "
                             "table rather than conditioned on the answered subset"),
           "datasets": rows}
    p = os.path.join(OUT, "FAILURE_ACCOUNTING_V3.json")
    json.dump(doc, open(p, "w"), indent=1, sort_keys=True)
    print("wrote", os.path.relpath(p, SYS_ROOT))
    for ds in sorted(rows):
        print(f"\n  {ds}")
        print(f"    {'cell':18} {'n':>4} {'answ':>5} {'t/o':>5} {'mem':>4} {'err':>4} "
              f"{'nonconv':>8} {'pf@1':>7}  engine")
        for k in sorted(rows[ds], key=lambda x: (x.split("@")[0], int(x.split("@")[1]))):
            r = rows[ds][k]
            nc = str(r["non_converged"]) if r["non_converged_applies"] else "n/a"
            print(f"    {k:18} {r['n_records']:4d} {r['answered']:5d} {r['timeouts']:5d} "
                  f"{r['mem_capped']:4d} {r['other_err']:4d} {nc:>8} "
                  f"{(r['patch_file_success_at_1'] or 0):7.3f}  {r['engine_tag'] or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
