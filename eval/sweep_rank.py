#!/usr/bin/env python3
"""Calibrate the exploitability score's per-finding reliability weight (w_flow)
on a TRAIN split and report cf@1 / pf@1 on a disjoint TEST split. Post-processes
the captured findings (capture_findings.py), so no re-scan per weight.

score(f) = entry_weight[ep] + (1 if interprocedural) + w_flow * confidence

Rationale (reviewer 2.9): file-level entry-point weight (0.5-5.0) dominates the
default score, so within a vulnerable file the ordering among differently-classed
findings is near-arbitrary. Raising w_flow lets a concrete source-to-sink taint
finding outrank a heuristic missing-guard/risk-pattern finding in the same file,
which is what class-and-file@1 rewards. We pick w_flow on TRAIN and report TEST.
"""
import os, sys, json, argparse

_ENTRY_WEIGHT = {"ajax_nopriv": 5.0, "rest_api": 4.0, "shortcode": 3.0,
                 "ajax_auth": 2.5, "admin": 1.0, "unknown": 0.5}
KS = (1, 3, 5, 10)


def score(f, wflow):
    return (_ENTRY_WEIGHT.get(f["ep"], 0.5)
            + (1.0 if f["ip"] else 0.0)
            + wflow * f["conf"])


def metrics(records, wflow):
    """cf@K and pf@K over records after re-ranking by score(wflow)."""
    cf = {k: 0 for k in KS}
    pf = {k: 0 for k in KS}
    n = len(records)
    for rec in records:
        gt = set(rec["gt"])
        cls = rec["cls"]
        # stable sort: ties keep captured (default-ranked) order
        order = sorted(range(len(rec["findings"])),
                       key=lambda i: score(rec["findings"][i], wflow), reverse=True)
        fs = [rec["findings"][i] for i in order]
        for k in KS:
            top = fs[:k]
            if any(f["file"] in gt for f in top):
                pf[k] += 1
            if any(f["file"] in gt and f["cls"] == cls for f in top):
                cf[k] += 1
    return ({k: round(cf[k] / n, 4) for k in KS},
            {k: round(pf[k] / n, 4) for k in KS})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    train = json.load(open(a.train))
    test = json.load(open(a.test))
    weights = [1.0, 2.0, 3.0, 5.0, 8.0, 12.0, 20.0]

    print(f"{'wflow':>6} | {'TRAIN cf@1':>10} {'cf@3':>6} {'cf@10':>6} {'pf@1':>6} "
          f"| {'TEST cf@1':>9} {'cf@3':>6} {'cf@10':>6} {'pf@1':>6}")
    rows = []
    for w in weights:
        cf_tr, pf_tr = metrics(train, w)
        cf_te, pf_te = metrics(test, w)
        rows.append({"wflow": w, "train": {"cf": cf_tr, "pf": pf_tr},
                     "test": {"cf": cf_te, "pf": pf_te}})
        print(f"{w:>6} | {cf_tr[1]:>10} {cf_tr[3]:>6} {cf_tr[10]:>6} {pf_tr[1]:>6} "
              f"| {cf_te[1]:>9} {cf_te[3]:>6} {cf_te[10]:>6} {pf_te[1]:>6}")

    # pick best w on TRAIN by cf@1 (tie-break: higher cf@3, then pf@1)
    best = max(rows, key=lambda r: (r["train"]["cf"][1], r["train"]["cf"][3],
                                    r["train"]["pf"][1]))
    print("\nBEST on TRAIN by cf@1: wflow =", best["wflow"])
    print("  TRAIN:", best["train"])
    print("  TEST :", best["test"])
    base = next(r for r in rows if r["wflow"] == 1.0)
    print("\nBASELINE wflow=1.0:")
    print("  TEST :", base["test"])
    print(f"\nTEST cf@1: {base['test']['cf'][1]} -> {best['test']['cf'][1]} "
          f"(wp-taint-scan 0.13, Semgrep 0.11)")
    if a.out:
        json.dump({"rows": rows, "best_wflow": best["wflow"],
                   "baseline_test": base["test"], "best_test": best["test"]},
                  open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
