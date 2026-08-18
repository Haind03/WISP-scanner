#!/usr/bin/env python3
"""Final GDA effect report from a gda_eval full-corpus feature dump.

Calibrates the guard-deficit ranking weight on the TRAIN split (the original 252
xlsx), then reports class-and-file@K for the baseline ranking (guard term off) vs
the GDA ranking on the disjoint TEST split and on the full corpus, with a per-class
breakdown and a paired plugin-level win/lose count (McNemar cells) at K=1 and K=10.

    python3 -m eval.gda_report out/gda_dump_full.json
"""
from __future__ import annotations
import sys, json
from eval.gda_sweep import filter_split, evaluate, score, KS


def _cf_hits(dump, wguard, center=0.0):
    """Per-plugin boolean cf@K hit vector, for paired comparison."""
    out = {k: [] for k in KS}
    for d in dump:
        gt = set(d["gt_files"])
        cls = d["cls"]
        feats = sorted(d["findings"],
                       key=lambda f: score(f, 1.0, wguard, None, None, center),
                       reverse=True)
        for k in KS:
            out[k].append(bool(any(f["file"] in gt and f["cls"] == cls
                                   for f in feats[:k])))
    return out


def _mcnemar(base, gda, k):
    b, g = base[k], gda[k]
    b01 = sum(1 for x, y in zip(b, g) if (not x) and y)   # gained by GDA
    b10 = sum(1 for x, y in zip(b, g) if x and (not y))   # lost by GDA
    return b01, b10


def _fmt(res):
    c = res["cf"]
    return f"cf@1={c[1]:.4f} cf@3={c[3]:.4f} cf@5={c[5]:.4f} cf@10={c[10]:.4f}  (n={res['n']})"


def main():
    dump_all = json.load(open(sys.argv[1]))
    train = filter_split(dump_all, "train")
    test = filter_split(dump_all, "test")
    print(f"full={len(dump_all)}  train={len(train)}  test={len(test)}\n")

    # 1) calibrate wguard on TRAIN. Objective: maximise the primary endpoint
    #    (micro class-and-file@1) SUBJECT TO no drop in macro-averaged cf@1/cf@10
    #    (equal weight per class). The macro constraint blocks the degenerate
    #    optimum where a large weight games the class imbalance - lifting the
    #    majority auth class while sinking every minority class. center=0 (additive)
    #    is the only form that helps here; the demote-only / centered forms are
    #    inert or strictly worse on this corpus (see eval log).
    _CLS = ["auth", "csrf", "sqli", "xss", "deserial", "lfi", "rce", "ssrf",
            "upload", "other"]

    def _macro(r, k):
        return sum(r["per"].get(c, {}).get(k, 0) for c in _CLS) / len(_CLS)

    base_tr = evaluate(train, wguard=0.0)
    bm1, bm10 = _macro(base_tr, 1), _macro(base_tr, 10)
    print("=== calibration on TRAIN (max micro cf@1 s.t. macro not degraded) ===")
    print(f"  base   micro@1={base_tr['cf'][1]:.4f} macro@1={bm1:.4f} macro@10={bm10:.4f}")
    best_w, best_micro = 0.0, base_tr["cf"][1]
    for w in (0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 2.5):
        r = evaluate(train, wguard=w, center=0.0)
        m1, m10 = _macro(r, 1), _macro(r, 10)
        ok = (m1 >= bm1 - 1e-9) and (m10 >= bm10 - 0.005)
        print(f"  w={w:<5} micro@1={r['cf'][1]:.4f} macro@1={m1:.4f} macro@10={m10:.4f}"
              f"  {'OK' if ok else 'x cannibalises'}")
        if ok and r["cf"][1] >= best_micro:
            best_micro, best_w = r["cf"][1], w
    best_c = 0.0
    print(f"  -> chosen wguard = {best_w}, center = {best_c}\n")

    # 2) report base vs GDA on TEST and ALL
    for name, ds in (("TEST (held-out)", test), ("FULL corpus", dump_all)):
        base = evaluate(ds, wguard=0.0)
        gda = evaluate(ds, wguard=best_w, center=best_c)
        print(f"=== {name} ===")
        print(f"  baseline    : {_fmt(base)}")
        print(f"  GDA(w={best_w},c={best_c}): {_fmt(gda)}")
        bh, gh = _cf_hits(ds, 0.0), _cf_hits(ds, best_w, best_c)
        for k in (1, 10):
            gained, lost = _mcnemar(bh, gh, k)
            print(f"    K={k:<2} plugins gained={gained} lost={lost} net={gained-lost}")
        # per-class deltas on guard + top classes
        print("  per-class cf@1 / cf@10 (base -> GDA):")
        for cls in ("auth", "csrf", "sqli", "xss", "deserial", "lfi", "rce",
                    "ssrf", "upload", "other"):
            b = base["per"].get(cls)
            g = gda["per"].get(cls)
            if not b:
                continue
            print(f"    {cls:9} n={b['n']:<4} "
                  f"cf@1 {b[1]:.3f}->{g[1]:.3f}   cf@10 {b[10]:.3f}->{g[10]:.3f}")
        print()


if __name__ == "__main__":
    main()
