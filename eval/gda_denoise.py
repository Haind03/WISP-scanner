#!/usr/bin/env python3
"""Learned per-sink RELIABILITY prior to un-bury the advisory finding.

The class-and-file gap to wp-taint is a burial problem: WISP emits ~45 findings/
plugin (wp-taint ~14), so the correct-class finding sits at median rank ~10. We
learn, on the TRAIN split only, a reliability for each sink signature -
P(this emission is the advisory finding | it was emitted) - and add w_rel * that
reliability to the exploitability score, demoting the sink types that are almost
never the advisory (speculative callback rce, unserialize risk pattern, ...). The
prior is estimated on train and applied unchanged to the held-out test split and to
the matched-100 head-to-head with wp-taint, so it cannot be over-fit to the report.

    python3 -m eval.gda_denoise out/gda_dump_sink.json
"""
from __future__ import annotations
import sys, json
from collections import defaultdict
from eval.gda_sweep import filter_split, score, KS

_CLS = ["auth", "csrf", "sqli", "xss", "deserial", "lfi", "rce", "ssrf",
        "upload", "other"]


def _sig(f):
    if f.get("src") == "unserialize(untrusted)":
        return "risk:unserialize"
    sink = (f.get("sink") or "").lstrip("$>-")
    return f"{f['cls']}:{sink}" if sink else f"{f['cls']}:?"


def learn_reliability(train):
    """reliability[sig] = P(emission of sig is the right-class-in-patched-file
    advisory finding). Laplace-smoothed. Learned on TRAIN only."""
    adv = defaultdict(int)
    total = defaultdict(int)
    for d in train:
        gt = set(d["gt_files"])
        cls = d["cls"]
        for f in d["findings"]:
            sig = _sig(f)
            total[sig] += 1
            if f["file"] in gt and f["cls"] == cls:
                adv[sig] += 1
    return {s: (adv[s] + 0.5) / (total[s] + 5.0) for s in total}, adv, total


def _score_rel(f, rel, w_rel):
    return score(f, 1.0, 0.5, None, None, 0.0) + w_rel * rel.get(_sig(f), 0.1)


def _cf(ds, keyfn):
    agg = {k: 0 for k in KS}
    per = defaultdict(lambda: {**{k: 0 for k in KS}, "n": 0})
    for d in ds:
        gt = set(d["gt_files"])
        cls = d["cls"]
        feats = sorted(d["findings"], key=keyfn, reverse=True)
        per[cls]["n"] += 1
        for k in KS:
            if any(f["file"] in gt and f["cls"] == cls for f in feats[:k]):
                agg[k] += 1
                per[cls][k] += 1
    n = len(ds) or 1
    return ({k: round(agg[k] / n, 4) for k in KS}, per)


def _macro(per, k):
    vals = [per[c][k] / per[c]["n"] for c in _CLS if per.get(c, {}).get("n")]
    return sum(vals) / len(vals) if vals else 0


def main():
    dump = json.load(open(sys.argv[1]))
    train = filter_split(dump, "train")
    test = filter_split(dump, "test")
    rel, adv, total = learn_reliability(train)

    print("=== lowest-reliability emitted sink types (demotion targets, >=40 emits) ===")
    for s in sorted(rel, key=lambda s: rel[s]):
        if total[s] >= 40:
            print(f"  {s:34} emits={total[s]:>4} advisory={adv[s]:>3} reliability={rel[s]:.3f}")

    base_key = lambda f: score(f, 1.0, 0.5, None, None, 0.0)

    # calibrate w_rel on TRAIN: max micro cf@1 s.t. macro@1/@10 not degraded
    bcf, bper = _cf(train, base_key)
    bm1, bm10 = _macro(bper, 1), _macro(bper, 10)
    best_w, best_micro = 0.0, bcf[1]
    print(f"\n=== calibrate w_rel on TRAIN (base micro@1={bcf[1]:.4f}) ===")
    for w in (0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0):
        cf, per = _cf(train, lambda f, w=w: _score_rel(f, rel, w))
        m1, m10 = _macro(per, 1), _macro(per, 10)
        ok = m1 >= bm1 - 1e-9 and m10 >= bm10 - 0.005
        print(f"  w_rel={w:<4} micro@1={cf[1]:.4f} macro@1={m1:.4f} macro@10={m10:.4f} {'OK' if ok else 'x'}")
        if ok and cf[1] >= best_micro:
            best_micro, best_w = cf[1], w
    print(f"  -> chosen w_rel = {best_w}")

    key = lambda f: _score_rel(f, rel, best_w)
    print(f"\n=== RESULTS (GDA ranking -> +learned denoise, w_rel={best_w}) ===")
    for name, ds in (("TEST held-out", test), ("FULL corpus", dump)):
        b, _ = _cf(ds, base_key)
        g, _ = _cf(ds, key)
        print(f"  {name:16} base {dict(b)}")
        print(f"  {name:16} +rel {dict(g)}")

    # matched-100 head-to-head vs wp-taint
    try:
        s100 = json.load(open("final/results/localize_s100_atk_0711.json"))
        keys = {(d["slug"], d["cve"]) for d in s100["details"]}
        m = [d for d in dump if (d["slug"], d["cve"]) in keys]
        b, _ = _cf(m, base_key)
        g, _ = _cf(m, key)
        print(f"\n  matched-100 wp-taint : {{1: 0.13, 3: 0.15, 5: 0.17, 10: 0.21}}")
        print(f"  matched-100 WISP base : {dict(b)}")
        print(f"  matched-100 WISP +rel : {dict(g)}")
    except Exception as e:
        print("matched-100 compare skipped:", e)


if __name__ == "__main__":
    main()
