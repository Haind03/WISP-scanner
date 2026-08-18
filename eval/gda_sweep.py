#!/usr/bin/env python3
"""Offline ranking-parameter sweep over a gda_eval feature dump.

Scores class-and-file@K under several ranking formulations without re-running the
engine, so the guard-deficit weighting can be tuned in milliseconds:

  base   : original exploitability (entry + inter + conf), guard term off
  gterm  : base + wguard * deficit                         (promote unprotected)
  gconf  : base but the missing-guard finding's confidence is REPLACED by
           gc_a + gc_b * deficit (demote guard-dominated findings so other-class
           advisories surface), guard term off
  both   : gconf confidence AND + wguard * deficit

  python3 -m eval.gda_sweep out/gda_dump300.json
"""
from __future__ import annotations
import os, sys, json

KS = (1, 3, 5, 10)


def _old_keys():
    """(slug, cve) of the original 252 xlsx = TRAIN split."""
    import openpyxl
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    old = os.path.join(os.path.dirname(root), "patchstack_bugbounty",
                       "patchstack_vulnerable_plugins.xlsx")
    keys = set()
    try:
        wb = openpyxl.load_workbook(old, read_only=True)
        it = wb.active.iter_rows(values_only=True)
        hdr = list(next(it))
        si, ci = hdr.index("Slug"), hdr.index("CVE")
        for r in it:
            if r[si] and r[ci]:
                keys.add((str(r[si]).strip(), str(r[ci]).strip()))
    except Exception:
        pass
    return keys


def filter_split(dump, split):
    if split == "all":
        return dump
    old = _old_keys()
    return [d for d in dump
            if ((str(d.get("slug", "")).strip(), str(d.get("cve", "")).strip()) in old)
            == (split == "train")]
_EW = {"ajax_nopriv": 5.0, "rest_api": 4.0, "shortcode": 3.0,
       "ajax_auth": 2.5, "admin": 1.0, "unknown": 0.5}


def _is_guard(f):
    return f["cls"] in ("csrf", "auth") and f["deficit"] >= 0.0


def score(f, wflow, wguard, gc_a, gc_b, center=0.0):
    conf = f["conf"]
    if gc_b is not None and _is_guard(f):
        conf = gc_a + gc_b * f["deficit"]
    # guard term: wguard*(deficit-center). center=0 => additive (promote unprotected
    # only); center=0.5 => balanced (promote unprotected, DEMOTE guard-dominated so
    # non-guard advisories surface). Applies only to missing-guard findings.
    guard_term = (wguard * (f["deficit"] - center)
                  if (wguard and f["deficit"] >= 0.0) else 0.0)
    return _EW.get(f["ep"], 0.5) + (1.0 if f["inter"] else 0.0) + wflow * conf + guard_term


def evaluate(dump, wflow=1.0, wguard=0.0, gc_a=None, gc_b=None, center=0.0):
    agg = {k: 0 for k in KS}
    per = {}
    n = 0
    for d in dump:
        gt = set(d["gt_files"])
        cls = d["cls"]
        feats = sorted(d["findings"],
                       key=lambda f: score(f, wflow, wguard, gc_a, gc_b, center),
                       reverse=True)
        pc = per.setdefault(cls, {**{k: 0 for k in KS}, "n": 0})
        pc["n"] += 1
        for k in KS:
            if any(f["file"] in gt and f["cls"] == cls for f in feats[:k]):
                agg[k] += 1
                pc[k] += 1
        n += 1
    d = n or 1
    return {"cf": {k: round(agg[k] / d, 4) for k in KS},
            "per": {c: {k: round(v[k] / v["n"], 3) for k in KS} | {"n": v["n"]}
                    for c, v in per.items()}, "n": n}


def main():
    dump = json.load(open(sys.argv[1]))
    split = sys.argv[2] if len(sys.argv) > 2 else "all"
    dump = filter_split(dump, split)
    print(f"[split={split}]")
    variants = [
        ("base                    ", dict(wguard=0.0)),
        ("gterm w=2               ", dict(wguard=2.0)),
        ("gterm w=3               ", dict(wguard=3.0)),
        ("gterm w=5               ", dict(wguard=5.0)),
        ("gconf a.15 b.5          ", dict(gc_a=0.15, gc_b=0.5)),
        ("gconf a.1 b.7           ", dict(gc_a=0.10, gc_b=0.7)),
        ("gconf a.0 b.9           ", dict(gc_a=0.0, gc_b=0.9)),
        ("both gconf.15/.5 +w2    ", dict(wguard=2.0, gc_a=0.15, gc_b=0.5)),
        ("both gconf.1/.7 +w3     ", dict(wguard=3.0, gc_a=0.10, gc_b=0.7)),
        ("both gconf.0/.9 +w3     ", dict(wguard=3.0, gc_a=0.0, gc_b=0.9)),
    ]
    print(f"dump n={len(dump)}\n")
    print(f"{'variant':26}{'cf@1':>8}{'cf@3':>8}{'cf@5':>8}{'cf@10':>8}")
    rows = []
    for name, kw in variants:
        r = evaluate(dump, **kw)
        rows.append((name, r))
        c = r["cf"]
        print(f"{name}{c[1]:>8}{c[3]:>8}{c[5]:>8}{c[10]:>8}")
    # per-class for the last "both" variant vs base, on the big classes
    base = evaluate(dump, wguard=0.0)
    best = rows[-1][1]
    print("\nper-class cf@1 / cf@10  (base -> best variant):")
    for c in sorted(set(base["per"]) | set(best["per"])):
        b = base["per"].get(c, {})
        v = best["per"].get(c, {})
        if not b:
            continue
        print(f"  {c:9} n={b['n']:<4} cf@1 {b.get(1,0):.2f}->{v.get(1,0):.2f}   "
              f"cf@10 {b.get(10,0):.2f}->{v.get(10,0):.2f}")


if __name__ == "__main__":
    main()
