#!/usr/bin/env python3
"""Compare the three WISP configurations on the shared corpus, matched by (slug,cve):

  A  original WISP            : default emission + baseline ranking (wguard=0)
  B  + GDA ranking (phase 1) : default emission + guard-deficit ranking (wguard=0.5)
  C  + GDA emission (phase 2): dominance-based emission + guard-deficit ranking

Reports micro/macro class-and-file@K, the auth/csrf coverage ceiling (right class
in a patched file at ANY rank - the recall the ranking can draw on), and
findings/plugin (a precision proxy).

  python3 -m eval.gda_phase2 out/gda_dump_full.json out/gda_dump_emit.json [split]
"""
from __future__ import annotations
import sys, json
from eval.gda_sweep import filter_split, evaluate

KS = (1, 3, 5, 10)
_CLS = ["auth", "csrf", "sqli", "xss", "deserial", "lfi", "rce", "ssrf",
        "upload", "other"]


def _ceil(dump, cls):
    n = tp = 0
    for d in dump:
        if d["cls"] != cls:
            continue
        n += 1
        gt = set(d["gt_files"])
        if any(f["file"] in gt and f["cls"] == cls for f in d["findings"]):
            tp += 1
    return tp, n


def _macro(r, k):
    return sum(r["per"].get(c, {}).get(k, 0) for c in _CLS) / len(_CLS)


def _fpp(dump):
    return sum(len(d["findings"]) for d in dump) / (len(dump) or 1)


def _summary(tag, dump, **kw):
    r = evaluate(dump, **kw)
    print(f"  {tag:32} micro@1={r['cf'][1]:.4f} micro@3={r['cf'][3]:.4f} "
          f"micro@10={r['cf'][10]:.4f}  macro@1={_macro(r,1):.4f} "
          f"macro@10={_macro(r,10):.4f}  find/plugin={_fpp(dump):.1f}")
    return r


def main():
    default = json.load(open(sys.argv[1]))
    emit = json.load(open(sys.argv[2]))
    split = sys.argv[3] if len(sys.argv) > 3 else "test"
    # match the two dumps to the same plugin set (same split, same keys)
    default = filter_split(default, split)
    emit = filter_split(emit, split)
    ek = {(d["slug"], d["cve"]) for d in emit}
    dk = {(d["slug"], d["cve"]) for d in default}
    common = ek & dk
    default = [d for d in default if (d["slug"], d["cve"]) in common]
    emit = [d for d in emit if (d["slug"], d["cve"]) in common]
    print(f"[split={split}] matched plugins: {len(common)}\n")

    print("=== class-and-file@K ===")
    A = _summary("A original WISP (w=0)", default, wguard=0.0)
    B = _summary("B +GDA ranking (w=0.5)", default, wguard=0.5, center=0.0)
    C = _summary("C +GDA emission (w=0.5)", emit, wguard=0.5, center=0.0)

    print("\n=== auth/csrf coverage ceiling (right class in patched file, ANY rank) ===")
    for cls in ("auth", "csrf"):
        da, na = _ceil(default, cls)
        de, ne = _ceil(emit, cls)
        print(f"  {cls:5}  default emission {da}/{na}={da/(na or 1):.3f}   "
              f"GDA emission {de}/{ne}={de/(ne or 1):.3f}")

    print("\n=== per-class cf@10 (A original -> C +GDA emission) ===")
    for c in _CLS:
        a = A["per"].get(c, {})
        cc = C["per"].get(c, {})
        if not a:
            continue
        print(f"  {c:9} n={a['n']:<4} {a.get(10,0):.3f} -> {cc.get(10,0):.3f}")


if __name__ == "__main__":
    main()
