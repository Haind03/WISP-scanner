#!/usr/bin/env python3
"""The log-log power-law fit behind the scalability figure, in one place.

The figure computed the fit inside the plotting function and printed it in a legend, while the
supplement typed the same slope and R-squared into prose. They agreed, but nothing connected them,
so a change to the input would have moved the legend and left the sentence behind. Both sides now
call this.

    python3 -m eval.scalability_fit
"""
from __future__ import annotations
import os, sys, json, math

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
INPUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "SCALABILITY_APPS_V3.json")
# The measurement lives outside the revision tree. Prefer the shipped copy so the bundle is
# self-contained, and fall back to the original when running from a full checkout.
FALLBACK = os.path.join(SYS_ROOT, "Reproduce_25_PHPBench_StaticAnalysis_Entropy",
                        "out_a4_fast.json")


def load_apps(path=None):
    for p in ([path] if path else [INPUT, FALLBACK]):
        if p and os.path.isfile(p):
            return json.load(open(p))
    raise SystemExit(f"no scalability input found (looked for {INPUT} and {FALLBACK})")


def fit(apps=None):
    """Least-squares fit of log10(scan_seconds) on log10(own PHP files).

    Returns slope, r2, n. A point with a zero on either axis has no logarithm and is dropped,
    which is the same set the figure plots.
    """
    apps = apps or load_apps()
    pts = [(r["php_own_code"], r["scan_seconds"]) for r in apps["results"]]
    pts = [(math.log10(x), math.log10(y)) for x, y in pts if x > 0 and y > 0]
    n = len(pts)
    if n < 2:
        raise SystemExit("scalability fit needs at least two usable points")
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    slope = sum((p[0] - mx) * (p[1] - my) for p in pts) / sxx
    icpt = my - slope * mx
    ss_res = sum((p[1] - (icpt + slope * p[0])) ** 2 for p in pts)
    ss_tot = sum((p[1] - my) ** 2 for p in pts)
    r2 = 1 - ss_res / ss_tot if ss_tot else 0.0
    return {"slope": slope, "intercept": icpt, "r2": r2, "n_points": n}


def main():
    f = fit()
    print(f"slope {f['slope']:.4f}  R2 {f['r2']:.4f}  over {f['n_points']} apps")


if __name__ == "__main__":
    main()
