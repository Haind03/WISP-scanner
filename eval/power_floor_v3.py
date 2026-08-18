#!/usr/bin/env python3
"""What the paired family could and could not have detected, per comparison.

The paper reports that nothing separates at line granularity. A reviewer asked, correctly, whether
that is evidence of absence or absence of evidence. For an exact McNemar test the answer is exact
rather than approximate: the test statistic depends only on the discordant pairs, so the smallest
attainable two-sided p-value for a comparison with n discordant pairs is the one where every pair
falls the same way, 2 * 0.5**n. If that floor already exceeds the threshold, the comparison could
not have rejected whatever the tools actually do, and reporting it as "no difference" would be
reporting the design rather than the result.

Holm makes this sharper. The strictest step of a family of k tests at alpha compares against
alpha/k, so a comparison needs enough discordant pairs to clear that, not just alpha.

    python3 -m eval.power_floor_v3
"""
from __future__ import annotations
import os, sys, json
from itertools import count

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
SRC = os.path.join(OUT_DIR, "PAIRED_FAMILY_V3.json")
OUT = os.path.join(OUT_DIR, "POWER_FLOOR_V3.json")


def floor_p(n):
    """Smallest two-sided exact McNemar p reachable with n discordant pairs."""
    return min(1.0, 2 * 0.5 ** n) if n else 1.0


def pairs_needed(threshold):
    """Fewest discordant pairs whose most extreme split clears a threshold."""
    for n in count(1):
        if floor_p(n) <= threshold:
            return n


def main():
    d = json.load(open(SRC, encoding="utf-8"))
    comps, fam = d["comparisons"], d["family"]
    alpha, k = fam["alpha"], fam["size"]
    strict = alpha / k

    rows = {}
    for key, r in comps.items():
        w = r["discordant_wisp_only"]
        l = r["discordant_baseline_only"]
        n = w + l
        rows[key] = {
            "endpoint": r["endpoint"], "baseline": r["baseline"],
            "discordant_total": n, "discordant_wisp_only": w, "discordant_baseline_only": l,
            "floor_p": round(floor_p(n), 6),
            "could_reach_alpha": floor_p(n) <= alpha,
            "could_reach_holm_strictest": floor_p(n) <= strict,
        }
    undetectable = sorted(k2 for k2, v in rows.items() if not v["could_reach_holm_strictest"])
    res = {
        "schema_version": "power-floor-v3",
        "script": "eval/power_floor_v3.py",
        "method": ("exact two-sided McNemar. With n discordant pairs the smallest attainable "
                   "p-value is 2*0.5**n, reached when every discordant pair falls one way, so a "
                   "comparison whose floor exceeds the threshold cannot reject at that threshold "
                   "regardless of the underlying difference"),
        "alpha": alpha,
        "family_size": k,
        "holm_strictest_threshold": round(strict, 6),
        "pairs_needed_at_alpha": pairs_needed(alpha),
        "pairs_needed_at_holm_strictest": pairs_needed(strict),
        "n_comparisons": len(rows),
        "n_undetectable_at_holm_strictest": len(undetectable),
        "undetectable_at_holm_strictest": undetectable,
        "comparisons": rows,
    }
    json.dump(res, open(OUT, "w"), indent=1, sort_keys=True)
    print(f"wrote {OUT}")
    print(f"  alpha {alpha}, family {k}, strictest Holm threshold {strict:.5f}")
    print(f"  discordant pairs needed: {res['pairs_needed_at_alpha']} at alpha, "
          f"{res['pairs_needed_at_holm_strictest']} at the strictest Holm step")
    print(f"  {len(undetectable)} of {len(rows)} comparisons could not have rejected at that "
          f"step whatever the tools do:")
    for kk in undetectable:
        print(f"    {kk}  ({rows[kk]['discordant_total']} discordant, "
              f"floor p={rows[kk]['floor_p']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
