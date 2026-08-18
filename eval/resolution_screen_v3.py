#!/usr/bin/env python3
"""A descriptive resolution screen: which non-separations this sample could have resolved.

NOT an equivalence test, and the distinction is the point. A formal equivalence result needs a
margin fixed before the data are seen and a design powered to clear it, and neither was done here.
An earlier version of this module and of the main text called the output an equivalence test while
the supplement said in plain words that no equivalence test had been run, so the paper contradicted
itself. This is the honest description of what the numbers are: a screen that reads the intervals
already computed against a stated margin, to separate the informative nulls from the underpowered
ones.

The paper says of several comparisons that they do not separate. A reviewer pointed out that this is
two different statements wearing one sentence. At exact-changed-line K=1 the WISP-versus-wp-taint-scan
comparison has eight discordant pairs in total, so no result it could have produced would have
reached the corrected threshold; calling that "no difference" reads as evidence of similarity when it
is an absence of evidence either way. At class emission, by contrast, the interval is tight and far
from zero, and a null there would genuinely mean the two are close.

This decides which is which, per comparison, from the intervals rather than by eye.

For each comparison the clustered interval on the paired difference is already computed by
`paired_family_v3`. The screen asks whether that whole interval lies inside a margin
$\\pm\\delta$. It needs no new resampling: an interval contained in $[-\\delta, +\\delta]$ is
`within_margin`, an interval that contains zero but reaches beyond the margin is `unresolved`, and an
interval excluding zero is `excludes_zero_uncorrected`. None of these three is a claim that two tools
are the same; `within_margin` says only that this sample could not place them further apart than
$\\delta$.

The margin is a judgment and is stated rather than tuned. We use $\\delta = 0.05$, five records in a
hundred, the same order as the significance level and small enough that a reader who cares about a
five-point difference is not served by being told the sample could not separate them. The output reports every comparison at
that margin and also the smallest margin at which each would pass, so a reader who prefers a
different threshold can apply it without rerunning anything.

    python3 -m eval.resolution_screen_v3            # writes RESOLUTION_SCREEN_V3.json
    python3 -m eval.resolution_screen_v3 --delta 0.1
"""
from __future__ import annotations
import os, sys, json, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")


def classify(lo, hi, delta):
    """From the interval alone, and the interval is UNCORRECTED.

    `excludes_zero_uncorrected` means this one interval excludes zero. It is not a separation: the
    paper's separations are the ones that survive Holm over the whole family, and several intervals
    here exclude zero while their corrected p-value does not (exact@5 against wp-taint-scan is one).
    The label says uncorrected so it can never be quoted as if it were the corrected verdict.
    """
    if lo > 0 or hi < 0:
        return "excludes_zero_uncorrected"
    if lo >= -delta and hi <= delta:
        return "within_margin"
    return "unresolved"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--delta", type=float, default=0.05,
                    help="resolution margin on the paired difference (default 0.05)")
    a = ap.parse_args()

    fam_p = os.path.join(OUT, "PAIRED_FAMILY_V3.json")
    if not os.path.isfile(fam_p):
        raise SystemExit("missing " + os.path.relpath(fam_p, SYS_ROOT))
    fam = json.load(open(fam_p, encoding="utf-8"))

    rows = {}
    for key, c in sorted(fam["comparisons"].items()):
        lo, hi = c["clustered_ci_delta"][:2]
        disc = int(c.get("discordant_wisp_only") or 0) + int(c.get("discordant_baseline_only") or 0)
        verdict = classify(lo, hi, a.delta)
        # the smallest symmetric margin this interval would fit inside, for a reader with a
        # different threshold in mind
        min_margin = None if (lo > 0 or hi < 0) else round(max(abs(lo), abs(hi)), 4)
        # A verdict of difference_uncorrected next to survives_holm == False is exactly the pair the
        # paper warns about, so name it here rather than leave a reader to notice.
        _note = ("uncorrected interval excludes zero but the comparison does not survive Holm over "
                 "the family, so it is not a separation"
                 if (verdict == "excludes_zero_uncorrected" and not c.get("survives_holm")) else None)
        rows[key] = {"endpoint": c["endpoint"], "baseline": c["baseline"],
                     "delta": c["delta"], "ci": [lo, hi],
                     "n_discordant_pairs": disc,
                     "survives_holm": bool(c.get("survives_holm")),
                     "verdict_at_delta": verdict,
                     "smallest_margin_containing_the_interval": min_margin,
                     "note": _note}

    counts = {}
    for r in rows.values():
        counts[r["verdict_at_delta"]] = counts.get(r["verdict_at_delta"], 0) + 1

    # the specific claim the reviewer named
    exact_k1 = {k: v for k, v in rows.items() if v["endpoint"] == "exact@1"}

    doc = {
        "schema_version": "resolution-screen-v3",
        "question": ("which of this paper's non-separations are evidence that two tools are close, "
                     "and which are only an absence of evidence"),
        "method": ("read off the clustered paired interval already computed by paired_family_v3: "
                   "an interval inside [-delta, +delta] is within_margin, one containing zero but "
                   "reaching past it is unresolved, one excluding zero is "
                   "excludes_zero_uncorrected; no new resampling and no hypothesis test"),
        "delta": a.delta,
        "delta_rationale": ("five records in a hundred, the same order as alpha and small enough "
                            "that a reader who cares about a five-point difference is not served "
                            "by a screen that cannot separate them; stated rather than tuned"),
        "counts_at_delta": counts,
        "exact_line_at_k1": exact_k1,
        "comparisons": rows,
        "not_an_equivalence_test": ("a formal equivalence result needs a margin fixed before the "
                                    "data are seen and a design powered to clear it, and neither "
                                    "was done here; within_margin says only that this sample could "
                                    "not place the two further apart than delta, never that they "
                                    "are the same, and unresolved is not evidence of difference"),
    }
    p = os.path.join(OUT, "RESOLUTION_SCREEN_V3.json")
    json.dump(doc, open(p, "w"), indent=1, sort_keys=True)
    print("wrote", os.path.relpath(p, SYS_ROOT), f"(delta={a.delta})")
    print(f"  at delta={a.delta}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    print(f"\n  {'comparison':28} {'delta':>7} {'interval':>18} {'disc':>5}  verdict")
    for k, r in sorted(rows.items(), key=lambda kv: (kv[1]["endpoint"], kv[1]["baseline"])):
        if r["endpoint"].startswith("exact") or r["verdict_at_delta"] == "within_margin":
            print(f"  {k:28} {r['delta']:+7.3f} [{r['ci'][0]:+6.3f},{r['ci'][1]:+6.3f}] "
                  f"{r['n_discordant_pairs']:5d}  {r['verdict_at_delta']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
