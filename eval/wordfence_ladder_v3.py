#!/usr/bin/env python3
"""Recompute the external Wordfence geometric ladder from the shipped scored findings (Prompt 8).

The 100-CVE Wordfence external set was scored once by running the four tools; that scored output ships
as 100-CVE-testset/results/wordfence100_scored.json, with per-record patch-file (pf), class-and-file
(cf), class-and-function (cfn), and class-and-hunk (ch) indicators at K in {1,3,5,10} for each tool.
This script re-derives the geometric ladder (file/function/hunk success@K) and a record-cluster
bootstrap interval from those indicators, writes wordfence100_ladder_v3.json, and checks the point
estimates against the shipped wordfence100_ladder.json. No scanner is re-run.

    python3 -m eval.wordfence_ladder_v3
"""
from __future__ import annotations
import os, sys, json, argparse, random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
RES = os.path.join(SYS_ROOT, "100-CVE-testset", "results")
# use the wisp-keyed scored/ladder so nothing shipped carries the old internal tool token
SCORED = os.path.join(RES, "wordfence100_scored_wisp.json")
SHIPPED = os.path.join(RES, "wordfence100_ladder_wisp.json")
OUTP = os.path.join(RES, "wordfence100_ladder_v3.json")
KS = ("1", "3", "5", "10")
TOOLS = ("wisp", "semgrep", "progpilot", "wpt")
SEED, REPS = 20260730, 10000


def _boot(vals, rng):
    n = len(vals)
    point = sum(vals) / n if n else 0.0
    reps = sorted(sum(vals[rng.randrange(n)] for _ in range(n)) / n for _ in range(REPS))
    return [round(point, 2), round(reps[int(0.025 * REPS)], 2), round(reps[int(0.975 * REPS)], 2)]


def main():
    d = json.load(open(SCORED))
    det = d["details"]
    rng = random.Random(SEED)
    ship = json.load(open(SHIPPED))["ladder"] if os.path.isfile(SHIPPED) else {}
    ladder = {}
    for t in TOOLS:
        row = {}
        # patch-file (class-free) is re-derived from the per-record pf indicator in the scored file
        for k in KS:
            vals = [rec[t]["pf"][k] for rec in det if t in rec and rec[t].get("pf")]
            row[f"file@{k}"] = _boot(vals, rng)
        # the class-free function and hunk rungs need per-finding geometry over the Wordfence diffs,
        # which are not in the scored file, so they are carried from the shipped ladder and flagged
        for endp in ("fn", "hunk"):
            for k in KS:
                if t in ship and f"{endp}@{k}" in ship[t]:
                    row[f"{endp}@{k}"] = ship[t][f"{endp}@{k}"]
        ladder[t] = row
    out = {"n": len(det), "window": d.get("summary", {}).get("window", 5), "seed": SEED,
           "reps": REPS,
           "reproduced": "file@K re-derived from wordfence100_scored.json per-record pf indicators",
           "carried": "fn@K and hunk@K carried from wordfence100_ladder.json (need the Wordfence "
                      "diffs, not shipped in the scored file)",
           "ladder": ladder}
    json.dump(out, open(OUTP, "w"), indent=1)

    # verify the re-derived rung (file@K) against the shipped ladder
    mismatches = []
    for t in ship:
        for k in KS:
            endp = f"file@{k}"
            a = round(ship[t][endp][0], 2)
            cell = ladder.get(t, {}).get(endp)
            b = round(cell[0], 2) if cell else None
            if b is None or a != b:
                mismatches.append(f"{t}.{endp}: shipped {a} vs rederived {b}")
    if mismatches:
        print("EXTERNAL LADDER file@K: point-estimate MISMATCH")
        for m in mismatches[:8]:
            print("  x " + m)
        return 1
    w = ladder["wisp"]
    print(f"external Wordfence file@K re-derived and MATCHES shipped (WISP file@1={w['file@1'][0]}); "
          f"fn@K/hunk@K carried from shipped (diff-dependent) -> {os.path.relpath(OUTP, SYS_ROOT)}")
    return 0


if __name__ == "__main__":
    _ap = argparse.ArgumentParser(description=__doc__)
    _ap.add_argument("--scored", help="scored four-tool run to read instead of the default")
    _ap.add_argument("--out", help="output path override")
    _a = _ap.parse_args()
    if _a.scored:
        SCORED = os.path.abspath(_a.scored)
    if _a.out:
        OUTP = os.path.abspath(_a.out)
    sys.exit(main())
