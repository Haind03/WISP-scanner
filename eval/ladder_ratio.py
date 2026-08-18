#!/usr/bin/env python3
"""Joint uncertainty for the ladder ratio: patch-file rate over defect rate.

The paper reports the top rung (a finding lands in a patched file) and the bottom
rung (two blinded reviewers agree it points at the defect) as separate estimates
and then divides them. Dividing two point estimates hides the fact that the
denominator is three findings. This script resamples plugin slugs once per
replicate and recomputes *both* rungs on the same resampled slugs, so the ratio
carries a single joint interval.

The denominator is zero in many replicates, which is the honest statement: the
ratio has no finite upper bound at this sample size. What survives is its lower
tail, and that is what the paper should claim.

    PYTHONHASHSEED=0 python3 -m eval.ladder_ratio --out out/ratio/LADDER_RATIO.json
"""
from __future__ import annotations
import os, sys, json, random, argparse, collections
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.ladder import one, WISP_CAP, WPT_RUN, TOPK
from eval.adjudication_weighted_v3 import population_index, load_sample

TOOLS = ("wisp", "wpt")


def ladder_rows(workers):
    """Per record, per tool, the top-3 findings with their in-file indicator."""
    wisp = {r["slug"] + "|" + r["cve"]: r for r in json.load(open(WISP_CAP))}
    stored = {d["slug"] + "|" + d["cve"]: d for d in json.load(open(WPT_RUN))["details"]}
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = sorted(k for k in wisp if k in stored and k in rows)
    print(f"ladder over the top-{TOPK} findings of {len(keys)} matched records", flush=True)
    res = []
    with Pool(workers) as pool:
        for i, d in enumerate(pool.imap_unordered(
                one, [(rows[k], stored[k], wisp[k]) for k in keys], chunksize=1), 1):
            res.append(d)
            if i % 20 == 0:
                print(f"  ...{i}/{len(keys)}", flush=True)
    bad = [d for d in res if d.get("err")]
    if bad:
        sys.exit(f"{len(bad)} record(s) failed: {bad[0]}")
    cls_of = {r["slug"] + "|" + r["cve"]: r["cls"] for r in load_rows()}
    per_slug = {}
    for d in res:
        slug = d["key"].split("|")[0]
        # register every matched-100 slug as a resampling unit, including a record
        # that yields zero findings from both tools. Such a record is still one of
        # the 98 matched-100 plugins and must enter the bootstrap: dropping it left
        # the draw over 97 slugs and shifted the ratio's lower percentile.
        cell = per_slug.setdefault(slug, {t: [] for t in TOOLS})
        cls = cls_of[d["key"]]
        for t in TOOLS:
            for rank, r in enumerate(d["tools"][t], 1):
                cell[t].append({"cls": cls, "rank": rank,
                                "in_file": bool(r["in_file"])})
    return per_slug


def weighted_from(cells, N):
    """Design-weighted defect rate over the cells the draw happens to cover."""
    covered = [c for c in N if c in cells]
    den = sum(N[c] for c in covered)
    if not den:
        return None
    return sum(N[c] * (cells[c][0] / cells[c][1]) for c in covered) / den


def joint(per_slug, adj_by_slug, B, seed):
    rnd = random.Random(seed)
    slugs = sorted(per_slug)
    out = {}
    for tool in TOOLS:
        ratios, nums, dens = [], [], []
        for _ in range(B):
            draw = [rnd.choice(slugs) for _ in slugs]
            pop = collections.Counter()
            hit = tot = 0
            for s in draw:
                for f in per_slug[s][tool]:
                    pop[(f["cls"], f["rank"])] += 1
                    tot += 1
                    hit += 1 if f["in_file"] else 0
            cells = collections.defaultdict(lambda: [0, 0])
            for s in draw:
                for r in adj_by_slug.get(s, []):
                    if r["tool"] != tool:
                        continue
                    c = cells[(r["cls"], r["rank"])]
                    c[1] += 1
                    c[0] += 1 if r["sd"] else 0
            if not tot:
                continue
            num = hit / tot
            den = weighted_from(cells, pop)
            if den is None:
                continue
            nums.append(num)
            dens.append(den)
            # a zero denominator is an infinite ratio, and it sorts above every
            # finite one, so the lower tail stays well defined and the upper does not.
            ratios.append(float("inf") if den == 0 else num / den)
        ratios.sort()
        nums.sort()
        dens.sort()
        n = len(ratios)
        nofinite = sum(1 for r in ratios if r == float("inf"))

        def q(v, p):
            if not v:
                return None
            x = v[min(int(p * len(v)), len(v) - 1)]
            return "unbounded" if x == float("inf") else round(x, 4)

        out[tool] = {
            "replicates": n,
            "replicates_zero_defect_rate": nofinite,
            "share_zero_defect_rate": round(nofinite / n, 4) if n else None,
            "ratio_p2_5": q(ratios, 0.025),
            "ratio_p50": q(ratios, 0.5),
            "ratio_p97_5": q(ratios, 0.975),
            "patch_file_rate_ci95": [q(nums, 0.025), q(nums, 0.975)],
            "defect_rate_ci95": [q(dens, 0.025), q(dens, 0.975)],
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260722)
    ap.add_argument("--cache", default="out/ratio/LADDER_ROWS.json")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    if os.path.exists(a.cache):
        per_slug = json.load(open(a.cache))
        print(f"reusing {a.cache}")
    else:
        per_slug = ladder_rows(a.workers)
        os.makedirs(os.path.dirname(a.cache) or ".", exist_ok=True)
        json.dump(per_slug, open(a.cache, "w"))
    per_slug = {k: v for k, v in per_slug.items()}

    pop, lut = population_index()
    rows, _ = load_sample(lut)
    adj_by_slug = collections.defaultdict(list)
    for r in rows:
        adj_by_slug[r["slug"]].append(r)

    rep = {"unit": "one finding from each tool's top-3 on matched-100",
           "n_slugs": len(per_slug), "B": a.B, "seed": a.seed,
           "note": "slugs are resampled once per replicate and both rungs are "
                   "recomputed on that draw, so the ratio carries one joint interval",
           "tools": joint(per_slug, adj_by_slug, a.B, a.seed)}

    for t in TOOLS:
        d = rep["tools"][t]
        print(f"\n{t}: ratio p2.5 {d['ratio_p2_5']}  median {d['ratio_p50']}  "
              f"p97.5 {d['ratio_p97_5']}")
        print(f"     zero-defect replicates {d['replicates_zero_defect_rate']}/"
              f"{d['replicates']} ({d['share_zero_defect_rate']})")
        print(f"     patch-file rate CI {d['patch_file_rate_ci95']}  "
              f"defect rate CI {d['defect_rate_ci95']}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
