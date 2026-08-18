#!/usr/bin/env python3
"""Plugin-clustered paired bootstrap CIs for the four-tool tables.

Table VII (full corpus, 1108 records) and Table VIII (the 520 records all four
tools complete) currently carry point estimates only, so the prose hedges every
comparison. This computes the paired intervals that decide which gaps are real.

Resampling unit is the plugin slug, not the record: a slug can carry several
advisories and their outcomes are not independent. Each replicate draws slugs
with replacement and scores every tool on the SAME draw, which is what makes the
difference paired and cancels the plugin-difficulty term.

Two metric families, and they answer different questions:

  emission (class recall) is defined on every record, because a tool that fails
  or says nothing simply does not emit the advisory class. Failure-as-miss, so
  the denominator is the whole record set and the comparison is honest on the
  full corpus.

  file-precision@K and whole-pool precision are ratios of sums whose denominator
  is the findings a tool actually emits. A record a tool never answers drops out
  of both sums, so these are conditional on emitting and a full-corpus interval
  compares tools over different record subsets. That is the coverage confound,
  and it is why the 520-record common subset exists. Intervals are reported for
  both views and the conditioning is stated, never silently pooled.

    python3 -m eval.paired_ci --out out/paired_20260717/PAIRED_CI.json
"""
from __future__ import annotations
import os, sys, json, glob, argparse, random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

KS = ("1", "3", "5", "10")
BASE = {"semgrep": "out/fill_20260714/atk_sg_1108.json",
        "progpilot": "out/fill_20260714/atk_pp_1108.json",
        "wp-taint-scan": "out/fill_20260714/atk_wpt_1108.json"}


def load_wisp(pat):
    det = {}
    files = sorted(glob.glob(pat))
    if not files:
        sys.exit(f"no WISP shards matched {pat}")
    for f in files:
        for d in json.load(open(f))["details"]:
            if "topk_tp" not in d:
                sys.exit(f"{f} predates the per-record @K counters; rerun eval.localize")
            det[d["slug"] + "|" + d["cve"]] = d
    return det


def load_base(path):
    det = {}
    for d in json.load(open(path))["details"]:
        det[d["slug"] + "|" + d["cve"]] = d
    return det


def metrics(det, keys):
    """Point metrics over a multiset of record keys (a bootstrap draw repeats keys)."""
    tp = {k: 0 for k in KS}
    n = {k: 0 for k in KS}
    ftp = nf = hits = 0
    for key in keys:
        d = det.get(key)
        if d is None:            # tool never scored this record
            continue
        for k in KS:
            tp[k] += d["topk_tp"][k]
            n[k] += d["topk_n"][k]
        ftp += d["file_tp"]
        nf += d["findings"]
        hits += 1 if d.get("hit") else 0
    m = {f"pf@{k}": (tp[k] / n[k] if n[k] else None) for k in KS}
    m["pool"] = ftp / nf if nf else None
    m["emission"] = hits / len(keys) if keys else None   # failure-as-miss
    m["f_per_rec"] = nf / len(keys) if keys else None
    return m


def boot(wisp, tools, keys, B, seed):
    """Paired clustered bootstrap. Returns delta CIs of WISP minus each tool."""
    rnd = random.Random(seed)
    by_slug = {}
    for key in keys:
        by_slug.setdefault(key.split("|")[0], []).append(key)
    slugs = sorted(by_slug)
    names = list(tools)
    fields = [f"pf@{k}" for k in KS] + ["pool", "emission"]
    draws = {t: {f: [] for f in fields} for t in names}
    for _ in range(B):
        pick = [by_slug[rnd.choice(slugs)] for _ in range(len(slugs))]
        rk = [k for grp in pick for k in grp]
        mn = metrics(wisp, rk)
        for t in names:
            mt = metrics(tools[t], rk)
            for f in fields:
                a, b = mn[f], mt[f]
                # a replicate that emits nothing leaves the ratio undefined; it
                # carries no information about the gap, so it is dropped rather
                # than coerced to zero, which would drag the interval down.
                if a is None or b is None:
                    continue
                draws[t][f].append(a - b)
    out = {}
    for t in names:
        out[t] = {}
        for f in fields:
            v = sorted(draws[t][f])
            if len(v) < B * 0.9:
                out[t][f] = {"note": f"undefined in {B-len(v)}/{B} replicates"}
                continue
            lo = v[int(0.025 * len(v))]
            hi = v[int(0.975 * len(v))]
            out[t][f] = {"lo": round(lo, 4), "hi": round(hi, 4),
                         "excludes_zero": bool(lo > 0 or hi < 0)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wisp", default="out/paired_20260717/loc_full/loc_*.json")
    ap.add_argument("--common", default="out/fill_20260714/common_subset_keys.json")
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260717)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    wisp = load_wisp(a.wisp)
    tools = {t: load_base(p) for t, p in BASE.items()}
    common = set(json.load(open(a.common)))
    full = sorted(wisp)
    print(f"WISP records {len(full)}; common subset {len(common)}")

    rep = {"B": a.B, "seed": a.seed, "cluster": "plugin slug",
           "wisp_source": a.wisp, "baseline_sources": BASE,
           "n_full": len(full), "n_common": len(common)}
    for view, keys in (("full_1108", full), ("common_520", sorted(common))):
        rep[view] = {"n_records": len(keys),
                     "n_slugs": len({k.split("|")[0] for k in keys}),
                     "point": {"WISP": metrics(wisp, keys),
                               **{t: metrics(tools[t], keys) for t in tools}},
                     "delta_ci": boot(wisp, tools, keys, a.B, a.seed)}
        print(f"  {view}: {len(keys)} records, "
              f"{rep[view]['n_slugs']} slugs")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
