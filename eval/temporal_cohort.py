#!/usr/bin/env python3
"""Temporal cohorts: does the corpus-scale picture hold on the newest advisories?

Every record carries a CVE identifier, whose year is a coarse but honest proxy for
when the advisory was disclosed. Splitting the 1108 records by that year gives a
temporal holdout that costs no new scanning: the rules, the vocabulary, and the
ranking were all developed against the matched-100 sample, which is dominated by
the older cohort, so the newest cohort is the closest thing to a prospective test
this corpus can supply.

Reported per cohort and per tool: class emission with a plugin-clustered interval,
and for WISP the share of records where a finding lands in a patched file.

    PYTHONHASHSEED=0 python3 -m eval.temporal_cohort --out out/ratio/TEMPORAL.json
"""
from __future__ import annotations
import os, sys, json, re, random, argparse, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_RD = os.environ.get("WISP_REPRO_DATA")


def _rp(path):
    """Resolve an input against the standalone bundle dir when WISP_REPRO_DATA is set."""
    return os.path.join(_RD, os.path.basename(path)) if _RD else path


WISP_REC = _rp("out/corrected_20260713/recall_wisp_1108_final.json")
WISP_LOC = _rp("out/fill_20260714/loc_full_merged.json")
BASE = {"semgrep": _rp("out/fill_20260714/atk_sg_1108.json"),
        "progpilot": _rp("out/fill_20260714/atk_pp_1108.json"),
        "wpt": _rp("out/fill_20260714/atk_wpt_1108.json")}


def year(cve):
    m = re.match(r"CVE-(\d{4})-", cve or "")
    return int(m.group(1)) if m else None


def boot_rate(vals, slugs, B, seed):
    rnd = random.Random(seed)
    by = collections.defaultdict(list)
    for v, s in zip(vals, slugs):
        by[s].append(v)
    keys = sorted(by)
    out = []
    for _ in range(B):
        d = [x for k in (rnd.choice(keys) for _ in keys) for x in by[k]]
        out.append(sum(d) / len(d))
    out.sort()
    return [round(out[int(0.025 * B)], 3), round(out[int(0.975 * B)], 3)]


def boot_delta(va, sa, vb, sb, B, seed):
    """Unpaired difference between two cohorts, each resampled by plugin."""
    rnd = random.Random(seed)
    ba, bb = collections.defaultdict(list), collections.defaultdict(list)
    for v, s in zip(va, sa):
        ba[s].append(v)
    for v, s in zip(vb, sb):
        bb[s].append(v)
    ka, kb = sorted(ba), sorted(bb)
    out = []
    for _ in range(B):
        xa = [x for k in (rnd.choice(ka) for _ in ka) for x in ba[k]]
        xb = [x for k in (rnd.choice(kb) for _ in kb) for x in bb[k]]
        out.append(sum(xa) / len(xa) - sum(xb) / len(xb))
    out.sort()
    return [round(out[int(0.025 * B)], 3), round(out[int(0.975 * B)], 3)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260722)
    ap.add_argument("--split", type=int, default=2026,
                    help="records with CVE year >= this form the recent cohort")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    hit = {}
    wisp = json.load(open(WISP_REC))["details"]
    hit["wisp"] = {d["slug"] + "|" + d["cve"]: int(bool(d.get("hit"))) for d in wisp}
    meta = {d["slug"] + "|" + d["cve"]: d for d in wisp}
    for t, p in BASE.items():
        hit[t] = {d["slug"] + "|" + d["cve"]: int(bool(d.get("hit")))
                  for d in json.load(open(p))["details"]}
    loc = {d["slug"] + "|" + d["cve"]: int(bool(d.get("cve_localized")))
           for d in json.load(open(WISP_LOC))["details"]}

    keys = sorted(set(hit["wisp"]) & set(hit["wpt"]) & set(hit["semgrep"])
                  & set(hit["progpilot"]))
    cohort = {}
    for k in keys:
        y = year(k.split("|")[1])
        cohort[k] = "unknown" if y is None else ("recent" if y >= a.split else "older")
    counts = collections.Counter(cohort.values())
    print(f"{len(keys)} records: " + ", ".join(f"{c}={n}" for c, n in sorted(counts.items())))
    print(f"split at CVE year {a.split}\n")

    rep = {"n": len(keys), "split_year": a.split, "B": a.B, "seed": a.seed,
           "cohorts": {c: {"n": n} for c, n in counts.items()}, "tools": {}}
    for c in counts:
        ks = [k for k in keys if cohort[k] == c]
        rep["cohorts"][c]["n_slugs"] = len({k.split("|")[0] for k in ks})

    print(f"{'tool':10} " + " ".join(f"{c:>26}" for c in ("older", "recent")) +
          "      difference (older - recent)")
    print("-" * 92)
    for t in ("wisp", "semgrep", "progpilot", "wpt"):
        row = {}
        for c in ("older", "recent"):
            ks = [k for k in keys if cohort[k] == c]
            v = [hit[t][k] for k in ks]
            s = [k.split("|")[0] for k in ks]
            row[c] = {"n": len(ks), "rate": round(sum(v) / len(v), 4),
                      "ci95": boot_rate(v, s, a.B, a.seed)}
        ko = [k for k in keys if cohort[k] == "older"]
        kr = [k for k in keys if cohort[k] == "recent"]
        d = boot_delta([hit[t][k] for k in ko], [k.split("|")[0] for k in ko],
                       [hit[t][k] for k in kr], [k.split("|")[0] for k in kr],
                       a.B, a.seed)
        row["delta_older_minus_recent_ci95"] = d
        rep["tools"][t] = row
        print(f"{t:10} " + " ".join(
            f"{row[c]['rate']:.3f} {str(row[c]['ci95']):>16}" for c in ("older", "recent")) +
            f"      {d}")

    # WISP patch-file localization, same split
    row = {}
    for c in ("older", "recent"):
        ks = [k for k in keys if cohort[k] == c and k in loc]
        v = [loc[k] for k in ks]
        s = [k.split("|")[0] for k in ks]
        row[c] = {"n": len(ks), "rate": round(sum(v) / len(v), 4),
                  "ci95": boot_rate(v, s, a.B, a.seed)}
    rep["wisp_patch_file_localized"] = row
    print(f"\nWISP patch-file localized: older {row['older']['rate']:.3f} "
          f"{row['older']['ci95']}, recent {row['recent']['rate']:.3f} "
          f"{row['recent']['ci95']}")

    # per-year detail for WISP, so a reader can see the trend rather than one split
    peryear = {}
    for k in keys:
        y = year(k.split("|")[1])
        peryear.setdefault(y, []).append(hit["wisp"][k])
    rep["wisp_class_emission_by_year"] = {
        str(y): {"n": len(v), "rate": round(sum(v) / len(v), 4)}
        for y, v in sorted(peryear.items(), key=lambda t: (t[0] is None, t[0]))}
    print("\nWISP class emission by CVE year")
    for y, d in rep["wisp_class_emission_by_year"].items():
        print(f"  {y:>6}  n={d['n']:>4}  {d['rate']:.3f}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
