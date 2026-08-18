#!/usr/bin/env python3
"""Recompute the matched-100 class-hit statistics against the correct advisory class.

Everything in the paper's matched-100 paragraph that mentions a class was computed
from a run whose records all carried cls="other" (see eval/rescore_matched100.py).
That includes the per-tool class emission with its intervals AND the paired
McNemar tests, because the paired indicator is the class hit itself. WISP was
scored from a different file with the right classes, so only the baselines and
therefore every WISP-versus-baseline pair are affected.

WISP's indicator comes from rank_first_class in the granularity run. The baselines'
come from the rescored stored findings. No tool is re-executed.

    python3 -m eval.matched100_paired --out out/paired_20260717/MATCHED100_PAIRED.json
"""
from __future__ import annotations
import os, sys, json, random, argparse
from math import comb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SYS_ROOT = os.environ.get("WISP_SYS_ROOT") or os.path.dirname(ROOT)
WISP_RUN = os.path.join(SYS_ROOT, "final", "results", "granularity_gda_off_after_emission_final.json")
RESCORED = "out/paired_20260717/MATCHED100_RESCORED.json"
OLD_RUN = "out/corrected_20260713/matched_100_baselines_final.json"
TOOLS = ("semgrep", "progpilot", "wpt")


def mcnemar_exact(b, c):
    """Two-sided exact McNemar over the discordant pairs only."""
    n = b + c
    if n == 0:
        return 1.0
    lo = min(b, c)
    tail = sum(comb(n, i) for i in range(lo + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def boot_rate(hits, slugs, B, seed):
    rnd = random.Random(seed)
    by = {}
    for h, s in zip(hits, slugs):
        by.setdefault(s, []).append(h)
    keys = sorted(by)
    out = []
    for _ in range(B):
        v = [x for k in (rnd.choice(keys) for _ in keys) for x in by[k]]
        out.append(sum(v) / len(v))
    out.sort()
    return [round(out[int(0.025 * B)], 3), round(out[int(0.975 * B)], 3)]


def boot_delta(a, b, slugs, B, seed):
    rnd = random.Random(seed)
    by = {}
    for x, y, s in zip(a, b, slugs):
        by.setdefault(s, []).append((x, y))
    keys = sorted(by)
    out = []
    for _ in range(B):
        pairs = [p for k in (rnd.choice(keys) for _ in keys) for p in by[k]]
        out.append(sum(p[0] for p in pairs) / len(pairs) -
                   sum(p[1] for p in pairs) / len(pairs))
    out.sort()
    return [round(out[int(0.025 * B)], 3), round(out[int(0.975 * B)], 3)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    wisp = {d["slug"] + "|" + d["cve"]: d for d in json.load(open(WISP_RUN))["details"]}
    resc = json.load(open(RESCORED))
    per = {d["key"]: d for d in json.load(open(RESCORED)).get("per_record", [])}
    # the rescored report keeps aggregates; rebuild per-record from its source run
    old = json.load(open(OLD_RUN))
    stored = {d["slug"] + "|" + d["cve"]: d for d in old["details"]}

    # per-record corrected hit for the baselines, recomputed here from the same
    # rule the rescorer used: the advisory class appears among a finding's classes
    from eval.datasets.patchstack import load_rows
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = sorted(k for k in stored if k in rows and k in wisp)
    print(f"paired over {len(keys)} records, {len({k.split('|')[0] for k in keys})} slugs")

    slugs = [k.split("|")[0] for k in keys]
    wisp_hit = [1 if wisp[k].get("rank_first_class") is not None else 0 for k in keys]
    base_hit = {}
    for t in TOOLS:
        v = []
        for k in keys:
            cls = rows[k]["cls"]
            fs = (stored[k].get(t) or {}).get("findings") or []
            v.append(1 if any(cls in (f.get("classes") or []) for f in fs) else 0)
        base_hit[t] = v

    rep = {"n": len(keys), "B": a.B, "seed": a.seed,
           "note": "class-hit indicator recomputed against the correct advisory class",
           "class_emission": {}, "paired_vs_wisp": {}}

    rep["class_emission"]["wisp"] = {
        "rate": round(sum(wisp_hit) / len(keys), 3),
        "ci95": boot_rate(wisp_hit, slugs, a.B, a.seed)}
    print(f"\n{'tool':10} {'published':>10} {'corrected':>10}  {'CI':>16}")
    print("-" * 52)
    print(f"{'WISP':10} {0.70:>10} {rep['class_emission']['wisp']['rate']:>10}  "
          f"{str(rep['class_emission']['wisp']['ci95']):>16}")
    for t in TOOLS:
        r = round(sum(base_hit[t]) / len(keys), 3)
        ci = boot_rate(base_hit[t], slugs, a.B, a.seed)
        rep["class_emission"][t] = {"rate": r, "ci95": ci,
                                    "published": old["summary"][t]["class_emission"]}
        print(f"{t:10} {old['summary'][t]['class_emission']:>10} {r:>10}  {str(ci):>16}")

    print(f"\n{'pair':16} {'WISP wins':>9} {'loses':>6} {'McNemar p':>12}  {'clustered CI':>18}")
    print("-" * 68)
    for t in TOOLS:
        b = sum(1 for x, y in zip(wisp_hit, base_hit[t]) if x and not y)
        c = sum(1 for x, y in zip(wisp_hit, base_hit[t]) if y and not x)
        p = mcnemar_exact(b, c)
        ci = boot_delta(wisp_hit, base_hit[t], slugs, a.B, a.seed)
        rep["paired_vs_wisp"][t] = {"wisp_wins": b, "wisp_loses": c,
                                   "mcnemar_p": p, "delta_ci95": ci,
                                   "delta": round(sum(wisp_hit) / len(keys) -
                                                  sum(base_hit[t]) / len(keys), 3)}
        ps = f"{p:.2e}" if p < 1e-4 else f"{p:.4f}"
        print(f"{'WISP vs '+t:16} {b:>9} {c:>6} {ps:>12}  {str(ci):>18}")

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
