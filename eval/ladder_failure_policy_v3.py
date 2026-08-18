#!/usr/bin/env python3
"""The geometric ladder under the contract's failure policy, and without it.

Contract v1 s4 rule 3: a record whose WISP analysis did not converge is a miss, scored over
the full denominator. The equal-budget matrix applies it. The geometric ladder - the paper's
primary table - does not: `eval/ladder_v3.py` reads each record's findings and never looks at
`wisp_converged`, so on the matched sample the 22 records that stop at a bounded approximation
are counted as clean successes. The revision notes report an *excluded* sensitivity for those
records, which is a third thing again: not the published arm and not the contract's arm.

The ladder's unit is a finding, not a record, so "miss" has to be said precisely. Three arms:

  kept       as published. Non-convergence ignored. Contract s4's robustness arm, not its headline.
  miss       contract canonical. A non-converged record's findings stay in the denominator and
             are credited at no rung: the tool emitted, but from an analysis that stopped at an
             approximation, so its output earns nothing.
  excluded   the record's findings leave both sides. Reported because the revision notes used
             this arm, and because it is the arm that conditions on WISP finishing, which is the
             survivor bias this paper criticises elsewhere.

Only WISP can move: the baselines have no convergence notion.

    python3 -m eval.ladder_failure_policy_v3
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
DATA = os.environ.get("WISP_REVISION_DATA") or os.path.join(
    SYS_ROOT, "final", "supplementary-data", "reproduce", "data")
TRAIN = os.path.join(DATA, "train_cap.json")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_FAILURE_POLICY_V3.json")

RUNGS = ["in_patched_file", "same_callable_as_change", "on_exact_changed_line",
         "within_5_changed_lines", "same_diff_hunk"]
TOPK = 3
REPS, SEED = 10000, 20260730


def boot(units, key, reps=REPS, seed=SEED):
    """Plugin-clustered bootstrap, the same unit and seed as every other interval here."""
    import numpy as np
    if not units:
        return None, None, None
    by = defaultdict(list)
    for u in units:
        by[u["slug"]].append(1 if u[key] else 0)
    slugs = sorted(by)
    num = sum(sum(by[s]) for s in slugs)
    den = sum(len(by[s]) for s in slugs)
    point = num / den if den else 0.0
    rng = np.random.default_rng(seed)
    idx = np.arange(len(slugs))
    vals = []
    for _ in range(reps):
        n = d = 0
        for i in rng.choice(idx, size=len(slugs), replace=True):
            v = by[slugs[i]]
            n += sum(v); d += len(v)
        if d:
            vals.append(n / d)
    lo, hi = (float(x) for x in np.percentile(vals, [2.5, 97.5]))
    return round(point, 4), round(lo, 4), round(hi, 4)


def load_convergence():
    """slug|cve -> converged. Prefer the flag carried in the population; fall back to the cache."""
    conv = {}
    if os.path.isfile(TRAIN):
        for r in json.load(open(TRAIN)):
            conv[r["slug"] + "|" + r["cve"]] = bool(r.get("wisp_converged", True))
    return conv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--population", default=POP)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    pop = [json.loads(l) for l in open(a.population)]
    top = [g for g in pop if g["rank"] <= TOPK]
    conv_cache = load_convergence()

    def converged(g):
        if g.get("wisp_converged") is not None:
            return bool(g["wisp_converged"])
        return conv_cache.get(g["slug"] + "|" + g["cve"], True)

    tools = sorted({g["tool"] for g in top})
    nonconv_keys = {k for k, v in conv_cache.items() if not v}
    res = {
        "schema_version": "ladder-failure-policy-v3",
        "contract": "EVALUATION-CONTRACT.md v1 s4 rule 3 + robustness clause",
        "population": os.path.relpath(a.population, SYS_ROOT),
        "topk": TOPK,
        "bootstrap": {"reps": REPS, "seed": SEED, "unit": "plugin slug (cluster)"},
        "n_records_non_converged": len(nonconv_keys),
        "n_records_total": len(conv_cache),
        "arms": {},
    }

    for arm in ("kept", "miss", "excluded"):
        per_tool = {}
        for tool in tools:
            us = [g for g in top if g["tool"] == tool]
            if arm == "excluded" and tool == "wisp":
                us = [g for g in us if converged(g)]
            if not us:
                continue
            entry = {"n_findings": len(us),
                     "n_records": len({g["slug"] + "|" + g["cve"] for g in us}),
                     "n_findings_from_non_converged":
                         sum(1 for g in us if tool == "wisp" and not converged(g))}
            for rung in RUNGS:
                if arm == "miss" and tool == "wisp":
                    units = [{"slug": g["slug"],
                              rung: (g[rung] and converged(g))} for g in us]
                else:
                    units = [{"slug": g["slug"], rung: g[rung]} for g in us]
                pt, lo, hi = boot(units, rung)
                entry[rung] = {"rate": pt, "ci": [lo, hi]}
            per_tool[tool] = entry
        res["arms"][arm] = per_tool

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1, sort_keys=True)

    print(f"{res['n_records_non_converged']} of {res['n_records_total']} records did not converge")
    hdr = f"{'arm':9} {'tool':10} {'n':>5} " + " ".join(f"{r.split('_')[0][:8]:>9}" for r in RUNGS)
    print("\n" + hdr)
    for arm in ("kept", "miss", "excluded"):
        for tool, e in res["arms"][arm].items():
            print(f"{arm:9} {tool:10} {e['n_findings']:>5} " +
                  " ".join(f"{e[r]['rate']:>9.4f}" for r in RUNGS))
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
