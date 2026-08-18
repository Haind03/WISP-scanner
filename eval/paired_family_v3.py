#!/usr/bin/env python3
"""The whole paired comparison family on matched-100, from one scorer, including the
exact-changed-line endpoint.

Two contract requirements were not met by the family the paper tabulates:

  * s7: "Paired comparisons: ... Holm-corrected over the whole comparison family, and
    the family MUST include the exact-changed-line endpoint (the current family omits
    it, so the 'no separation at line granularity' claim has no paired test behind
    it)." eval/matched100_cluster_paired.py builds `class + pf@K + cf@K` only - nine
    endpoints, no line rung - so the exact-line paired numbers quoted in the manuscript
    had no producing script and no output JSON.
  * s2: "There is exactly one ground-truth module (eval/patch_geometry.py)." The older
    family read two per-tool run files scored by eval/localize, not by patch_geometry.

This script fixes both: every indicator is derived from FINDING_POPULATION_V3.jsonl,
which is the patch_geometry-scored population the primary ladder already uses, over the
FULL record denominator from the sample file (contract s3/s4 failure-as-miss: a record a
tool never answered contributes a 0, it is not dropped).

Endpoints, per record and tool:
    class      any finding, any rank, whose reported class matches the advisory class
    pf@K       a finding at rank <= K in a patch-changed file
    cf@K       a finding at rank <= K in a patch-changed file AND class-matching
    exact@K    a finding at rank <= K on a vulnerable-side changed line

    PYTHONHASHSEED=0 python3 -m eval.paired_family_v3

Writes revision-cns-v2/out/PAIRED_FAMILY_V3.json.
"""
from __future__ import annotations
import os, sys, json, argparse, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.matched100_cluster_paired import mcnemar_exact, perm_cluster, boot_delta, holm
from eval import adjudication_v3_common as C

POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "PAIRED_FAMILY_V3.json")

BASELINES = ("semgrep", "progpilot", "wpt")
KS = (1, 3, 5, 10)


def endpoints():
    """The TESTED family. Contract s7 fixes what must be in it: the class endpoint, the
    patch-file rungs, the class-and-file rungs, and the exact-changed-line rung."""
    return (["class"] + [f"pf@{K}" for K in KS] + [f"cf@{K}" for K in KS]
            + [f"exact@{K}" for K in KS])


def diagnostic_endpoints():
    """Reported as point estimates only, never entered into the tested family.

    tab:exact tightens class-and-file to the changed callable and to a five-line window.
    They are diagnostics, and adding 24 more comparisons to the family would make the
    Holm threshold answer a question nobody asked. They are computed here so they come
    from the same scorer and the same failure policy as everything else, instead of from
    a separate run whose class labels drifted."""
    return [f"cfn@{K}" for K in KS] + [f"cprox@{K}" for K in KS]


def indicators(pop_rows, keys):
    """tool -> endpoint -> list of 0/1 aligned with `keys` (the full denominator)."""
    by = collections.defaultdict(lambda: collections.defaultdict(list))
    for g in pop_rows:
        by[g["tool"]][g["slug"] + "|" + g["cve"]].append(g)

    ind = {}
    for tool, per_rec in by.items():
        e = {ep: [] for ep in endpoints() + diagnostic_endpoints()}
        for k in keys:
            fs = per_rec.get(k, [])
            e["class"].append(1 if any(f["class_match"] for f in fs) else 0)
            for K in KS:
                top = [f for f in fs if f["rank"] <= K]
                e[f"pf@{K}"].append(1 if any(f["in_patched_file"] for f in top) else 0)
                e[f"cf@{K}"].append(
                    1 if any(f["in_patched_file"] and f["class_match"] for f in top) else 0)
                e[f"exact@{K}"].append(
                    1 if any(f["on_exact_changed_line"] for f in top) else 0)
                e[f"cfn@{K}"].append(
                    1 if any(f["in_patched_file"] and f["class_match"]
                             and f["same_callable_as_change"] for f in top) else 0)
                e[f"cprox@{K}"].append(
                    1 if any(f["in_patched_file"] and f["class_match"]
                             and f["within_5_changed_lines"] for f in top) else 0)
        ind[tool] = e
    return ind


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260730)
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--failure-policy", default="contract", choices=("contract", "kept"),
                    help="contract = s4 rule 3 applied (headline); kept = the robustness arm")
    a = ap.parse_args()

    keys = [l.strip() for l in open(SAMPLE) if l.strip()]
    slugs = [k.split("|")[0] for k in keys]
    # One loader, one failure policy, so this family cannot disagree with the ladder about
    # which records WISP is credited for.
    pop = C.load_population(failure_policy=a.failure_policy)
    ind = indicators(pop, keys)

    present = [t for t in BASELINES if t in ind]
    missing = [t for t in BASELINES if t not in ind]
    if "wisp" not in ind:
        sys.exit("no WISP rows in the finding population")

    res = {
        "schema_version": "paired-family-v3",
        "contract": "EVALUATION-CONTRACT.md v1 s2 (one scorer), s3/s4 (full denominator, "
                    "failure-as-miss), s7 (family includes the exact-changed-line endpoint)",
        "source": os.path.relpath(POP, SYS_ROOT),
        "denominator": os.path.relpath(SAMPLE, SYS_ROOT),
        "n_records": len(keys),
        "n_slugs": len(set(slugs)),
        "bootstrap": {"reps": a.B, "seed": a.seed, "unit": "plugin slug (cluster)"},
        "failure_policy": a.failure_policy,
        "baselines_present": present,
        "baselines_absent_from_population": missing,
        "point_estimates": {},
        "comparisons": {},
    }

    for tool in ["wisp"] + present:
        res["point_estimates"][tool] = {
            ep: round(sum(ind[tool][ep]) / len(keys), 4)
            for ep in endpoints() + diagnostic_endpoints()}
    res["tested_endpoints"] = endpoints()
    res["diagnostic_endpoints_not_in_family"] = diagnostic_endpoints()

    family = []
    for ep in endpoints():
        x = ind["wisp"][ep]
        for t in present:
            y = ind[t][ep]
            b = sum(1 for i, j in zip(x, y) if i and not j)
            c = sum(1 for i, j in zip(x, y) if j and not i)
            name = f"{ep} vs {t}"
            pm = mcnemar_exact(b, c)
            pp = perm_cluster(x, y, slugs, a.B, a.seed)
            ci = boot_delta(x, y, slugs, a.B, a.seed)
            res["comparisons"][name] = {
                "endpoint": ep, "baseline": t,
                "wisp_rate": round(sum(x) / len(keys), 4),
                "baseline_rate": round(sum(y) / len(keys), 4),
                "delta": round((sum(x) - sum(y)) / len(keys), 4),
                "discordant_wisp_only": b, "discordant_baseline_only": c,
                "p_mcnemar_exact": pm, "p_cluster_permutation": pp,
                "clustered_ci_delta": ci,
                "ci_excludes_zero": bool(ci[0] > 0 or ci[1] < 0),
            }
            family.append((name, pp))

    adj = holm(family)
    surv = 0
    for name, p in adj.items():
        res["comparisons"][name]["p_holm_adjusted"] = p
        sig = p < a.alpha
        res["comparisons"][name]["survives_holm"] = sig
        surv += sig
    res["family"] = {
        "size": len(family),
        "alpha": a.alpha,
        "survive_holm": surv,
        "fail_holm": sorted(n for n in adj if not res["comparisons"][n]["survives_holm"]),
    }

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1, sort_keys=True)

    print(f"{len(keys)} records, {len(set(slugs))} slugs; family of {len(family)} "
          f"({len(endpoints())} endpoints x {len(present)} baselines)")
    if missing:
        print(f"NOTE: absent from the population, so not compared: {', '.join(missing)}")
    print(f"\n{'endpoint':10} " + " ".join(f"{t:>10}" for t in ["wisp"] + present))
    for ep in endpoints():
        print(f"{ep:10} " + " ".join(
            f"{res['point_estimates'][t][ep]:>10.3f}" for t in ["wisp"] + present))
    print(f"\nHolm at alpha={a.alpha}: {surv}/{len(family)} survive")
    for n in res["family"]["fail_holm"]:
        c = res["comparisons"][n]
        print(f"  does NOT survive: {n:24} delta={c['delta']:+.3f} "
              f"CI={c['clustered_ci_delta']} p_holm={c['p_holm_adjusted']}")
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
