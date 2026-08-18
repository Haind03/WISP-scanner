#!/usr/bin/env python3
"""Does the patch-file endpoint order the tools the same way on two independent ground truths?

P0-7 asks whether the endpoint that replaced "defect identification" is itself validated. Full
construct validity needs a human to say that a finding names the disclosed defect, which is P1-A and
is not answered here. What *is* answerable from data already on disk is the weaker but still
necessary property: an endpoint that claims to measure a tool's localization should not reorder the
tools when the ground truth is drawn from a different source.

Two sources, no scanner re-run:

  Patchstack   revision-cns-v2/out/CORPUS_FINDING_POPULATION_V3.jsonl, 1108 records, 834 plugins
  Wordfence    revision-cns-v2/out/WORDFENCE_LADDER_TRUE_V3.json, 100 records, 100 plugins, drawn
               from the NVD feed restricted to the Wordfence CNA, with every corpus slug excluded

Both are scored record-level success@1 under the contract failure policy, so a record a tool
produced nothing for, or whose WISP analysis stopped short of a fixpoint, earns nothing. The
denominator is every record in the source, not the records that happened to yield findings.

The statistic is Spearman rank correlation between the two sources' orderings of the four tools, at
each rung. Four tools is a very short ranking, so rho takes one of a handful of values and its
interval is wide by construction. That is reported rather than hidden, and the concrete orderings and
the identity of the leading tool are reported beside it, because on four items those are what a
reader can actually check. Intervals come from resampling plugins within each source independently,
which is the same clustering unit the rest of the paper uses.

    python3 -m eval.endpoint_transfer_v3
"""
from __future__ import annotations
import os, sys, json, random, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CORPUS = os.path.join(OUT, "CORPUS_FINDING_POPULATION_V3.jsonl")
CORPUS_LADDER = os.path.join(OUT, "CORPUS_LADDER_V3.json")
# The authoritative record list. The population file only holds records that yielded a finding, so
# taking the plugin list from it would quietly drop the records every tool missed, which are exactly
# the ones failure-as-miss exists to count.
CORPUS_RECORDS = os.path.join(OUT, "CORPUS1108_WISP_CONTRACT_V3.json")
WORDFENCE = os.path.join(OUT, "WORDFENCE_LADDER_TRUE_V3.json")
DEST = os.path.join(OUT, "ENDPOINT_TRANSFER_V3.json")

TOOLS = ("wisp", "wpt", "semgrep", "progpilot")
RUNGS = ("in_patched_file", "same_callable_as_change", "on_exact_changed_line",
         "within_5_changed_lines", "same_diff_hunk")
SEED = 20260730
B = 10000
K = 1          # success@1: the cutoff every headline number in the paper uses


def _spearman(a, b):
    """Spearman rho on two equal-length rank vectors, ties averaged.

    Written out rather than imported so the artifact keeps its stdlib-only reproduction path."""
    n = len(a)
    if n < 2:
        return None

    def ranks(v):
        order = sorted(range(n), key=lambda i: v[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    ra, rb = ranks(a), ranks(b)
    ma, mb = sum(ra) / n, sum(rb) / n
    num = sum((ra[i] - ma) * (rb[i] - mb) for i in range(n))
    da = sum((ra[i] - ma) ** 2 for i in range(n)) ** 0.5
    db = sum((rb[i] - mb) ** 2 for i in range(n)) ** 0.5
    if da == 0 or db == 0:
        return None            # a constant vector has no ordering to correlate
    return num / (da * db)


def load_corpus():
    """Per plugin, per tool, per rung: did the rank-1 finding satisfy the rung?

    A record with no finding for a tool never appears in the population file, and under
    failure-as-miss it must still count against that tool, so the denominator is taken from the
    ladder's own record count rather than from the rows present here."""
    records = defaultdict(set)                        # slug -> {record ids}, every declared record
    for r in json.load(open(CORPUS_RECORDS, encoding="utf-8"))["details"]:
        records[r["slug"]].add((r["slug"], r["cve"]))

    # Keyed by record, not by plugin. 1108 records sit on 854 plugins, so collapsing to the plugin
    # would let one hit stand in for several records and inflate every rate.
    hit = defaultdict(lambda: defaultdict(dict))      # record -> tool -> rung -> bool (rank-1 only)
    seen_records = set()
    for line in open(CORPUS, encoding="utf-8"):
        r = json.loads(line)
        if r["rank"] > K:
            continue
        rec = (r["slug"], r["cve"])
        seen_records.add(rec)
        withheld = bool(r.get("credit_withheld_non_convergence"))
        for rung in RUNGS:
            prev = hit[rec][r["tool"]].get(rung, False)
            hit[rec][r["tool"]][rung] = prev or (bool(r.get(rung)) and not withheld)

    n_declared = json.load(open(CORPUS_LADDER, encoding="utf-8"))["records_scored"]
    n_listed = sum(len(v) for v in records.values())
    if n_listed != n_declared:
        raise SystemExit(f"record list holds {n_listed} records but the ladder declares {n_declared}")
    return hit, records, seen_records, n_declared


def load_wordfence():
    """Per record, per tool, per rung: was the rung first satisfied at rank 1?"""
    d = json.load(open(WORDFENCE, encoding="utf-8"))
    keys = d["record_keys"]
    fr = d["first_rank_per_record"]
    hit = defaultdict(lambda: defaultdict(dict))
    records = defaultdict(set)
    for i, key in enumerate(keys):
        slug = key.split("|")[0]
        rec = (slug, key)
        records[slug].add(rec)
        for tool in TOOLS:
            for rung in RUNGS:
                v = fr[tool][rung][i]
                hit[rec][tool][rung] = (v is not None and v <= K)
    return hit, records, d["n_records_scored"]


def rates(hit, records, slugs):
    """success@1 per tool per rung, denominator = every record the given plugins declare.

    `slugs` may repeat, which is what a clustered bootstrap draw looks like, and a repeated plugin
    contributes its records again on both sides of the fraction."""
    num = {t: {r: 0 for r in RUNGS} for t in TOOLS}
    denom = 0
    for s in slugs:
        for rec in records[s]:
            denom += 1
            for t in TOOLS:
                th = hit.get(rec, {}).get(t, {})
                for r in RUNGS:
                    if th.get(r):
                        num[t][r] += 1
    denom = denom or 1
    return {t: {r: num[t][r] / denom for r in RUNGS} for t in TOOLS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=B)
    a = ap.parse_args()

    c_hit, c_records, c_seen, c_declared = load_corpus()
    w_hit, w_records, w_declared = load_wordfence()
    c_slugs = sorted(c_records)
    w_slugs = sorted(w_records)
    c_denom, w_denom = c_declared, w_declared

    c_rates = rates(c_hit, c_records, c_slugs)
    w_rates = rates(w_hit, w_records, w_slugs)

    rng = random.Random(SEED)
    per_rung = {}
    for rung in RUNGS:
        cv = [c_rates[t][rung] for t in TOOLS]
        wv = [w_rates[t][rung] for t in TOOLS]
        rho = _spearman(cv, wv)
        c_order = [t for t in sorted(TOOLS, key=lambda t: -c_rates[t][rung])]
        w_order = [t for t in sorted(TOOLS, key=lambda t: -w_rates[t][rung])]

        boots = []
        for _ in range(a.reps):
            cs = [c_slugs[rng.randrange(len(c_slugs))] for _ in range(len(c_slugs))]
            ws = [w_slugs[rng.randrange(len(w_slugs))] for _ in range(len(w_slugs))]
            cr = rates(c_hit, c_records, cs)
            wr = rates(w_hit, w_records, ws)
            v = _spearman([cr[t][rung] for t in TOOLS], [wr[t][rung] for t in TOOLS])
            if v is not None:
                boots.append(v)
        boots.sort()
        lo = boots[int(0.025 * len(boots))] if boots else None
        hi = boots[int(0.975 * len(boots)) - 1] if boots else None

        per_rung[rung] = {
            "patchstack_rate": {t: round(c_rates[t][rung], 4) for t in TOOLS},
            "wordfence_rate": {t: round(w_rates[t][rung], 4) for t in TOOLS},
            "patchstack_order": c_order,
            "wordfence_order": w_order,
            "leader_agrees": c_order[0] == w_order[0],
            "leader_patchstack": c_order[0],
            "leader_wordfence": w_order[0],
            "spearman_rho": None if rho is None else round(rho, 4),
            "ci95": [None if lo is None else round(lo, 4),
                     None if hi is None else round(hi, 4)],
            "n_bootstrap_defined": len(boots),
        }

    agree = [r for r in RUNGS if per_rung[r]["leader_agrees"]]
    summary = {
        "n_rungs": len(RUNGS),
        "n_leader_agree": len(agree),
        "rungs_leader_agrees": agree,
        "rungs_leader_disagrees": [r for r in RUNGS if not per_rung[r]["leader_agrees"]],
        "coarsest_rung": RUNGS[0],
        "coarsest_leader_agrees": per_rung[RUNGS[0]]["leader_agrees"],
        "exact_line_leader_agrees": per_rung["on_exact_changed_line"]["leader_agrees"],
    }

    doc = {
        "schema_version": "endpoint-transfer-v3.1",
        "script": "eval/endpoint_transfer_v3.py",
        "question": ("does the endpoint order the four tools the same way when the ground truth "
                     "comes from an independent source"),
        "not_answered": ("whether a finding names the disclosed defect, which needs human "
                         "adjudication and is not attempted here"),
        "k": K,
        "seed": SEED,
        "bootstrap_replicates": a.reps,
        "bootstrap_unit": "plugin slug, resampled within each source independently",
        "failure_policy": ("contract: a record a tool produced nothing for, and a record whose WISP "
                           "analysis did not converge, earns nothing at any rung"),
        "sources": {
            "patchstack": {"file": "CORPUS_FINDING_POPULATION_V3.jsonl",
                           "records": c_denom, "records_with_findings": len(c_seen),
                           "plugins": len(c_slugs)},
            "wordfence": {"file": "WORDFENCE_LADDER_TRUE_V3.json",
                          "records": w_denom, "plugins": len(w_slugs)},
        },
        "reconciles_with": (
            "The Patchstack in_patched_file rate here is the contract arm, which withholds credit "
            "on a record whose WISP analysis did not converge. It is therefore lower than the "
            "0.431 the manuscript reports for the same rung on the same corpus, which is the kept "
            "arm computed over the same 1108 records without that withholding. Both are on record "
            "and neither contradicts the other. The Wordfence side reproduces the shipped external "
            "table exactly, WISP 0.54, wp-taint-scan 0.45, Semgrep 0.33, Progpilot 0.30."),
        "short_ranking_caveat": (
            "four tools give a four-item ranking, so Spearman rho is confined to a small set of "
            "values and its interval is wide by construction. The orderings and the leading tool "
            "are reported beside it because on four items those are the checkable facts."),
        "per_rung": per_rung,
        "summary": summary,
    }
    with open(DEST, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True)
        fh.write("\n")

    print(f"wrote {DEST}")
    print(f"  Patchstack {c_denom} records / {len(c_slugs)} plugins, "
          f"Wordfence {w_denom} records / {len(w_slugs)} plugins, success@{K}")
    for rung in RUNGS:
        p = per_rung[rung]
        flag = "same leader" if p["leader_agrees"] else f"LEADER FLIPS {p['leader_patchstack']} -> {p['leader_wordfence']}"
        print(f"  {rung:26} rho={p['spearman_rho']!s:>7} "
              f"[{p['ci95'][0]}, {p['ci95'][1]}]  {flag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
