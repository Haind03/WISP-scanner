#!/usr/bin/env python3
"""Per-mechanism patch-file precision under the Evaluation Contract (v3).

This is the contract-config counterpart of eval/mech_precision.py. The original read a pre-revision
pool (out/fill_20260714/train_cap.json) at 2000 bootstrap replicates. The contract changed the
patch-file labeling (deleted vulnerable files are scored at file level, not as whole-file changed
lines), so the per-mechanism precision must be recomputed against the contract finding population
rather than reused from the pre-revision pool. No scanner is re-run here: the contract WISP findings,
their mechanism markers, and their patch-file labels are all already in FINDING_POPULATION_V3.jsonl.

Mechanism is read off each finding with the engine's own markers, exactly as in the original:

  missing-guard predicate  reported class in {auth, csrf}: a state-changing sink reachable from a
                           request entry point with no adequate nonce or capability guard, carrying
                           the literal source "request" and no value flow.
  syntactic risk pattern   source == "unserialize(untrusted)": unserialize on a non-literal argument
                           not established as tainted (the pure syntactic pattern, not the
                           taint-backed second-order deserial flows, which count as proven taint).
  proven taint flow        everything else, backed by an actual source-to-sink flow.

The split reproduces the original finding counts (886 / 232 / 2734) exactly; only the precision
changes, because the ground-truth geometry it is scored against changed under the contract.

    python3 -m eval.mech_precision_v3
"""
from __future__ import annotations
import os, sys, json, random, hashlib, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
DEST = os.path.join(OUT, "MECH_PRECISION_V3.json")

GUARD_CLASSES = {"auth", "csrf"}
RISK_SOURCE = "unserialize(untrusted)"
MECHS = ["proven-taint", "missing-guard", "risk-pattern"]
SEED = 20260730          # contract bootstrap seed
B = 10000               # contract bootstrap replicates


def mech(reported_classes, source):
    if any(c in GUARD_CLASSES for c in reported_classes):
        return "missing-guard"
    if source == RISK_SOURCE:
        return "risk-pattern"
    return "proven-taint"


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    # by_slug: slug -> list of (mechanism, hit_bool)
    by_slug = {}
    # Failure policy: this is a rate over FINDINGS, so it uses the "kept" arm for the same
    # reason the geometric ladder does. Rule 3 is a record-level rule ("over the full record
    # denominator"), and a baseline that fails emits nothing and so is never charged in a
    # per-finding denominator. See eval/analyze_geometry_v3.py:geom_units_from_population.
    for line in open(POP):
        r = json.loads(line)
        if r.get("tool") != "wisp":
            continue
        m = mech(r.get("reported_classes") or [], r.get("source"))
        by_slug.setdefault(r["slug"], []).append((m, bool(r.get("in_patched_file"))))

    slugs = sorted(by_slug)

    def counts(sample_slugs):
        tp = {m: 0 for m in MECHS}
        n = {m: 0 for m in MECHS}
        for s in sample_slugs:
            for m, hit in by_slug[s]:
                n[m] += 1
                tp[m] += 1 if hit else 0
        return tp, n

    tp, n = counts(slugs)
    point = {m: (tp[m] / n[m] if n[m] else None) for m in MECHS}
    tot_tp = sum(tp.values())
    tot_n = sum(n.values())

    rnd = random.Random(SEED)
    draws = {m: [] for m in MECHS}
    for _ in range(B):
        pick = [rnd.choice(slugs) for _ in range(len(slugs))]
        btp, bn = counts(pick)
        for m in MECHS:
            if bn[m]:
                draws[m].append(btp[m] / bn[m])
    ci = {}
    for m in MECHS:
        v = sorted(draws[m])
        ci[m] = [round(v[int(0.025 * len(v))], 4), round(v[int(0.975 * len(v))], 4)] if v else None

    result = {
        "schema_version": "analysis-v3-mech-precision",
        "script": "eval/mech_precision_v3.py",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "matched-100 diagnostic, contract finding population",
        "source": "FINDING_POPULATION_V3.jsonl (wisp), contract config",
        "input_hashes": {"population": _sha256(POP)},
        "seed": SEED,
        "bootstrap_replicates": B,
        "bootstrap_unit": "plugin_slug",
        "mechanisms": {
            m: {"file_tp": tp[m], "findings": n[m],
                "file_precision": round(point[m], 4) if point[m] is not None else None,
                "ci95": ci[m]}
            for m in MECHS
        },
        "all_mechanisms": {"file_tp": tot_tp, "findings": tot_n,
                           "file_precision": round(tot_tp / tot_n, 4) if tot_n else None},
    }
    json.dump(result, open(DEST, "w"), indent=1)
    print("wrote", DEST)
    for m in MECHS:
        d = result["mechanisms"][m]
        print(f"  {m:14} prec={d['file_precision']:.4f}  {d['ci95']}  ({d['file_tp']}/{d['findings']})")
    a = result["all_mechanisms"]
    print(f"  {'ALL':14} prec={a['file_precision']:.4f}  ({a['file_tp']}/{a['findings']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
