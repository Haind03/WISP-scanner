#!/usr/bin/env python3
"""Per-mechanism file-precision, the counterpart of the per-mechanism recall of tab:mech.

tab:mech splits WISP's class recall by the mechanism that earned the hit. A reviewer asked for
the same split on precision, because the three mechanisms have very different evidential weight
and a headline that mixes them hides which one carries the false positives.

Mechanism is read off each finding, using the engine's own markers rather than a fresh guess:

  missing-guard predicate  cls in {auth, csrf}. These are emitted when a state-changing sink is
                           reachable from a request entry point with no adequate nonce or
                           capability guard dominating it, so they carry the literal source
                           "request" and no source-to-sink value flow. Verified: every auth/csrf
                           finding in the pool carries exactly that source and no other.

  syntactic risk pattern   source == "unserialize(untrusted)". Section "Risk-pattern findings
                           beyond taint" defines it as unserialize/maybe_unserialize on a
                           non-literal argument without allowed_classes, flagged even when the
                           argument is NOT established as tainted. That is precisely what this
                           source marker records. Verified: it occurs only on deserial findings,
                           and only with an unserialize/maybe_unserialize sink.

  proven taint flow        everything else, i.e. a finding backed by an actual source-to-sink
                           flow, including the second-order deserial flows (get_option, meta).

Scope is the matched-100 diagnostic, the same pool the paper's other finding-level precision
endpoints use, because the full-corpus localization pass stores per-record aggregates only and
does not retain per-finding provenance. This is stated in the caption rather than implied.

    python3 -m eval.mech_precision --out out/paired_20260717/MECH_PRECISION.json
"""
from __future__ import annotations
import os, sys, json, argparse, random

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

POOL = "out/fill_20260714/train_cap.json"
RISK_SOURCE = "unserialize(untrusted)"
GUARD_CLASSES = {"auth", "csrf"}


def mech(f):
    if f["cls"] in GUARD_CLASSES:
        return "missing-guard"
    if f["source"] == RISK_SOURCE:
        return "risk-pattern"
    return "proven-taint"


def audit(records):
    """The two structural assumptions the split rests on, checked not assumed."""
    bad = []
    for r in records:
        for f in r["findings"]:
            if f["cls"] in GUARD_CLASSES and f["source"] != "request":
                bad.append(f"guard finding with source {f['source']!r}")
            if f["source"] == RISK_SOURCE and f["cls"] != "deserial":
                bad.append(f"risk-pattern finding with class {f['cls']!r}")
            if f["source"] == RISK_SOURCE and f["sink"] not in ("unserialize", "maybe_unserialize"):
                bad.append(f"risk-pattern finding with sink {f['sink']!r}")
    return bad


def precision(records, want, keys=None):
    tp = n = 0
    for r in records:
        if keys is not None and (r["slug"] + "|" + r["cve"]) not in keys:
            continue
        gt = set(r["gt"])
        for f in r["findings"]:
            if mech(f) != want:
                continue
            n += 1
            tp += 1 if f["file"] in gt else 0
    return tp, n


def boot(records, mechs, B, seed):
    """Plugin-clustered bootstrap CI on each mechanism's precision."""
    rnd = random.Random(seed)
    by_slug = {}
    for r in records:
        by_slug.setdefault(r["slug"], []).append(r["slug"] + "|" + r["cve"])
    slugs = sorted(by_slug)
    draws = {m: [] for m in mechs}
    for _ in range(B):
        pick = [by_slug[rnd.choice(slugs)] for _ in range(len(slugs))]
        keys = {}
        for grp in pick:
            for k in grp:
                keys[k] = keys.get(k, 0) + 1
        for m in mechs:
            tp = n = 0
            for r in records:
                c = keys.get(r["slug"] + "|" + r["cve"], 0)
                if not c:
                    continue
                gt = set(r["gt"])
                for f in r["findings"]:
                    if mech(f) != m:
                        continue
                    n += c
                    tp += c if f["file"] in gt else 0
            if n:
                draws[m].append(tp / n)
    out = {}
    for m in mechs:
        v = sorted(draws[m])
        out[m] = {"lo": round(v[int(0.025 * len(v))], 4),
                  "hi": round(v[int(0.975 * len(v))], 4)} if v else None
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default=POOL)
    ap.add_argument("--B", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260717)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    recs = json.load(open(a.pool))
    bad = audit(recs)
    if bad:
        print(f"ASSUMPTION VIOLATED in {len(bad)} finding(s), the split would be wrong:")
        for b in bad[:5]:
            print("   ", b)
        sys.exit(1)
    print(f"assumptions hold over {sum(len(r['findings']) for r in recs)} findings "
          f"in {len(recs)} records")

    mechs = ["proven-taint", "missing-guard", "risk-pattern"]
    rep = {"pool": a.pool, "scope": "matched-100 diagnostic", "B": a.B, "seed": a.seed,
           "n_records": len(recs), "mechanisms": {}}
    tot_tp = tot_n = 0
    for m in mechs:
        tp, n = precision(recs, m)
        tot_tp += tp
        tot_n += n
        rep["mechanisms"][m] = {"file_tp": tp, "findings": n,
                                "file_precision": round(tp / n, 4) if n else None}
    rep["all_mechanisms"] = {"file_tp": tot_tp, "findings": tot_n,
                             "file_precision": round(tot_tp / tot_n, 4)}
    rep["ci95"] = boot(recs, mechs, a.B, a.seed)
    for m in mechs:
        d = rep["mechanisms"][m]
        c = rep["ci95"][m]
        print(f"  {m:14} prec={d['file_precision']:.4f}  "
              f"[{c['lo']:.3f}, {c['hi']:.3f}]  ({d['file_tp']}/{d['findings']})")
    print(f"  {'ALL':14} prec={rep['all_mechanisms']['file_precision']:.4f}  "
          f"({tot_tp}/{tot_n})")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
