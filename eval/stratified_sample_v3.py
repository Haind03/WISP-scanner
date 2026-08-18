#!/usr/bin/env python3
"""Draw a stratified 100-record sample and re-score the headline endpoints on it.

The matched sample the paper reports is drawn deterministically on `slug|cve` with seed 42 and is not
stratified. A reviewer objected that an unstratified draw can over- or under-represent a
vulnerability class, a plugin size or a patch shape, and that the headline conclusions are therefore
resting on one arbitrary hundred records.

This answers that without re-running a single scanner. All four full-corpus contract scans are on
disk, so a second sample can be drawn from the same 1108 records and scored by the same code. The
strata are the three properties the objection names:

  * advisory class, proportional to the corpus
  * patch breadth, the number of PHP files the vendor diff touched, in three bands
  * patch shape, whether the record offers any exact-line target at all

Sampling is proportional within each stratum and deterministic given the seed, and every plugin slug
contributes at most one record so the sample stays clustered the same way the reported one is.

The output is a comparison, not a replacement. The reported sample stays the reported sample; this
says whether the same conclusions survive a draw that controls for what the objection names.

    python3 -m eval.stratified_sample_v3            # writes STRATIFIED_SAMPLE_V3.json
    python3 -m eval.stratified_sample_v3 --seed 7   # a different draw
"""
from __future__ import annotations
import os, sys, json, random, argparse
from collections import defaultdict, Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
TOOLS = ("wisp", "semgrep", "progpilot", "wpt")
KS = (1, 3, 5, 10)


def _scan(tool):
    p = os.path.join(OUT, "CORPUS1108_%s_CONTRACT_V3.json" % tool.upper())
    if not os.path.isfile(p):
        raise SystemExit("missing corpus scan: " + os.path.relpath(p, SYS_ROOT))
    d = json.load(open(p, encoding="utf-8"))
    return {r["slug"] + "|" + r["cve"]: r for r in (d.get("details") or d.get("records"))}


def _breadth_band(n):
    return "1 file" if n <= 1 else ("2-3 files" if n <= 3 else "4+ files")


def _strata(rows):
    """(class, patch-breadth band, whether the patch touched any PHP file) for each record."""
    st = {}
    for k, r in rows.items():
        gt = int(r.get("gt_files") or 0)
        st[k] = (r.get("cls") or "other", _breadth_band(gt), gt > 0)
    return st


def _answered(rec, tool):
    """The contract's failure rule, at the record level: an error is a miss, and for WISP a
    non-converged analysis is a miss as well (contract v1 s4 rule 3)."""
    t = rec.get(tool) or {}
    if t.get("err"):
        return False
    if tool == "wisp":
        stt = t.get("analysis_status") or {}
        if stt and not stt.get("complete", True):
            return False
    return True


def score(keys, scans):
    """Read the per-record endpoint fields the scan already carries.

    These are the same `pf`/`cf` indicators every other analysis in this paper reads, so the
    stratified draw is scored by the same definition rather than by a second implementation of it.
    A record that the contract counts as a miss contributes zero, never a dropped denominator.
    """
    out = {}
    for tool in TOOLS:
        rows, cell = scans[tool], {}
        for name in ("pf", "cf"):
            for k in KS:
                hit = 0
                for key in keys:
                    r = rows.get(key)
                    if r is None or not _answered(r, tool):
                        continue
                    hit += int(((r.get(tool) or {}).get(name) or {}).get(str(k)) or 0)
                cell["%s@%d" % (name, k)] = round(hit / len(keys), 4)
        emis = sum(1 for key in keys
                   if (r := rows.get(key)) is not None and _answered(r, tool)
                   and int((r.get(tool) or {}).get("hit") or 0))
        cell["class_emission"] = round(emis / len(keys), 4)
        cell["answered"] = round(sum(1 for key in keys if (r := rows.get(key)) is not None
                                     and _answered(r, tool)) / len(keys), 4)
        out[tool] = cell
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n", type=int, default=100)
    a = ap.parse_args()

    scans = {t: _scan(t) for t in TOOLS}
    base = scans["wisp"]
    st = _strata(base)

    # one record per slug, so the sample clusters like the reported one
    by_slug = defaultdict(list)
    for k in sorted(base):
        by_slug[k.split("|")[0]].append(k)
    rng = random.Random(a.seed)
    pool = [rng.choice(v) for _, v in sorted(by_slug.items())]

    buckets = defaultdict(list)
    for k in pool:
        buckets[st[k]].append(k)
    total = len(pool)
    # proportional allocation, largest-remainder so the parts sum to n
    quota = {s: a.n * len(v) / total for s, v in buckets.items()}
    take = {s: int(q) for s, q in quota.items()}
    for s in sorted(quota, key=lambda s: -(quota[s] - take[s]))[:a.n - sum(take.values())]:
        take[s] += 1
    keys = []
    for s in sorted(buckets):
        v = sorted(buckets[s])
        rng.shuffle(v)
        keys += v[:take[s]]
    keys = sorted(keys)

    res = score(keys, scans)
    corpus = score(sorted(base), scans)

    def _dist(ks):
        c = Counter(st[k][0] for k in ks)
        return {k: round(v / len(ks), 4) for k, v in sorted(c.items())}

    doc = {
        "schema_version": "stratified-sample-v3",
        "why": ("the reported matched sample is an unstratified seed-42 draw; this is a second "
                "draw stratified on advisory class, patch breadth and whether the record offers "
                "any exact-line target, scored by the same code on the same corpus scans"),
        "seed": a.seed, "n": len(keys),
        "strata": ["advisory class", "patch breadth (1 / 2-3 / 4+ changed PHP files)",
                   "has an exact-line target"],
        "allocation": "proportional to the corpus, largest remainder, one record per plugin slug",
        "class_distribution": {"stratified_sample": _dist(keys), "full_corpus": _dist(sorted(base))},
        "endpoints": {"stratified_sample": res, "full_corpus_1108": corpus},
        "record_keys": keys,
        "note": ("This does not replace the reported sample. It answers whether the reported "
                 "conclusions survive a draw that controls for the properties the objection names."),
    }
    p = os.path.join(OUT, "STRATIFIED_SAMPLE_V3.json")
    json.dump(doc, open(p, "w"), indent=1, sort_keys=True)
    print("wrote", os.path.relpath(p, SYS_ROOT), f"({len(keys)} records, seed {a.seed})")
    print(f"{'tool':12} {'pf@1':>7} {'cf@1':>7} {'pf@10':>7} {'class':>7}   (stratified | corpus)")
    for t in TOOLS:
        s, c = res[t], corpus[t]
        print(f"  {t:10} {s['pf@1']:7.3f} {s['cf@1']:7.3f} {s['pf@10']:7.3f} {s['class_emission']:7.3f}"
              f"   | {c['pf@1']:.3f} {c['cf@1']:.3f} {c['pf@10']:.3f} {c['class_emission']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
