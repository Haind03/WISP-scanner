#!/usr/bin/env python3
"""Recompute the reference census's aggregate counts from its own entries array.

The census file carries both a per-entry array and a handful of top-level counts. On 2026-08-19 the
two disagreed: `n_peer_reviewed` read 8 while nine entries carry `now_published: true`, and 8 is
exactly `n_with_doi`, which is the signature of the wrong field being carried across. Two of the
nine published works are USENIX papers, and USENIX assigns no DOI, so the two counts are not
supposed to be equal and their equality was the tell.

This recomputes every aggregate that the entries array can derive, rewrites only those, and leaves
every other field, including the provenance fields, exactly as its author wrote them. It prints
what it changed and exits non-zero if nothing needed changing, so it cannot be run as a no-op that
looks like a check.

    python3 -m eval.fix_reference_census_aggregates_v3 [--dry-run]
"""
from __future__ import annotations
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(os.path.dirname(ROOT), "revision-cns-v2", "out", "REFERENCE_CENSUS_V3.json")


def derive(entries):
    return {
        "n_references": len(entries),
        "n_preprints_before": sum(1 for e in entries if e.get("was_preprint")),
        "n_preprints_after": sum(1 for e in entries
                                 if e.get("was_preprint") and not e.get("now_published")),
        "n_with_doi": sum(1 for e in entries if e.get("doi")),
        "n_peer_reviewed": sum(1 for e in entries if e.get("now_published")),
        "n_upgraded_with_verified_doi": sum(
            1 for e in entries if e.get("was_preprint") and e.get("now_published")),
    }


def main(dry=False):
    d = json.load(open(SRC, encoding="utf-8"))
    want = derive(d["entries"])
    diff = {k: (d.get(k), v) for k, v in want.items() if d.get(k) != v}
    if not diff:
        print("reference census aggregates already agree with the entries array, nothing to do")
        return 1
    for k, (was, now) in sorted(diff.items()):
        print(f"  {k}: {was} -> {now}")
    if dry:
        print("dry run, nothing written")
        return 0
    d.update(want)
    d["aggregates_recomputed_from_entries"] = (
        "2026-08-19, by eval/fix_reference_census_aggregates_v3.py, because n_peer_reviewed "
        "disagreed with the entries array it summarises")
    with open(SRC, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    print(f"rewrote {len(diff)} aggregate(s) in {SRC}")
    return 0


if __name__ == "__main__":
    sys.exit(main(dry="--dry-run" in sys.argv))
