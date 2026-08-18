#!/usr/bin/env python3
"""Measure the three ladder predicates whose prose description disagreed with the scorer.

A reviewer found that the paper defines the ground truth endpoint in several places and that the
definitions do not agree with each other. Three of the disagreements are not wording slips, because
a reader who implemented the prose would compute a different value than the scorer did:

  callable at top level   The prose said the callable rung needs the finding's enclosing FUNCTION to
                          contain a changed line, and that a finding outside every function body can
                          never win it. The scorer compares lexical SCOPE, and all code outside named
                          functions shares one TOPLEVEL scope (patch_geometry.scope_of), so such a
                          finding does win the rung when the patch also changed top-level code.
  same hunk vs proximity  Two passages label the second refinement of tab:exact a hunk endpoint. The
                          table, the supplement and the scorer use proximity@5 there and keep same
                          hunk as a separate predicate. The two do not imply each other.

Prose is being corrected to match the scorer, and no measurement changes, so the numbers here are
not a new result. They exist so the corrected sentences can cite a magnitude from a JSON rather than
carry a count someone typed after reading a grep, which is the failure mode this revision exists to
remove. They are read from the shipped finding population, so this adds no scan and no re-score.

    python3 -m eval.ladder_predicate_audit_v3
"""
from __future__ import annotations
import os, sys, json, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_PREDICATE_AUDIT_V3.json")
TOPK = 3


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--population", default=POP)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.population, encoding="utf-8") if l.strip()]
    top = [r for r in rows if (r.get("rank") or 10 ** 6) <= TOPK]
    if not top:
        sys.exit(f"no rank<={TOPK} rows in {a.population}")

    callable_top = [r for r in top
                    if r.get("same_callable_as_change") and r.get("finding_at_top_level")]
    hunk_only = [r for r in top
                 if r.get("same_diff_hunk") and not r.get("within_5_changed_lines")]
    prox_only = [r for r in top
                 if r.get("within_5_changed_lines") and not r.get("same_diff_hunk")]

    res = {
        "schema_version": "ladder-predicate-audit-v3",
        "purpose": ("magnitudes for the prose corrections a reviewer's ground-truth definition "
                    "audit required; no measurement changes, the scorer is unmodified"),
        "population": os.path.relpath(a.population, SYS_ROOT),
        "top_k": TOPK,
        "n_rows": len(rows),
        "n_top_k": len(top),
        "callable_rung_won_at_top_level": {
            "n": len(callable_top),
            "predicate": ("same_callable_as_change AND finding_at_top_level, which the scorer can "
                          "only produce by matching the shared TOPLEVEL scope"),
            "prose_would_say": 0,
            "examples": sorted({f"{r['slug']}|{r['cve']}" for r in callable_top})[:10],
        },
        "same_hunk_without_proximity5": {
            "n": len(hunk_only),
            "predicate": "same_diff_hunk AND NOT within_5_changed_lines",
            "why": "a hunk span carries three context lines on each side of a group of edits",
        },
        "proximity5_without_same_hunk": {
            "n": len(prox_only),
            "predicate": "within_5_changed_lines AND NOT same_diff_hunk",
            "why": "distance to the nearest changed line can reach outside that line's hunk span",
        },
        "implication_checks": {
            "exact_line_implies_same_hunk": all(
                r.get("same_diff_hunk") for r in top if r.get("on_exact_changed_line")),
            "n_exact_line": sum(1 for r in top if r.get("on_exact_changed_line")),
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "population"}, indent=1)[:1400])
    print("wrote", a.out)


if __name__ == "__main__":
    main()
