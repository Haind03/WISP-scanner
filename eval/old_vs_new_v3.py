#!/usr/bin/env python3
"""Regenerate OLD-VS-NEW-RESULTS.csv's `new_value` column from the canonical result JSONs.

The file answers one question for a reviewer: what did the previous submission claim, and what does
this one claim instead. It was maintained by hand, and by 2026-08-14 its `new_value` column held
wisp-scanner-v1.2 numbers that the paper had left behind. It said WISP's top rung was 0.536 where
the paper says \\WispInPatchedFile, its bottom rung 0.054 where the paper says
\\WispExactChangedLine, and full-corpus non-convergence 272 of 1108 where the shipped census says 8.
A reviewer read those and concluded, reasonably, that the revision's provenance could not be
trusted.

The `old_value` column is history and stays as written: it is what the previous submission said, and
no result file can regenerate it. The `new_value` column is a claim about the current run, so it is
derived here from the same JSONs the macros use, by the same pointer syntax the CSV already carries
in `evidence_json`.

Rows whose evidence is not a machine-resolvable pointer (a deleted study, a title change, a prose
reframing) keep their text and are listed as manual, so the set that cannot be derived is visible
rather than indistinguishable from the set that was not derived.

    python3 -m eval.old_vs_new_v3            # rewrite the CSV in bundle-src
    python3 -m eval.old_vs_new_v3 --check    # exit 2 if any derived cell is stale
"""
from __future__ import annotations
import os, sys, csv, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CSV = os.path.join(SYS_ROOT, "revision-cns-v2", "bundle-src", "OLD-VS-NEW-RESULTS.csv")
TS = os.path.join(SYS_ROOT, "100-CVE-testset", "results")

# claim -> (json file, dotted pointer, formatter). Only rows whose current value is a measurement.
# Everything else is prose about what changed and is left alone.
DERIVED = {
    "WISP top rung (patched file)":
        ("GEOMETRIC_LADDER_V3.json", "per_tool.wisp.in_patched_file", "rate"),
    "WISP middle rung":
        ("GEOMETRIC_LADDER_V3.json", "per_tool.wisp.same_callable_as_change", "rate_same_callable"),
    "WISP bottom geometric rung":
        ("GEOMETRIC_LADDER_V3.json", "per_tool.wisp.on_exact_changed_line", "rate_exact"),
    "WISP file-to-bottom collapse":
        ("GEOMETRIC_LADDER_V3.json", None, "collapse"),
    "WISP full-corpus completeness":
        ("CONVERGENCE_DECOMPOSITION_V3.json", None, "nonconv"),
    "Summary fixpoint":
        ("CONVERGENCE_DECOMPOSITION_V3.json", None, "fixpoint"),
    "External Wordfence exact-line":
        (os.path.join(TS, "wordfence100_ladder_true_v3.json"), None, "wf_exact"),
    "WISP patch-file@1 fair matrix":
        ("BASELINE_MATCHED100_V3.json", None, "matrix_pf1"),
    "Exact-line paired separation":
        ("PAIRED_FAMILY_V3.json", None, "exact_sep"),
    "Full-corpus class emission":
        ("FULLCORPUS_FAILURE_AS_MISS_V3.json", None, "corpus_emission"),
}


def _load(name: str) -> dict:
    p = name if os.path.isabs(name) else os.path.join(OUT, name)
    if not os.path.isfile(p):
        raise SystemExit(f"missing canonical input: {os.path.relpath(p, SYS_ROOT)}")
    return json.load(open(p, encoding="utf-8"))


def _dig(d, dotted):
    for k in dotted.split("."):
        d = d[k]
    return d


def _fmt(kind: str, src: str, ptr) -> str:
    d = _load(src)
    def _rate(pointer):
        v = _dig(d, pointer)
        return v["rate"] if isinstance(v, dict) else (v[0] if isinstance(v, list) else v)
    if kind == "rate":
        return f"{_rate(ptr):.3f}"
    if kind == "rate_same_callable":
        return f"{_rate(ptr):.3f} (same callable)"
    if kind == "rate_exact":
        return f"{_rate(ptr):.3f} (exact changed line; contract deleted-file fix)"
    if kind == "collapse":
        pe = d["primary_effect"]["wisp"]["drop_to_exact_changed_line"]
        ct = d["conditional_transition"]["wisp"]["P(on_exact_changed_line|patched_file)"]
        lo, hi = pe["ci95"][:2]
        return (f"risk difference {pe['diff']:.3f} CI[{lo:.3f} {hi:.3f}] + conditional "
                f"P(exact|file)={ct['rate']:.2f}")
    if kind == "nonconv":
        c = d.get("corpus", {}).get("v13", {})
        n, tot = c.get("non_converged"), c.get("n")
        return (f"no per-plugin timeout; {n} of {tot} ({c.get('non_converged_rate'):.4f}) do not "
                f"reach a summary fixpoint on the shipped engine")
    if kind == "fixpoint":
        v13 = d.get("corpus", {}).get("v13", {})
        v12 = d.get("corpus", {}).get("v12", {})
        return (f"bounded iterative stabilization; non-convergence surfaced AND enforced as "
                f"failure-as-miss ({v13.get('non_converged')} of {v13.get('n')} on the shipped "
                f"engine, against {v12.get('non_converged')} of {v12.get('n')} on the previous one)")
    if kind == "matrix_pf1":
        pb = d["per_budget"]
        parts = " / ".join(f"{pb[b]['wisp_pf1']:.2f}" for b in ("25", "60", "300") if b in pb)
        return f"{parts} at 25 / 60 / 300 s on the shipped engine, under the contract"
    if kind == "exact_sep":
        surv = [(v["endpoint"], v["baseline"]) for v in d["comparisons"].values()
                if v.get("survives_holm") and str(v["endpoint"]).startswith("exact")]
        if not surv:
            return ("no comparison at exact-changed-line granularity survives Holm correction "
                    "against any baseline")
        names = {"wpt": "wp-taint-scan", "progpilot": "Progpilot", "semgrep": "Semgrep"}
        listed = ", ".join(f"{e} against {names.get(b, b)}" for e, b in sorted(surv))
        return (f"one comparison survives Holm correction at exact-changed-line granularity "
                f"({listed}); against the two independent baselines none does")
    if kind == "corpus_emission":
        w = d["arms"]["full_1108"]["contract"]["wisp"]
        return (f"{w['emission']:.4f} over {w['n']} records under the contract failure policy "
                f"(a non-converged analysis is a miss)")
    if kind == "wf_exact":
        w = d["ladder"]["wisp"]["on_exact_changed_line"]
        return f"{w[0]:.4f} per finding over {w[2]} findings on the external Wordfence set"
    raise SystemExit(f"unknown formatter {kind}")


def main() -> int:
    check = "--check" in sys.argv
    rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
    fields = list(rows[0].keys())
    stale, derived, manual = [], 0, 0
    for r in rows:
        spec = DERIVED.get(r["claim"])
        if not spec:
            manual += 1
            continue
        src, ptr, kind = spec
        want = _fmt(kind, src, ptr)
        derived += 1
        if r["new_value"] != want:
            stale.append(f"{r['claim']}: had {r['new_value']!r}, canonical is {want!r}")
            if not check:
                r["new_value"] = want
    if stale and not check:
        with open(CSV, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
    print(f"OLD-VS-NEW: {derived} row(s) derived from canonical JSON, {manual} left as prose")
    for s in stale:
        print(("  STALE " if check else "  fixed ") + s)
    if stale:
        print("  (the old_value column is history and is never rewritten)")
    return 2 if (stale and check) else 0


if __name__ == "__main__":
    sys.exit(main())
