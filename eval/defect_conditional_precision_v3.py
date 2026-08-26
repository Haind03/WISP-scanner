#!/usr/bin/env python3
"""Conditional precision of the human blind judgment, given each geometric rung.

WHY THIS EXISTS. Section "A pilot" argued that the exact-changed-line rung is the closest proxy to
human judgment by setting one marginal rate beside another, 0.06 against 0.08. That is a weak
argument and close to coincidence. The labels already on disk answer the question directly: given
that a finding lands on an exact changed line, how often does a blind judge call it the vendor's
defect, and how does that compare with the same conditional given only a patched-file hit.

Three rates per annotator, all over the same 200 labelled findings:
    P(same defect | on an exact changed line)
    P(same defect | in a patched file)
    P(same defect | NOT in a patched file)

The 200 findings sit in 88 records over 86 plugin slugs, so they are not independent and every
interval here is a slug-clustered bootstrap. It reuses eval.analyze_v3.boot_rate at the shared
SEED rather than defining a second bootstrap, because two bootstraps in one paper is two seeds and
two conventions to keep in step.

The exact-line cell rests on 12 findings. That is small, it is reported with its raw count beside
the rate everywhere it is printed, and the paper labels the whole result exploratory.
"""
from __future__ import annotations
import json, os, sys, csv, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval import analyze_v3 as A

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LABELS = os.path.join(ROOT, "defect-study", "defect_study_labels.csv")
OUT = os.path.join(os.path.dirname(ROOT), "revision-cns-v2", "out",
                   "DEFECT_CONDITIONAL_PRECISION_V3.json")
REPS = 10000


def _t(v) -> bool:
    return str(v).strip().upper() in ("TRUE", "1", "YES", "T")


def main() -> int:
    rows = list(csv.DictReader(open(LABELS, encoding="utf-8-sig")))
    if not rows:
        print("no labels on disk"); return 2

    units = [{"slug": r["slug"], "row": r} for r in rows]
    strata = {
        "on_exact_changed_line": lambda u: _t(u["row"]["on_exact_changed_line"]),
        "in_patched_file":       lambda u: _t(u["row"]["in_patched_file"]),
        "not_in_patched_file":   lambda u: not _t(u["row"]["in_patched_file"]),
    }

    out = {
        "schema_version": 1,
        "script": "eval/defect_conditional_precision_v3.py",
        "source": "defect-study/defect_study_labels.csv",
        "n_findings": len(rows),
        "n_records": len({r["record_uid"] for r in rows}),
        "n_slugs": len({r["slug"] for r in rows}),
        "bootstrap": {"seed": A.SEED, "replicates": REPS, "cluster": "plugin slug"},
        "generated_utc": datetime.datetime.now(datetime.timezone.utc)
                         .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "annotators": {},
    }

    for ann in ("A", "B"):
        col = f"{ann}_root_cause_relation"
        same = lambda u, c=col: u["row"][c].strip().upper() == "SAME_DEFECT"
        block = {}
        for name, keep in strata.items():
            sub = [u for u in units if keep(u)]
            block[name] = A.boot_rate(sub, same, REPS)
        # the ratio the paper quotes, computed from raw counts rather than from rounded rates
        e, f = block["on_exact_changed_line"], block["in_patched_file"]
        block["exact_over_file_ratio"] = (
            round((e["count"] / e["n"]) / (f["count"] / f["n"]), 2)
            if e["n"] and f["n"] and f["count"] else None)
        out["annotators"][ann] = block

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)

    for ann, b in out["annotators"].items():
        print(f"annotator {ann}:")
        for k in ("on_exact_changed_line", "in_patched_file", "not_in_patched_file"):
            v = b[k]
            print(f"   {k:24s} {v['count']:3d}/{v['n']:3d} = {v['rate']:.3f}  "
                  f"CI[{v['ci95'][0]:.3f}, {v['ci95'][1]:.3f}]")
        print(f"   exact/file ratio          {b['exact_over_file_ratio']}")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
