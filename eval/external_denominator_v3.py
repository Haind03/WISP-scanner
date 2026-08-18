#!/usr/bin/env python3
"""Reconcile the two finding denominators the external-source section reports.

A reviewer read the per-finding paragraph, which scores 3631 WISP findings, next to the table,
which reports 26.5 findings per plugin over 100 records, multiplied, and concluded the two came
from different runs. They do not. We re-scored the per-finding ladder against the contract run's
own stored findings and got output identical to the shipped ladder, rung by rung and count by
count, for all four tools.

The gap is two denominators, not two runs. The per-finding ladder measures the geometry of what
the engine emitted, so it scores every finding on every record. The table reports what the
contract credits, so it zeroes the records whose analysis did not converge and averages over the
rest. This computes both from the one scan file, so the reconciliation ships instead of being an
inference a reader has to make.

    python3 -m eval.external_denominator_v3
"""
from __future__ import annotations
import os, sys, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
SCAN = os.path.join(SYS_ROOT, "revision-cns-v2", "progpilot_v3", "wordfence100_contract_v3.json")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "EXTERNAL_DENOMINATOR_V3.json")


def main():
    d = json.load(open(SCAN, encoding="utf-8"))
    det = d["details"]
    tot = sum(r["wisp"]["n"] for r in det)
    nonconv = [r for r in det
               if (r["wisp"].get("analysis_status") or {}).get("complete") is False]
    nonconv_findings = sum(r["wisp"]["n"] for r in nonconv)
    credited_records = len(det) - len(nonconv)
    credited_findings = tot - nonconv_findings
    res = {
        "schema_version": "external-denominator-v3",
        "script": "eval/external_denominator_v3.py",
        "scan": os.path.relpath(SCAN, SYS_ROOT),
        "note": ("the per-finding ladder scores every emitted finding, the table averages what "
                 "the contract credits, and the difference is exactly the records whose analysis "
                 "did not converge"),
        "n_records": len(det),
        "findings_emitted": tot,
        "non_converged_records": len(nonconv),
        "findings_on_non_converged_records": nonconv_findings,
        "credited_records": credited_records,
        "credited_findings": credited_findings,
        "findings_per_credited_record": round(credited_findings / credited_records, 1),
    }
    json.dump(res, open(OUT, "w"), indent=1, sort_keys=True)
    print(f"wrote {OUT}")
    print(f"  {res['findings_emitted']} findings emitted over {res['n_records']} records")
    print(f"  {res['non_converged_records']} did not converge and hold "
          f"{res['findings_on_non_converged_records']} of them")
    print(f"  {res['credited_findings']} over {res['credited_records']} credited records "
          f"= {res['findings_per_credited_record']} per record")
    return 0


if __name__ == "__main__":
    sys.exit(main())
