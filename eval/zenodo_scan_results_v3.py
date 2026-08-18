#!/usr/bin/env python3
"""Regenerate the Zenodo test-set scan-results CSV from the contract re-scan.

The shipped `testset-scan-results.csv` has three problems the audit recorded. Its Progpilot
column came from the strict exit-code runner that discarded every record on which Progpilot
exited non-zero while printing valid findings. Its `*_err` columns carry one opaque token,
`timeout_or_error`, which conflates the two so the contract's failure-policy breakdown cannot
be reconstructed. And it records no provenance at all: no engine tag, no sha, no configuration,
no timeout, so the engine behind the table is not recoverable from anything on disk.

This writes the same per-record shape from the contract run, with the error kinds split, a
convergence column, and a sibling provenance JSON.

    python3 -m eval.zenodo_scan_results_v3
"""
from __future__ import annotations
import os, sys, csv, json, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

SCAN = os.path.join(SYS_ROOT, "revision-cns-v2", "progpilot_v3", "testset325_contract_v3.json")
OUT_DIR = os.path.join(SYS_ROOT, "WISP-Zenodo-Rerelease")
TOOLS = ("wisp", "semgrep", "progpilot", "wpt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan", default=SCAN)
    ap.add_argument("--out-dir", default=OUT_DIR)
    a = ap.parse_args()

    d = json.load(open(a.scan))
    det, prov = d["details"], d["provenance"]

    cols = ["slug", "cve", "class"]
    for t in TOOLS:
        cols += [f"{t}_classhit", f"{t}_pf@1", f"{t}_pf@10",
                 f"{t}_cf@1", f"{t}_cf@10", f"{t}_findings", f"{t}_status"]
    cols.append("wisp_converged")

    path = os.path.join(a.out_dir, "testset-scan-results.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in sorted(det, key=lambda x: (x["slug"], x.get("cve") or "")):
            row = [r["slug"], r.get("cve") or "", r.get("cls") or ""]
            for t in TOOLS:
                x = r.get(t) or {}
                err = x.get("err") or ""
                # "ok" / "timeout" / "non_converged" / the tool's own error token: one column,
                # one meaning per value, so the failure policy can be recomputed from the CSV.
                row += [int(bool(x.get("hit"))), x.get("pf", {}).get("1", 0),
                        x.get("pf", {}).get("10", 0), x.get("cf", {}).get("1", 0),
                        x.get("cf", {}).get("10", 0), x.get("n", 0), err or "ok"]
            st = (r.get("wisp") or {}).get("analysis_status") or {}
            row.append("" if not st else int(bool(st.get("complete"))))
            w.writerow(row)

    stamp = {
        "describes": "testset-scan-results.csv",
        "dataset": "slug-disjoint 325 (Patchstack), one record per plugin",
        "n_records": len(det),
        "tools": list(TOOLS),
        "engine": prov.get("wisp_config"),
        "git_dirty_at_scan_time": prov.get("git_dirty"),
        "timeouts_seconds": prov.get("timeouts_seconds"),
        "semgrep_rules": prov.get("semgrep_configs"),
        "tool_identities": prov.get("tool_identities"),
        "failure_rule": prov.get("failure_rule"),
        "ground_truth_module": prov.get("ground_truth_module"),
        "scorer": prov.get("scorer"),
        "columns": {
            "<tool>_classhit": "the advisory class appears in any finding for that record",
            "<tool>_pf@K": "a top-K finding lies in a file the vendor patch changed",
            "<tool>_cf@K": "as pf@K and the finding also reports the advisory class",
            "<tool>_findings": "number of findings the tool returned for that record",
            "<tool>_status": "ok | timeout | non_converged | a tool-specific error token. The "
                             "previous release collapsed these to 'timeout_or_error'.",
            "wisp_converged": "1 if the WISP analysis reached a summary fixpoint, 0 if it "
                              "stopped at a bounded approximation, blank if it did not run",
        },
        "note": "Under the failure policy above a record that timed out, errored, or did not "
                "converge scores 0 at every endpoint over the full 325-record denominator. The "
                "raw per-record columns are given so any other policy can be recomputed.",
    }
    sp = os.path.join(a.out_dir, "testset-scan-provenance.json")
    json.dump(stamp, open(sp, "w"), indent=1, sort_keys=True)

    print(f"wrote {path} ({len(det)} records, {len(cols)} columns)")
    print(f"wrote {sp}")
    import collections
    for t in TOOLS:
        c = collections.Counter((r.get(t) or {}).get("err") or "ok" for r in det)
        print(f"  {t:10} {dict(c)}")


if __name__ == "__main__":
    main()
