#!/usr/bin/env python3
"""Merge 8 localize shard JSONs into one full-1108 report (exact, from raw agg counters)."""
import json, glob
from collections import defaultdict

KS = (1, 3, 5, 10)
shards = sorted(glob.glob("out/shards/localize_*.json"))
assert shards, "no localize shard JSONs found"
A = defaultdict(int)
details = []
for sp in shards:
    d = json.load(open(sp))
    for k, v in d["agg"].items():
        A[k] += v
    details.extend(d.get("details", []))

def r(x, y): return round(x / y, 4) if y else 0
rep = {
    "n_plugins": A["n"], "total_findings": A["findings"],
    "file_precision": r(A["file_tp"], A["file_tp"] + A["file_fp"]),
    "file_recall": r(A["files_hit"], A["gt_files"]),
    "line_precision": r(A["line_tp"], A["line_tp"] + A["line_fp"]),
    "fn_precision": r(A["fn_tp"], A["fn_tp"] + A["fn_fp"]),
    "cve_localized": A["cve_localized"],
    "cve_localized_rate": r(A["cve_localized"], A["n"]),
    "cve_fn_localized": A["cve_fn_localized"],
    "cve_fn_localized_rate": r(A["cve_fn_localized"], A["n"]),
    "rank_at_k": {str(k): {"precision": r(A[f"top{k}_tp"], A[f"top{k}_n"]),
                           "cve_localized_rate": r(A[f"top{k}_cve"], A["n"])} for k in KS},
    "agg": dict(A), "details": details, "_shards": len(shards),
}
json.dump(rep, open("out/localize_full.json", "w"), indent=2)
print(f"merged {len(shards)} shards -> {A['n']} plugins")
print(f"file_precision(all) = {rep['file_precision']}   cve_localized_rate = {rep['cve_localized_rate']}")
print("exploitability-ranked precision@K:")
print(f"{'K':>4}{'file_prec@K':>14}{'cve_loc@K':>12}")
for k in KS:
    d = rep["rank_at_k"][str(k)]
    print(f"{k:>4}{d['precision']:>14}{d['cve_localized_rate']:>12}")
print(f"{'(all)':>4}{rep['file_precision']:>14}{rep['cve_localized_rate']:>12}")
