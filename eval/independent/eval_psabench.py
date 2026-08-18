#!/usr/bin/env python3
"""Run the current WISP revision on the PSAbench A2/A3 capability cases.

This benchmark is a capability check, not a WordPress advisory-localization set.  Files whose
name contains ``safe`` are negatives; all other PHP files are positives.  The evaluator records
the per-subcategory confusion counts so the pooled result cannot hide the A3 propagation gap.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from wisp.engine import taint_engine as te


def is_negative(name):
    return "safe" in name.lower()


def subcategory(rel):
    parts = rel.split(os.sep)
    return os.sep.join(parts[:2]) if len(parts) >= 2 else parts[0]


def fires(path):
    try:
        findings, _ = te.detect_file(path, os.path.basename(path), {})
        return bool(findings)
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="datasets/php25_psabench")
    ap.add_argument("--out", default="out/out_psabench.json")
    args = ap.parse_args()

    buckets = {}
    for dim in ("A2", "A3"):
        root = os.path.join(args.dataset, dim)
        for directory, _, files in os.walk(root):
            for name in files:
                if not name.endswith(".php"):
                    continue
                path = os.path.join(directory, name)
                rel = os.path.relpath(path, args.dataset)
                bucket = buckets.setdefault(subcategory(rel), {"tp": 0, "fn": 0,
                                                                  "fp": 0, "tn": 0})
                hit = fires(path)
                if is_negative(name):
                    bucket["fp" if hit else "tn"] += 1
                else:
                    bucket["tp" if hit else "fn"] += 1

    total = {key: 0 for key in ("tp", "fn", "fp", "tn")}
    rows = []
    for name in sorted(buckets):
        counts = buckets[name]
        for key in total:
            total[key] += counts[key]
        positives = counts["tp"] + counts["fn"]
        negatives = counts["fp"] + counts["tn"]
        rows.append({
            "subcat": name,
            **counts,
            "TPR": round(counts["tp"] / positives, 3) if positives else 0,
            "TNR": round(counts["tn"] / negatives, 3) if negatives else 0,
        })

    output = {
        "benchmark": "PSAbench A2/A3",
        "dataset": os.path.abspath(args.dataset),
        "config": {"WISP_NO_GDA": os.environ.get("WISP_NO_GDA", "0")},
        "per_subcat": rows,
        "pooled": total,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as handle:
        json.dump(output, handle, indent=2)

    positives = total["tp"] + total["fn"]
    negatives = total["fp"] + total["tn"]
    print("PSAbench A2/A3: %d cases; TPR %.3f; TNR %.3f" % (
        positives + negatives,
        total["tp"] / positives if positives else 0,
        total["tn"] / negatives if negatives else 0,
    ))


if __name__ == "__main__":
    main()
