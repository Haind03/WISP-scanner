#!/usr/bin/env python3
"""Compare two granularity diagnostics with identity and rank accounting."""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
import os


PRIMARY = {
    "class": "rank_first_class",
    "patch_file": "rank_first_patch_file",
    "class_file": "rank_first_class_file",
    "class_function": "rank_first_class_function",
    "class_hunk": "rank_first_class_hunk",
}
TRACE = {
    "trace_patch_file": "rank_first_trace_patch_file",
    "trace_class_file": "rank_first_trace_class_file",
    "trace_class_function": "rank_first_trace_class_function",
    "trace_class_hunk": "rank_first_trace_class_hunk",
}
KS = (1, 3, 5, 10)


def _identity(row):
    return f"{row['slug']}|{row['cve']}"


def _rank(row, field):
    value = row.get(field)
    return math.inf if value is None else int(value)


def _metric(before, after, field):
    n = len(before)
    at_k = {}
    for k in KS:
        gained = [_identity(a) for b, a in zip(before, after)
                  if _rank(b, field) > k >= _rank(a, field)]
        lost = [_identity(a) for b, a in zip(before, after)
                if _rank(b, field) <= k < _rank(a, field)]
        before_count = sum(_rank(row, field) <= k for row in before)
        after_count = sum(_rank(row, field) <= k for row in after)
        at_k[str(k)] = {
            "before_count": before_count,
            "after_count": after_count,
            "delta_count": after_count - before_count,
            "before_rate": round(before_count / n, 4) if n else 0.0,
            "after_rate": round(after_count / n, 4) if n else 0.0,
            "delta_percentage_points": round(
                100.0 * (after_count - before_count) / n, 2) if n else 0.0,
            "gained": gained,
            "lost": lost,
        }
    improved = []
    regressed = []
    unchanged = 0
    for b, a in zip(before, after):
        old, new = _rank(b, field), _rank(a, field)
        item = {
            "identity": _identity(a),
            "before": None if math.isinf(old) else old,
            "after": None if math.isinf(new) else new,
        }
        if new < old:
            improved.append(item)
        elif new > old:
            regressed.append(item)
        else:
            unchanged += 1
    return {
        "at_k": at_k,
        "rank_improved": improved,
        "rank_regressed": regressed,
        "rank_unchanged": unchanged,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    with open(args.before, encoding="utf-8") as handle:
        before_report = json.load(handle)
    with open(args.after, encoding="utf-8") as handle:
        after_report = json.load(handle)
    before = before_report["details"]
    after = after_report["details"]

    identity_fields = (
        "slug", "cve", "cls", "vulnerable_file", "patched_file", "gt_files",
    )
    identity_mismatches = []
    for index, (old, new) in enumerate(zip(before, after)):
        changed = {field: [old.get(field), new.get(field)]
                   for field in identity_fields
                   if old.get(field) != new.get(field)}
        if changed:
            identity_mismatches.append({"index": index, "changes": changed})
    exact_identity = (
        len(before) == len(after)
        and not identity_mismatches
        and [_identity(row) for row in before] == [_identity(row) for row in after]
    )
    if not exact_identity:
        raise SystemExit("reports do not describe the same ordered evaluation set")

    transitions = Counter(
        f"{old.get('bucket')} -> {new.get('bucket')}"
        for old, new in zip(before, after))
    finding_deltas = [new.get("findings", 0) - old.get("findings", 0)
                      for old, new in zip(before, after)]
    comparison = {
        "schema_version": 1,
        "before": os.path.abspath(args.before),
        "after": os.path.abspath(args.after),
        "identity": {
            "exact_ordered_match": True,
            "n": len(before),
            "sample_sha256_before": before_report.get("source_hashes", {}).get("sample"),
            "sample_sha256_after": after_report.get("source_hashes", {}).get("sample"),
            "window_before": before_report.get("summary", {}).get("window"),
            "window_after": after_report.get("summary", {}).get("window"),
        },
        "config": {
            "before": before_report.get("config", {}),
            "after": after_report.get("config", {}),
        },
        "primary_metrics": {
            name: _metric(before, after, field)
            for name, field in PRIMARY.items()
        },
        "trace_aware_after_only": {
            name: {
                str(k): sum(_rank(row, field) <= k for row in after)
                for k in KS
            }
            for name, field in TRACE.items()
        },
        "buckets": {
            "before": dict(Counter(row.get("bucket") for row in before)),
            "after": dict(Counter(row.get("bucket") for row in after)),
            "transitions": dict(sorted(transitions.items())),
        },
        "findings": {
            "before_total": sum(row.get("findings", 0) for row in before),
            "after_total": sum(row.get("findings", 0) for row in after),
            "before_mean": before_report.get("summary", {}).get("mean_findings"),
            "after_mean": after_report.get("summary", {}).get("mean_findings"),
            "delta_total": sum(finding_deltas),
            "plugins_increased": sum(delta > 0 for delta in finding_deltas),
            "plugins_decreased": sum(delta < 0 for delta in finding_deltas),
            "plugins_unchanged": sum(delta == 0 for delta in finding_deltas),
            "largest_increases": sorted(
                ({"identity": _identity(row), "delta": delta}
                 for row, delta in zip(after, finding_deltas) if delta > 0),
                key=lambda item: item["delta"], reverse=True)[:10],
            "largest_decreases": sorted(
                ({"identity": _identity(row), "delta": delta}
                 for row, delta in zip(after, finding_deltas) if delta < 0),
                key=lambda item: item["delta"])[:10],
        },
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(comparison, handle, indent=2)
        handle.write("\n")
    print(json.dumps({
        "n": len(before),
        "buckets": comparison["buckets"],
        "findings": comparison["findings"],
    }, indent=2))


if __name__ == "__main__":
    main()
