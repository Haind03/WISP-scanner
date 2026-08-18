#!/usr/bin/env python3
"""One-pass diagnostic for the Patchstack granularity ladder.

Scans each selected vulnerable archive once, then separates misses caused by
class emission, file localization, ranking, function correspondence, and hunk
correspondence.  Archive/tool failures stay in the denominator.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from multiprocessing import Pool
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from eval.datasets import patchstack as patchstack_dataset
from eval.datasets.patchstack import load_rows
from eval import localize as localize_module
from eval.localize import _changed_lines, _enclosing_fn, _fn_ranges, _php_map, _unzip
from wisp.engine import l1_ingest
from wisp.engine import taint_ast as ta
from wisp.engine import taint_engine as te


def _keyof(path):
    parts = (path or "").replace("\\", "/").split("/")
    parts = [part for part in parts if part and part != "."]
    return "/".join(parts[1:]) if len(parts) > 1 else (parts[0] if parts else "")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ground_truth(vroot, proot):
    vmap, pmap = _php_map(vroot), _php_map(proot)
    gt = {}
    for rel, vulnerable_file in vmap.items():
        if rel not in pmap:
            continue
        changed = _changed_lines(vulnerable_file, pmap[rel])
        if changed:
            gt[rel.replace(os.sep, "/")] = (changed, _fn_ranges(vulnerable_file))
    return gt


def _rank_metrics(findings, advisory_class, gt, window):
    result = {
        "rank_first_class": None,
        "rank_first_patch_file": None,
        "rank_first_class_file": None,
        "rank_first_class_function": None,
        "rank_first_class_hunk": None,
        # Trace-aware counterparts accept either the caller/callsite location or
        # the separately retained ultimate sink endpoint.
        "rank_first_trace_patch_file": None,
        "rank_first_trace_class_file": None,
        "rank_first_trace_class_function": None,
        "rank_first_trace_class_hunk": None,
    }
    for rank, finding in enumerate(findings, 1):
        finding_class = finding.vuln_class
        finding_file = _keyof(finding.file)
        line = int(getattr(finding, "line", 0) or 0)
        locations = [(finding_file, line)]
        sink_file = _keyof(getattr(finding, "sink_file", ""))
        sink_line = int(getattr(finding, "sink_line", 0) or 0)
        if sink_file and (sink_file, sink_line) not in locations:
            locations.append((sink_file, sink_line))
        if finding_class == advisory_class and result["rank_first_class"] is None:
            result["rank_first_class"] = rank
        trace_gt = [(path, loc_line, gt[path]) for path, loc_line in locations
                    if path in gt]
        if trace_gt and result["rank_first_trace_patch_file"] is None:
            result["rank_first_trace_patch_file"] = rank
        if finding_class == advisory_class and trace_gt:
            if result["rank_first_trace_class_file"] is None:
                result["rank_first_trace_class_file"] = rank
            if (result["rank_first_trace_class_hunk"] is None
                    and any(loc_line and any(abs(loc_line - changed_line) <= window
                                             for changed_line in changed)
                            for _path, loc_line, (changed, _ranges) in trace_gt)):
                result["rank_first_trace_class_hunk"] = rank
            if result["rank_first_trace_class_function"] is None:
                for _path, loc_line, (changed, ranges) in trace_gt:
                    enclosing = _enclosing_fn(loc_line, ranges) if loc_line else None
                    if (enclosing and any(enclosing[0] <= changed_line <= enclosing[1]
                                          for changed_line in changed)):
                        result["rank_first_trace_class_function"] = rank
                        break
        if finding_file not in gt:
            continue
        if result["rank_first_patch_file"] is None:
            result["rank_first_patch_file"] = rank
        if finding_class != advisory_class:
            continue
        if result["rank_first_class_file"] is None:
            result["rank_first_class_file"] = rank
        changed, ranges = gt[finding_file]
        if (result["rank_first_class_hunk"] is None and line
                and any(abs(line - changed_line) <= window for changed_line in changed)):
            result["rank_first_class_hunk"] = rank
        enclosing = _enclosing_fn(line, ranges) if line else None
        if (result["rank_first_class_function"] is None and enclosing
                and any(enclosing[0] <= changed_line <= enclosing[1]
                        for changed_line in changed)):
            result["rank_first_class_function"] = rank
    return result


def _one(task):
    index, row, window = task
    detail = {
        "index": index,
        "slug": row["slug"],
        "cve": row["cve"],
        "cls": row["cls"],
        "vulnerable_file": row.get("vuln_file", ""),
        "patched_file": row.get("patched_file", ""),
        "error": "",
        "findings": 0,
        "gt_files": 0,
    }
    vzip, pzip = row["vuln_zip"], row["patched_zip"]
    if not os.path.isfile(vzip) or not os.path.isfile(pzip):
        detail["error"] = "missing_archive"
        return detail

    vroot, proot = _unzip(vzip), _unzip(pzip)
    if not vroot or not proot:
        detail["error"] = "archive_extract_error"
        if vroot:
            shutil.rmtree(vroot, ignore_errors=True)
        if proot:
            shutil.rmtree(proot, ignore_errors=True)
        return detail

    plugin = None
    try:
        gt = _ground_truth(vroot, proot)
        detail["gt_files"] = len(gt)
        plugin = l1_ingest.load_plugin(vzip)
        if not (plugin and plugin.php_files):
            detail["error"] = "plugin_load_error"
            return detail
        try:
            findings = te.detect(plugin)
        except Exception as exc:  # failure-as-miss, but retain the cause
            detail["error"] = f"engine_error:{type(exc).__name__}"
            return detail
        detail["findings"] = len(findings)
        detail.update(_rank_metrics(findings, row["cls"], gt, window))
        if detail["rank_first_class"] is None:
            detail["bucket"] = "no_class_emission"
        elif detail["rank_first_class_file"] is None:
            detail["bucket"] = "class_only_wrong_file"
        elif detail["rank_first_class_file"] > 1:
            detail["bucket"] = "class_file_ranked_below_1"
        else:
            detail["bucket"] = "class_file_at_1"
        return detail
    finally:
        if plugin:
            plugin.cleanup()
        shutil.rmtree(vroot, ignore_errors=True)
        shutil.rmtree(proot, ignore_errors=True)


def _aggregate(details, window):
    n = len(details)
    ranks = (
        "rank_first_class", "rank_first_patch_file", "rank_first_class_file",
        "rank_first_class_function", "rank_first_class_hunk",
        "rank_first_trace_patch_file", "rank_first_trace_class_file",
        "rank_first_trace_class_function", "rank_first_trace_class_hunk",
    )
    at_k = {}
    for name in ranks:
        at_k[name.removeprefix("rank_first_")] = {
            str(k): round(sum(1 for row in details
                              if row.get(name) is not None and row[name] <= k) / n, 4)
            if n else 0.0
            for k in (1, 3, 5, 10)
        }
    return {
        "n": n,
        "errors": Counter(row.get("error") or "ok" for row in details),
        "buckets": Counter(row.get("bucket") or "tool_or_archive_error" for row in details),
        "at_k": at_k,
        "window": window,
        "mean_findings": round(sum(row["findings"] for row in details) / n, 2) if n else 0.0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--window", type=int, default=5)
    args = parser.parse_args()

    wanted = {line.strip() for line in open(args.sample, encoding="utf-8") if line.strip()}
    rows = [row for row in load_rows()
            if f"{row['slug']}|{row['cve']}" in wanted]
    if len(rows) != len(wanted):
        loaded = {f"{row['slug']}|{row['cve']}" for row in rows}
        raise SystemExit(f"sample has {len(wanted) - len(loaded)} unmatched identities")

    tasks = [(index, row, args.window) for index, row in enumerate(rows)]
    details = []
    if args.workers <= 1:
        iterator = map(_one, tasks)
        for detail in iterator:
            details.append(detail)
            print(f"[{len(details):3}/{len(tasks)}] {detail['slug'][:32]:32} "
                  f"{detail.get('bucket') or detail['error']}", flush=True)
    else:
        with Pool(args.workers) as pool:
            for detail in pool.imap_unordered(_one, tasks, chunksize=1):
                details.append(detail)
                print(f"[{len(details):3}/{len(tasks)}] {detail['slug'][:32]:32} "
                      f"{detail.get('bucket') or detail['error']}", flush=True)
    details.sort(key=lambda row: row["index"])

    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        commit = ""
    report = {
        "schema_version": 1,
        "engine_commit": commit,
        "source_hashes": {
            "taint_engine.py": _sha256(te.__file__),
            "taint_ast.py": _sha256(ta.__file__),
            "diagnose_granularity.py": _sha256(os.path.abspath(__file__)),
            "patchstack.py": _sha256(patchstack_dataset.__file__),
            "localize.py": _sha256(localize_module.__file__),
            "sample": _sha256(args.sample),
        },
        "config": {
            "WISP_NO_GDA": os.environ.get("WISP_NO_GDA", ""),
            "WISP_HANDLER_EP": os.environ.get("WISP_HANDLER_EP", ""),
            "WISP_QUALIFIED_SUMMARIES": os.environ.get("WISP_QUALIFIED_SUMMARIES", ""),
            "WISP_SANI_CLASS": os.environ.get("WISP_SANI_CLASS", ""),
            "WISP_PARAM_PROP": os.environ.get("WISP_PARAM_PROP", ""),
            "effective_qualified_summaries": bool(te._QUALIFIED),
            "effective_param_property_effects": te._param_prop_enabled(),
            "workers": args.workers,
            "window": args.window,
        },
        "summary": _aggregate(details, args.window),
        "details": details,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=dict)
        handle.write("\n")
    print(json.dumps(report["summary"], indent=2, default=dict))


if __name__ == "__main__":
    main()
