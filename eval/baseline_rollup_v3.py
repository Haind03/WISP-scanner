#!/usr/bin/env python3
"""Roll up a fair baseline matrix into its rollup JSON, on either dataset.

Reads the per-cell detail files under baseline_v3/cells/ and the matrix aggregate, then produces a
tool x budget table for every metric, a per-budget ranking on the primary metric (patch-file
success@1), and slug-cluster bootstrap confidence intervals: one CI per cell on pf@1, and a paired
WISP-minus-baseline difference CI at each budget. The bootstrap unit is the plugin slug (resample
slugs with replacement, carry every record for the slug), matching the revision-v2 dependence model.
Provenance is copied from the matrix at run time, never patched afterward.

    python3 -m eval.baseline_rollup_v3                                     # matched-100, unchanged
    python3 -m eval.baseline_rollup_v3 --dataset full-1108 --tag full1108  # the corpus matrix

Every cell is audited for host failure before it is read. A cell is a wall-clock measurement, so a
process the kernel killed for memory is not a capability observation, and a rollup that averages one
in reports a tool weaker than it is.
"""
from __future__ import annotations
import os, sys, json, glob, random, time, hashlib, argparse, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CELL_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "cells")
TOOLS = ["wisp", "semgrep", "progpilot", "wpt"]
SEED = 20260730
REPS = 10000
METRICS = ["coverage", "class_emission_failure_as_miss",
           "patch_file_success_at_1", "patch_file_success_at_3",
           "patch_file_success_at_5", "patch_file_success_at_10"]

# One dataset per rollup, and the output name is derived rather than chosen, so a corpus rollup can
# never land on the matched-sample file.
PROFILES = {
    "matched-100": {"tag": "", "matrix": "BASELINE_MATRIX_V3.json",
                    "out": "BASELINE_MATCHED100_V3.json",
                    "schema": "baseline-matched100-v3", "kind": "matched100_rollup"},
    "full-1108": {"tag": "full1108", "matrix": "BASELINE_MATRIX_V3_full1108.json",
                  "out": "BASELINE_FULL1108_V3.json",
                  "schema": "baseline-full1108-v3", "kind": "full1108_rollup"},
}

# Thresholds measured against the eleven clean corpus cells, where SIGKILL never appears and the
# worst archive failure is one record in 1108. The contaminated wpt@300 cell carried 37 and 38.
# `host_memory_floor` is the harness catching the same event before the kernel does, and it is a
# host failure for the same reason: the scan was stopped by what else was running, not by the tool.
# `mem_cap_exceeded` is deliberately NOT here, because that is the declared budget doing its job and
# is scored as a miss exactly like a timeout.
HOST_FAILURE_ERRS = ("nonzero_exit:-9", "nonzero_exit:-15", "host_memory_floor")
ARCHIVE_ERR_FRACTION = 0.01


def _cell_path(dataset, tag, tool, budget):
    return os.path.join(CELL_DIR, f"{dataset}__{tool}@{budget}{('__' + tag) if tag else ''}.json")


def audit_cell(cell_json, dataset, tag, tool, budget):
    """Refuse a cell whose failures came from the host rather than from the tool.

    A signal-9 exit is the out-of-memory killer, and a burst of archive extraction errors is the
    same event seen from the other side. Both depress coverage and patch-file rates exactly the way
    a weaker engine would, so they have to stop the rollup rather than be averaged into it."""
    det = cell_json["details"]
    errs = collections.Counter(d["err"] for d in det if d["err"])
    n = len(det)
    killed = sum(v for k, v in errs.items() if k in HOST_FAILURE_ERRS)
    archive = errs.get("archive_extract_error", 0)
    problems = []
    if errs.get("host_memory_floor"):
        problems.append(f"{errs['host_memory_floor']} scan(s) stopped because the host ran out of "
                        f"memory, which can include scans that did nothing wrong")
    signalled = killed - errs.get("host_memory_floor", 0)
    if signalled:
        problems.append(f"{signalled} record(s) killed by signal (out of memory)")
    if archive > ARCHIVE_ERR_FRACTION * n:
        problems.append(f"{archive} archive extraction errors, over {ARCHIVE_ERR_FRACTION:.0%} of {n}")
    prov = cell_json.get("provenance") or {}
    return {"cell": f"{tool}@{budget}", "n_records": n, "err_split": dict(errs.most_common()),
            "host_failures": killed, "archive_errors": archive,
            "clean": not problems, "problems": problems,
            # From the cell, never from the matrix. A matrix file keeps the provenance of the run
            # that created it, so after cells are re-measured under a changed protocol its
            # run-level record describes a protocol none of its cells were measured under.
            "mem_cap_mb": prov.get("mem_cap_mb"), "workers": prov.get("workers"),
            "mem_capped": sum(1 for d in det if d.get("err") == "mem_cap_exceeded"),
            "peak_rss_mb_max": max([d.get("peak_rss_mb") or 0 for d in det], default=0)}


def make_cell_reader(dataset, tag, audits, strict):
    def _cell_details(tool, budget):
        f = _cell_path(dataset, tag, tool, budget)
        c = json.load(open(f))
        key = f"{tool}@{budget}"
        if key not in audits:
            a = audit_cell(c, dataset, tag, tool, budget)
            a["cell_file"] = os.path.relpath(f, SYS_ROOT)
            audits[key] = a
            if not a["clean"]:
                msg = f"cell {key} is contaminated by host failure: " + "; ".join(a["problems"])
                if strict:
                    raise SystemExit("REFUSED: " + msg + "\n  rerun the cell at a worker count the "
                                     "host can hold, or pass --allow-host-failures to override")
                print("WARNING: " + msg, file=sys.stderr)
        return c["details"]
    return _cell_details


def _by_slug(details):
    """Group per-record pf1 flags by slug (the bootstrap cluster)."""
    g = {}
    for d in details:
        g.setdefault(d["slug"], []).append(int(d["pf1"]))
    return g


def _boot_rate(clusters, rng):
    """Bootstrap CI of the pf@1 mean, resampling slugs with replacement."""
    keys = list(clusters)
    n_rec = sum(len(v) for v in clusters.values())
    point = sum(sum(v) for v in clusters.values()) / n_rec if n_rec else 0.0
    reps = []
    for _ in range(REPS):
        num = den = 0
        for _ in range(len(keys)):
            v = clusters[keys[rng.randrange(len(keys))]]
            num += sum(v); den += len(v)
        reps.append(num / den if den else 0.0)
    reps.sort()
    lo, hi = reps[int(0.025 * REPS)], reps[int(0.975 * REPS)]
    return {"point": round(point, 4), "ci95": [round(lo, 4), round(hi, 4)], "n_records": n_rec}


def _boot_paired_diff(a_details, b_details, rng):
    """Paired WISP-minus-baseline pf@1 difference, resampling shared slugs with replacement."""
    a = {(d["slug"], d["cve"]): int(d["pf1"]) for d in a_details}
    b = {(d["slug"], d["cve"]): int(d["pf1"]) for d in b_details}
    keys = sorted(set(a) & set(b))
    by_slug = {}
    for slug, cve in keys:
        by_slug.setdefault(slug, []).append((slug, cve))
    slugs = list(by_slug)
    def mean_diff(sample_keys):
        if not sample_keys:
            return 0.0
        return sum(a[k] - b[k] for k in sample_keys) / len(sample_keys)
    point = mean_diff(keys)
    reps = []
    for _ in range(REPS):
        sk = []
        for _ in range(len(slugs)):
            sk.extend(by_slug[slugs[rng.randrange(len(slugs))]])
        reps.append(mean_diff(sk))
    reps.sort()
    lo, hi = reps[int(0.025 * REPS)], reps[int(0.975 * REPS)]
    return {"diff_point": round(point, 4), "ci95": [round(lo, 4), round(hi, 4)],
            "separated": bool(lo > 0 or hi < 0), "n_pairs": len(keys)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="matched-100", choices=sorted(PROFILES))
    ap.add_argument("--tag", default=None, help="cell-file tag; defaults to the dataset's own")
    ap.add_argument("--allow-host-failures", action="store_true",
                    help="warn instead of refusing when a cell carries OOM kills")
    a = ap.parse_args()
    prof = PROFILES[a.dataset]
    tag = prof["tag"] if a.tag is None else a.tag
    DATASET = a.dataset

    matrix_path = os.path.join(OUT, prof["matrix"])
    if not os.path.isfile(matrix_path):
        raise SystemExit(f"no matrix at {os.path.relpath(matrix_path, SYS_ROOT)}")
    matrix = json.load(open(matrix_path))
    cells = matrix["cells"]
    budgets = sorted({int(k.split("@")[1]) for k in cells})
    rng = random.Random(SEED)
    audits = {}
    _cell_details = make_cell_reader(DATASET, tag, audits, not a.allow_host_failures)

    # Audit every cell before any bootstrap runs. Finding the contamination after ten minutes of
    # resampling is finding it too late to be useful.
    for b in budgets:
        for t in TOOLS:
            if f"{t}@{b}" in cells:
                _cell_details(t, b)
    print(f"audited {len(audits)} cells, "
          f"{sum(1 for x in audits.values() if x['clean'])} clean")

    # tool x budget table for every metric, straight from the matrix aggregate
    table = {m: {t: {b: cells.get(f"{t}@{b}", {}).get(m) for b in budgets} for t in TOOLS}
             for m in METRICS}
    ops = {t: {b: {"timeouts": cells.get(f"{t}@{b}", {}).get("timeouts"),
                   "other_err": cells.get(f"{t}@{b}", {}).get("other_err"),
                   "median_elapsed_s": cells.get(f"{t}@{b}", {}).get("median_elapsed_s")}
               for b in budgets} for t in TOOLS}

    # per-cell pf@1 bootstrap CI (slug-cluster)
    pf1_ci = {}
    for b in budgets:
        for t in TOOLS:
            if f"{t}@{b}" in cells:
                pf1_ci[f"{t}@{b}"] = _boot_rate(_by_slug(_cell_details(t, b)), rng)

    # per-budget ranking on pf@1 and paired WISP-minus-baseline diff CI
    per_budget = {}
    for b in budgets:
        present = [t for t in TOOLS if f"{t}@{b}" in cells]
        rank = sorted(present, key=lambda t: table["patch_file_success_at_1"][t][b] or 0, reverse=True)
        diffs = {}
        if "wisp" in present:
            wd = _cell_details("wisp", b)
            for t in present:
                if t != "wisp":
                    diffs[t] = _boot_paired_diff(wd, _cell_details(t, b), rng)
        best_base = max((t for t in present if t != "wisp"),
                        key=lambda t: table["patch_file_success_at_1"][t][b] or 0, default=None)
        per_budget[b] = {
            "ranking_pf1": rank,
            "wisp_pf1": table["patch_file_success_at_1"]["wisp"][b] if "wisp" in present else None,
            "best_baseline": best_base,
            "best_baseline_pf1": table["patch_file_success_at_1"][best_base][b] if best_base else None,
            "wisp_minus_baseline_pf1": diffs}

    out = {
        "schema_version": prof["schema"],
        "artifact_kind": prof["kind"],
        "dataset": DATASET, "n_records": matrix.get("n_records"),
        "budgets_s": budgets, "tools": TOOLS,
        "primary_metric": "patch_file_success_at_1 (failure-as-miss, window=5)",
        "bootstrap": {"unit": "plugin slug (cluster)", "reps": REPS, "seed": SEED,
                      "note": "resample slugs with replacement, carry every record for the slug"},
        # The matrix's file-level block is the stamp of the run that FIRST created the matrix, not of
        # the cells rolled up here. Copying it unlabelled put wisp-scanner-v1.2 at the top of a
        # rollup whose WISP cells are v1.3, and a reviewer correctly refused to accept that the
        # paper's tables came from the runs the methods section claims. It is kept for the host and
        # harness detail it does carry, renamed so it cannot be read as the engine of these numbers,
        # and the engine question is answered per cell just below.
        "provenance_of_first_matrix_run": matrix.get("provenance"),
        "engine_per_cell": {ck: (row.get("engine") or {}) for ck, row in sorted(cells.items())},
        "engines_producing_wisp_cells": matrix.get("engines_producing_wisp_cells"),
        "provenance_note": matrix.get("provenance_note"),
        "table": table, "operational": ops,
        "pf1_bootstrap_ci": pf1_ci, "per_budget": per_budget,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    # The worker count is per cell, because a cell rerun after a host failure was measured under
    # different conditions than the run that produced its neighbours.
    out["host_failure_audit"] = {k: {x: v[x] for x in
                                     ("n_records", "err_split", "host_failures",
                                      "archive_errors", "clean", "problems", "mem_cap_mb",
                                      "workers", "mem_capped", "peak_rss_mb_max")}
                                 for k, v in sorted(audits.items())}
    # The protocol the cells were actually measured under, read from the cells. Recorded as one
    # value only when every cell agrees, so a mixed matrix cannot be described as a uniform one.
    caps = {v["mem_cap_mb"] for v in audits.values() if v["mem_cap_mb"]}
    out["mem_cap_mb"] = caps.pop() if len(caps) == 1 else None
    out["cell_mem_cap_mb"] = {k: v["mem_cap_mb"] for k, v in sorted(audits.items())}
    out["cell_workers"] = {k: (cells[k].get("workers") or audits[k]["workers"])
                           for k in sorted(cells)}
    out["cell_mem_capped"] = {k: v["mem_capped"] for k, v in sorted(audits.items())}
    out["cell_peak_rss_mb_max"] = {k: v["peak_rss_mb_max"] for k, v in sorted(audits.items())}
    dst = os.path.join(OUT, prof["out"])
    json.dump(out, open(dst, "w"), indent=1)
    payload = json.dumps(out, sort_keys=True).encode()
    print(f"wrote {os.path.relpath(dst, SYS_ROOT)}  sha256 {hashlib.sha256(payload).hexdigest()[:12]}")

    # human-readable summary
    print("\npatch-file success@1 (failure-as-miss), slug-cluster 95% CI")
    hdr = "  tool        " + "".join(f"{b:>18}s" for b in budgets)
    print(hdr)
    for t in TOOLS:
        row = f"  {t:12}"
        for b in budgets:
            c = pf1_ci.get(f"{t}@{b}")
            row += f"  {c['point']:.3f} [{c['ci95'][0]:.2f},{c['ci95'][1]:.2f}]" if c else f"{'--':>18}"
        print(row)
    print("\nWISP minus best baseline @ pf1, paired slug-cluster CI")
    for b in budgets:
        pb = per_budget[b]
        bb = pb["best_baseline"]
        d = pb["wisp_minus_baseline_pf1"].get(bb) if bb else None
        if d:
            sep = "separated" if d["separated"] else "overlaps 0"
            print(f"  @{b:>3}s  WISP {pb['wisp_pf1']:.3f} vs {bb} {pb['best_baseline_pf1']:.3f}  "
                  f"diff {d['diff_point']:+.3f} CI[{d['ci95'][0]:+.2f},{d['ci95'][1]:+.2f}] {sep}")


if __name__ == "__main__":
    main()
