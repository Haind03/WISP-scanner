#!/usr/bin/env python3
"""Fair baseline run matrix (Prompt 5): dataset x budget x tool, one wall-clock rule for all.

Every cell uses the same manifest, the same host, the same worker policy, the same failure-as-miss
rule, and the same top-K scorer. WISP is capped by a real per-plugin subprocess timeout with a
process-group kill (partial output dropped), so "WISP uncapped" is removed. Semgrep runs against the
LOCAL snapshot yaml files from RULE_MANIFEST_V3.json, never a dynamic registry id. Each cell writes a
separate output file, the exact run command, wall time, and timeout/error counts. Provenance
(git commit, tool hashes) is written into the JSON at run time, never patched afterward.

    # validate the harness on a few plugins, one budget
    python3 -m eval.baseline_matrix_v3 --sample <file> --budgets 25 --limit 3 --tag smoke
    # the matched-100 matrix at three budgets
    python3 -m eval.baseline_matrix_v3 --sample <file> --budgets 25,60,300 --dataset matched-100
"""
from __future__ import annotations
import os, sys, json, time, signal, argparse, shutil, subprocess, hashlib
import multiprocessing as mp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip
from eval.testset.scan_testset import (ToolFailure, _gt, _score, map_class,
                                       _semgrep_ranked, _wpt_ranked, TOOL_TIMEOUTS)
from eval.fullcorpus_atk import _progpilot_ranked_lenient
from eval import wisp_contract as WC
from eval.resource_budget import run_capped, BudgetExceeded
from eval import resource_budget as rb

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
SNAP = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "semgrep_rules")
CELL_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "cells")
# progpilot.phar requires PHP >= 8.3 and fatal-errors on this PHP 8.1 host (emitting nothing); the
# compatible build progpilot_ok.phar runs and emits findings. The fair matrix uses the working phar.
PROGPILOT = os.path.join(SYS_ROOT, "baselines", "progpilot_ok.phar")
WPT_BIN = os.path.join(SYS_ROOT, "external", "wp-taint-scan", "bin", "taint-scan")
SEMGREP_LOCAL = [os.path.join(SNAP, "p_php.yaml"), os.path.join(SNAP, "p_security_audit.yaml")]
WINDOW = 5
KS = (1, 3, 5, 10)
# Resident-memory ceiling per scanned plugin, the same for every tool. Set from measurement, and set
# high on purpose, because a ceiling that fails a scan the tool would have completed is not a budget
# but a handicap. The first attempt at 3 GB did exactly that: it failed WISP on w3-total-cache, which
# on an idle host peaks at 4.76 GB and then finishes normally in under two minutes. Measured peaks
# for scans that complete are 0.69 GB for Semgrep, 1.05 GB for Progpilot and 4.76 GB for WISP, while
# wp-taint-scan on blog-filter passes 12 GB and never finishes. Six gigabytes sits above every
# completing scan observed and well below the divergent one, so a breach is evidence of divergence
# rather than of a tight budget. It is also three times the 2 GB soft heap ceiling wp-taint-scan is
# configured with and itself documents as unenforceable.
MEM_CAP_MB = 6144


def _sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) else ""


def _run_wisp_subprocess(vzip, budget, variant=None):
    """Run WISP on one plugin in its own process group; kill the group at the budget. Partial output
    is dropped (only a clean JSON stdout is accepted). Config is the Evaluation Contract (GDA off,
    sanitizer on); a named sensitivity variant may be requested. WISP runs under the same memory
    ceiling as every baseline, so the budget is a property of the protocol and not a handicap
    applied to one tool."""
    cfg = {"variant": variant} if variant else {}
    cmd = [sys.executable, "-m", "eval._wisp_worker", vzip, json.dumps(cfg)]
    try:
        done, _peak = run_capped(cmd, budget, MEM_CAP_MB, cwd=ROOT)
    except BudgetExceeded as e:
        raise ToolFailure(str(e))
    out, p = done.stdout, done
    if p.returncode != 0 or not out.strip():
        raise ToolFailure(f"harness_exit:{p.returncode}")
    d = json.loads(out)
    miss = WC.worker_miss_reason(d)      # not-ok OR analysis non-convergence -> failure-as-miss (contract §4)
    if miss:
        raise ToolFailure(miss)
    return d["ranked"], cmd


def _run_tool(tool, vzip, vroot, budget):
    """Return (ranked, run_command). Raises ToolFailure at the budget/on error."""
    if tool == "wisp":
        return _run_wisp_subprocess(vzip, budget)
    cfg = {"timeouts": {"semgrep": budget, "progpilot": budget, "wpt": budget},
           "mem_cap_mb": MEM_CAP_MB}
    if tool == "semgrep":
        cfg.update({"semgrep_bin": "semgrep", "semgrep_configs": SEMGREP_LOCAL})
        cmd = ["semgrep", *sum([["--config", c] for c in SEMGREP_LOCAL], []),
               "--json", "--quiet", "--metrics=off", "--jobs", "1", "--timeout", "20",
               "--max-target-bytes", "2000000", vroot]
        return _semgrep_ranked(vroot, cfg), cmd
    if tool == "progpilot":
        cfg["progpilot_bin"] = PROGPILOT
        return _progpilot_ranked_lenient(vroot, cfg), ["php", PROGPILOT, vroot]
    cfg["wpt_bin"] = WPT_BIN
    return _wpt_ranked(vzip, cfg), [WPT_BIN, "-target", "<src>", "-output-dir", "<out>"]


def scan_one(task):
    r, tool, budget = task
    res = {"slug": r["slug"], "cve": r["cve"], "cls": map_class(r["cls"]),
           "err": "", "hit": False, "elapsed": None, "findings": 0}
    for k in KS:
        res[f"pf{k}"] = 0
    vzip, pzip = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(vzip) and os.path.isfile(pzip)):
        res["err"] = "missing_archive"; return res
    vroot, proot = _unzip(vzip), _unzip(pzip)
    try:
        if not (vroot and proot):
            res["err"] = "archive_extract_error"; return res
        gt = _gt(vroot, proot)
        t0 = time.time()
        try:
            ranked, _cmd = _run_tool(tool, vzip, vroot, budget)
        except ToolFailure as e:
            res["err"] = str(e); res["elapsed"] = round(time.time() - t0, 1)
            res["peak_rss_mb"] = round(rb.LAST_PEAK_KB / 1024, 1); return res
        except Exception as e:
            res["err"] = f"harness:{type(e).__name__}"; return res
        res["elapsed"] = round(time.time() - t0, 1)
        # What the scan actually cost against the ceiling it was given. Recorded for every record,
        # so the claim that the memory budget is generous is a column a reader can check rather
        # than a sentence they have to believe.
        res["peak_rss_mb"] = round(rb.LAST_PEAK_KB / 1024, 1)
        res["findings"] = len(ranked)
        class_emit, pf, cf, ch, cfn = _score(ranked, gt, res["cls"], WINDOW)
        res["hit"] = bool(class_emit)
        for k in KS:
            res[f"pf{k}"] = pf[k]
    finally:
        for d in (vroot, proot):
            if d:
                shutil.rmtree(d, ignore_errors=True)
    return res


def _provenance(workers=None):
    def _git(*a):
        try:
            return subprocess.check_output(["git", "-C", ROOT, *a], stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            return ""
    rm = os.path.join(OUT, "RULE_MANIFEST_V3.json")
    tm = os.path.join(OUT, "TOOL_MANIFEST_V3.json")
    return {"wisp_git_commit": _git("rev-parse", "HEAD"),
            "wisp_git_dirty": bool(_git("status", "--porcelain")),
            "rule_manifest_sha256": _sha256_file(rm), "tool_manifest_sha256": _sha256_file(tm),
            "semgrep_local_configs": {os.path.basename(c): _sha256_file(c) for c in SEMGREP_LOCAL},
            "host": os.uname().sysname + " " + os.uname().release,
            "python": sys.version.split()[0],
            # The number belongs in the record. Every metric here is a wall-clock verdict, so two
            # runs at different worker counts are two different experiments, and a provenance
            # string that cannot tell them apart is a provenance string that hides the difference.
            "workers": workers,
            "host_cpu_count": os.cpu_count(),
            "worker_policy": "fixed Pool workers (see workers); every plugin has its own per-plugin "
                             "wall-clock cap; tools are NOT run concurrently (one tool at a time); "
                             "cold cache (first run)",
            # Time was budgeted from the start and memory was not, which let one tool blow through
            # its own soft heap ceiling to 13.2 GB and be killed by the host, taking sibling scans
            # with it. Both budgets are now declared, enforced identically for every tool, and
            # recorded here, because a resource budget that is not in the record is not a protocol.
            "mem_cap_mb": MEM_CAP_MB,
            "mem_cap_policy": "resident-set ceiling per scanned plugin, identical for all four "
                              "tools, enforced by the harness (eval.resource_budget.run_capped) by "
                              "sampling the process tree's VmRSS and killing the process group on "
                              "breach; recorded as mem_cap_exceeded and scored as a miss, the same "
                              "as a timeout",
            "failure_rule": "failure-as-miss (contract v1 s4): a timeout, a memory-ceiling breach, "
                            "an error, OR WISP analysis non-convergence "
                            "(analysis_status.complete==false) counts as no finding over the full "
                            "denominator for every metric",
            "wisp_config": WC.config_stamp(),
            "scorer": "eval.testset.scan_testset._score, window=%d, K=%s" % (WINDOW, KS),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _loadavg():
    try:
        return [float(x) for x in open("/proc/loadavg").read().split()[:3]]
    except Exception:
        return None


def cell(rows, tool, budget, workers):
    """Every metric here is a wall-clock verdict, so competing load on the host changes the answer.
    A run that shares the machine pushes plugins past the budget and reads as lower coverage, which
    looks exactly like a capability difference and is not one. The host load is sampled at both ends
    of the cell so a reader can see the conditions instead of taking a claim of quiet on trust."""
    t0 = time.time()
    load0 = _loadavg()
    with mp.Pool(workers) as pool:
        det = pool.map(scan_one, [(r, tool, budget) for r in rows])
    load1 = _loadavg()
    n = len(det)
    done = sum(1 for d in det if not d["err"])
    agg = {"tool": tool, "budget_s": budget, "dataset_n": n,
           "completed": done, "coverage": round(done / n, 4) if n else 0,
           "timeouts": sum(1 for d in det if d["err"] == "timeout"),
           "non_converged": sum(1 for d in det if d["err"] == "non_converged"),
           # Broken out rather than pooled into other_err. A memory-ceiling breach is the second
           # budget doing its job, so it belongs beside the timeout count where a reader can see
           # how much of a tool's failure is resource exhaustion rather than a defect.
           "mem_capped": sum(1 for d in det if d["err"] == "mem_cap_exceeded"),
           "other_err": sum(1 for d in det if d["err"] and d["err"] not in
                            ("timeout", "non_converged", "mem_cap_exceeded")),
           "class_emission_failure_as_miss": round(sum(1 for d in det if d["hit"]) / n, 4) if n else 0,
           "peak_rss_mb_max": max([d.get("peak_rss_mb") or 0 for d in det], default=0),
           "peak_rss_mb_p90": sorted(d.get("peak_rss_mb") or 0 for d in det)[int(0.9 * n)]
           if n else 0,
           "wall_time_total_s": round(time.time() - t0, 1),
           "host_loadavg_start": load0, "host_loadavg_end": load1,
           "median_elapsed_s": round(sorted(d["elapsed"] for d in det if d["elapsed"] is not None)[done // 2], 1)
           if done else None}
    for k in KS:
        agg[f"patch_file_success_at_{k}"] = round(sum(d[f"pf{k}"] for d in det) / n, 4) if n else 0
    agg["details"] = det
    return agg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--dataset", default="matched-100")
    ap.add_argument("--budgets", default="25,60,300")
    ap.add_argument("--tools", default="wisp,semgrep,progpilot,wpt")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--tag", default="")
    a = ap.parse_args()

    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows()
            if os.path.exists(r["vuln_zip"]) and r["slug"] + "|" + r["cve"] in want]
    if a.limit:
        rows = rows[:a.limit]
    budgets = [int(b) for b in a.budgets.split(",")]
    tools = a.tools.split(",")
    prov = _provenance(a.workers)
    os.makedirs(CELL_DIR, exist_ok=True)

    matrix_path = os.path.join(OUT, f"BASELINE_MATRIX_V3{('_' + a.tag) if a.tag else ''}.json")
    matrix = json.load(open(matrix_path)) if os.path.exists(matrix_path) else {
        "schema_version": "baseline-matrix-v3", "dataset": a.dataset, "n_records": len(rows),
        "provenance": prov, "cells": {}}
    print(f"matrix {a.dataset}: {len(rows)} records x {len(budgets)} budgets x {len(tools)} tools")

    for budget in budgets:
        for tool in tools:                          # one tool at a time (no CPU contention)
            ck = f"{tool}@{budget}"
            if ck in matrix["cells"]:
                print(f"skip {ck} (already done)", flush=True); continue
            c = cell(rows, tool, budget, a.workers)
            # separate per-cell output file
            cell_file = os.path.join(CELL_DIR, f"{a.dataset}__{ck}{('__' + a.tag) if a.tag else ''}.json")
            json.dump({"provenance": prov, **c}, open(cell_file, "w"), indent=1)
            matrix["cells"][ck] = {k: v for k, v in c.items() if k != "details"}
            matrix["cells"][ck]["cell_file"] = os.path.relpath(cell_file, SYS_ROOT)
            # Engine identity PER CELL. The file-level provenance block below is written once, when
            # the matrix file is first created, so re-measuring the WISP cells on a new engine left
            # the whole file stamped with the old one. A reviewer read that stamp, saw
            # wisp-scanner-v1.2 on a matrix whose WISP cells are v1.3, and could not tell which
            # engine produced which number. A cell is the unit that was measured, so it is the unit
            # that carries the stamp.
            #
            # For a baseline the WISP engine tag is not a property of the result: Semgrep's output
            # does not depend on which WISP engine happened to be on disk. It is recorded as the
            # harness engine and labelled as not applicable, rather than left to look like a claim.
            _wc = prov.get("wisp_config") or {}
            matrix["cells"][ck]["engine"] = {
                "engine_tag": _wc.get("engine_tag"),
                "engine_sha256": _wc.get("engine_sha256"),
                "per_key_cap": _wc.get("per_key_cap"),
                "applies_to_this_cell": (tool == "wisp"),
                "note": ("the engine that produced this cell" if tool == "wisp" else
                         "harness engine present at run time; this cell is %s output and does not "
                         "depend on it" % tool),
                "measured_utc": prov.get("timestamp_utc")}
            # Per cell, not just per run. A cell re-run at a different worker count after a host
            # failure is a cell measured under different conditions, and the matrix has to say so
            # rather than inherit the run-level number and hide it.
            matrix["cells"][ck]["workers"] = a.workers
            # Refresh the file-level summary from the cells every write, so the header can never
            # again describe an engine that only some of the file was measured on.
            _eng = sorted({(v.get("engine") or {}).get("engine_tag")
                           for v in matrix["cells"].values()
                           if (v.get("engine") or {}).get("applies_to_this_cell")} - {None})
            matrix["engines_producing_wisp_cells"] = _eng
            matrix["provenance_note"] = (
                "The 'provenance' block is the stamp of the run that FIRST created this file and "
                "describes that run only. Cells added or re-measured later carry their own "
                "'engine' block, which is authoritative. WISP cells here were produced by: "
                + (", ".join(_eng) if _eng else "no WISP cell in this file") + ". Baseline cells "
                "carry the harness engine for the record and do not depend on it.")
            json.dump(matrix, open(matrix_path, "w"), indent=1)
            l0, l1 = c["host_loadavg_start"], c["host_loadavg_end"]
            load = f" load={l0[0]:.1f}->{l1[0]:.1f}" if l0 and l1 else ""
            print(f"{ck:16} cov={c['coverage']:.2f} emit={c['class_emission_failure_as_miss']:.3f} "
                  f"pf@1={c['patch_file_success_at_1']:.3f} pf@3={c['patch_file_success_at_3']:.3f} "
                  f"timeouts={c['timeouts']} memcap={c['mem_capped']} err={c['other_err']} "
                  f"({c['wall_time_total_s']:.0f}s){load}", flush=True)
    print(f"BASELINE_MATRIX_DONE -> {matrix_path}")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
