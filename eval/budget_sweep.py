#!/usr/bin/env python3
"""Equal-budget comparison: every tool gets the SAME per-plugin wall-clock budget.

The headline comparison gives each tool its own native budget (Progpilot 25 s,
wp-taint-scan 60 s, Semgrep 300 s, WISP uncapped), which confounds capability with
budget: a tool that times out is charged a miss it might not deserve. This script
holds the budget fixed across all four tools and sweeps it, producing the
coverage/accuracy-versus-budget curve.

WISP has no internal timeout because it runs in-process, so here it is interrupted
with SIGALRM at the budget; the subprocess tools are capped by their own timeout.
Every tool is therefore charged a timeout under the same wall-clock rule.

Per (tool, budget) it reports: coverage (records that completed), class emission
over all records (failure-as-miss), and patch-file success@1.

    python3 -m eval.budget_sweep --budgets 25,60,120 --tools wisp,semgrep,progpilot,wpt \
        --sample /path/sample_100.txt --out out/budget_sweep.json
"""
from __future__ import annotations
import os, sys, json, argparse, shutil, time, signal
import multiprocessing as mp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip
from eval.testset.scan_testset import (ToolFailure, _gt, _semgrep_ranked,
                                       _progpilot_ranked, _wpt_ranked, _wisp_ranked,
                                       TOOL_TIMEOUTS)
from eval.fullcorpus_atk import _progpilot_ranked_lenient

PP_PHAR = os.environ.get("PROGPILOT_BIN", "")
WPT_BIN = os.environ.get("WPT_BIN", "")


class _Alarm(Exception):
    pass


def _run_tool(tool, vzip, vroot, config, budget):
    """Return ranked findings, or raise ToolFailure('timeout') at the budget."""
    if tool == "wisp":
        # WISP runs in-process. Pool workers are daemonic and may not fork children,
        # so the budget is enforced with SIGALRM inside the worker itself; the
        # subprocess tools get the same wall-clock cap through their own timeout.
        def _fire(signum, frame):
            raise _Alarm()
        prev = signal.signal(signal.SIGALRM, _fire)
        signal.alarm(int(budget))
        try:
            return _wisp_ranked(vzip, config)
        except _Alarm:
            raise ToolFailure("timeout")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, prev)
    cfg = dict(config)
    cfg["timeouts"] = {"semgrep": budget, "progpilot": budget, "wpt": budget}
    if tool == "semgrep":
        return _semgrep_ranked(vroot, cfg)
    if tool == "progpilot":
        return _progpilot_ranked_lenient(vroot, cfg)
    return _wpt_ranked(vzip, cfg)


def scan_one(task):
    r, tool, config, budget = task
    res = {"slug": r["slug"], "cve": r["cve"], "cls": r["cls"],
           "err": "", "hit": False, "pf1": 0, "findings": 0}
    vzip, pzip = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(vzip) and os.path.isfile(pzip)):
        res["err"] = "missing_archive"; return res
    vroot, proot = _unzip(vzip), _unzip(pzip)
    try:
        if not (vroot and proot):
            res["err"] = "archive_extract_error"; return res
        gt = set(_gt(vroot, proot).keys())
        t0 = time.time()
        try:
            ranked = _run_tool(tool, vzip, vroot, config, budget)
        except ToolFailure as e:
            res["err"] = str(e); return res
        except Exception as e:
            res["err"] = f"harness:{type(e).__name__}"; return res
        res["elapsed"] = round(time.time() - t0, 1)
        res["findings"] = len(ranked)
        res["hit"] = r["cls"] in {c for f in ranked for c in f.get("classes", [])}
        res["pf1"] = int(bool(ranked) and ranked[0]["file"] in gt)
    finally:
        for d in (vroot, proot):
            if d:
                shutil.rmtree(d, ignore_errors=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budgets", default="25,60,120")
    ap.add_argument("--tools", default="wisp,semgrep,progpilot,wpt")
    ap.add_argument("--sample", required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--progpilot-bin", default=PP_PHAR)
    ap.add_argument("--wpt-bin", default=WPT_BIN)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    config = {"semgrep_bin": os.environ.get("SEMGREP_BIN", "semgrep"),
              "semgrep_configs": ["p/php", "p/security-audit"],
              "progpilot_bin": a.progpilot_bin, "wpt_bin": a.wpt_bin,
              "timeouts": dict(TOOL_TIMEOUTS), "wisp_gda": False}
    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows()
            if os.path.exists(r["vuln_zip"]) and r["slug"] + "|" + r["cve"] in want]
    budgets = [int(b) for b in a.budgets.split(",")]
    tools = a.tools.split(",")

    # resume: keep whatever cells already finished
    out = json.load(open(a.out)) if os.path.exists(a.out) else {"cells": {}}
    for budget in budgets:
        for tool in tools:
            ck = f"{tool}@{budget}"
            if ck in out["cells"]:
                print(f"skip {ck} (đã có)", flush=True); continue
            t0 = time.time()
            with mp.Pool(a.workers) as pool:
                det = pool.map(scan_one, [(r, tool, config, budget) for r in rows])
            n = len(det)
            done = sum(1 for d in det if not d["err"])
            out["cells"][ck] = {
                "tool": tool, "budget_s": budget, "n": n,
                "completed": done, "coverage": round(done / n, 4) if n else 0,
                "timeouts": sum(1 for d in det if d["err"] == "timeout"),
                "other_err": sum(1 for d in det if d["err"] and d["err"] != "timeout"),
                "class_emission": round(sum(1 for d in det if d["hit"]) / n, 4) if n else 0,
                "pf1": round(sum(d["pf1"] for d in det) / n, 4) if n else 0,
                "elapsed_total_s": round(time.time() - t0, 1),
                "details": det,
            }
            json.dump(out, open(a.out, "w"), indent=1)   # ghi ngay, chết không mất
            c = out["cells"][ck]
            print(f"{ck:16} cov={c['coverage']:.2f} emit={c['class_emission']:.3f} "
                  f"pf@1={c['pf1']:.3f} timeouts={c['timeouts']} ({c['elapsed_total_s']:.0f}s)",
                  flush=True)
    print("BUDGET_SWEEP_DONE")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
