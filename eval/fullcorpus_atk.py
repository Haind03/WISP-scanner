#!/usr/bin/env python3
"""Finding-level file-precision@K for Semgrep / Progpilot / wp-taint-scan on the
FULL 1108-record Patchstack corpus, with CORRECTED archive identity.

This is the fresh counterpart of the retired full-corpus baseline table: the old
outputs (baselines/out_sg_atk_full.json, out_pp_atk_full.json, out_wpt_atk_full.json)
were scored against a patched archive picked by filename glob, which chose the
wrong patched zip for ~200 records, so they cannot be reused. Here every record
uses eval.datasets.patchstack.load_rows()'s corrected vuln_zip/patched_zip pair,
and each tool is ranked by its own best native signal via the shared runners in
eval.testset.scan_testset (Semgrep severity, Progpilot emission order,
wp-taint-scan native access-tier ranking through eval.wpt_adapter).

The WISP column of the same table comes from eval.localize's rank_at_k on the
same corpus (finding-level file-precision@K), so the metric is identical.

    python3 -m eval.fullcorpus_atk --tool semgrep   --workers 8 --out out/fill_20260714/atk_sg_1108.json
    python3 -m eval.fullcorpus_atk --tool progpilot --workers 8 --out out/fill_20260714/atk_pp_1108.json
    python3 -m eval.fullcorpus_atk --tool wpt       --workers 8 --out out/fill_20260714/atk_wpt_1108.json
"""
from __future__ import annotations
import os, sys, json, argparse, shutil, time
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip
from eval.testset.scan_testset import (ToolFailure, _gt, _semgrep_ranked,
                                       _progpilot_ranked, _wpt_ranked,
                                       _tool_identity, SG_CONFIGS, TOOL_TIMEOUTS)

import subprocess, json as _json
from eval.testset.scan_testset import map_class, _keyof, _SEV  # noqa: E402

KS = (1, 3, 5, 10)
# Portable like the rest of eval/: binaries come from the environment or --flags,
# never from a hardcoded developer path.
PP_PHAR = os.environ.get("PROGPILOT_BIN", "")
WPT_BIN = os.environ.get("WPT_BIN", "")


def _progpilot_ranked_lenient(vroot, config):
    """Kept as the historical name used by this module, eval.baseline_matrix_v3 and
    eval.budget_sweep. It is now an alias for the single Progpilot runner in
    eval.testset.scan_testset, which parses stdout regardless of the exit code.

    There used to be two runners: this one and a strict one in scan_testset that
    raised on any nonzero exit. They disagreed on the same stdout, so the tables
    built on each disagreed about Progpilot (contract v1 s5). The strict branch is
    gone; scan_testset._progpilot_ranked is the one implementation. Its rows carry
    two extra keys (source_file, source_line) that scoring here ignores, and the
    file/line/classes/rule it produces are computed identically.
    """
    return _progpilot_ranked(vroot, config)


def scan_one(task):
    r, tool, config = task
    res = {"slug": r["slug"], "cve": r["cve"], "cls": r["cls"], "err": "",
           "gt_files": 0, "findings": 0, "file_tp": 0,
           "topk_tp": {str(k): 0 for k in KS}, "topk_n": {str(k): 0 for k in KS},
           "top10": [], "detected": [], "hit": False, "tool_seconds": None}
    vzip, pzip = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(vzip) and os.path.isfile(pzip)):
        res["err"] = "missing_archive"; return res
    vroot, proot = _unzip(vzip), _unzip(pzip)
    try:
        if not (vroot and proot):
            res["err"] = "archive_extract_error"; return res
        gt = set(_gt(vroot, proot).keys())
        res["gt_files"] = len(gt)
        # Time the tool call only, excluding unzip and diffing, so an equal-budget
        # curve can be derived from one generous run instead of one run per budget:
        # a record the tool finished in 40 s would also finish under a 60 s cap.
        # Wall time under N workers carries contention, but every tool is measured
        # the same way, and the derived curve is stated as such.
        t_tool = time.time()
        try:
            if tool == "semgrep":
                ranked = _semgrep_ranked(vroot, config)
            elif tool == "progpilot":
                ranked = _progpilot_ranked_lenient(vroot, config)
            else:
                ranked = _wpt_ranked(vzip, config)
        except ToolFailure as e:
            res["tool_seconds"] = round(time.time() - t_tool, 2)
            res["err"] = str(e); return res
        except Exception as e:
            res["tool_seconds"] = round(time.time() - t_tool, 2)
            res["err"] = f"harness:{type(e).__name__}"; return res
        res["tool_seconds"] = round(time.time() - t_tool, 2)
        files = [f["file"] for f in ranked]
        res["detected"] = sorted({c for f in ranked for c in f.get("classes", [])})
        res["hit"] = r["cls"] in res["detected"]
        res["findings"] = len(files)
        res["file_tp"] = sum(1 for f in files if f in gt)
        for k in KS:
            top = files[:k]
            res["topk_n"][str(k)] = len(top)
            res["topk_tp"][str(k)] = sum(1 for f in top if f in gt)
        res["top10"] = files[:10]
    finally:
        shutil.rmtree(vroot, ignore_errors=True) if vroot else None
        shutil.rmtree(proot, ignore_errors=True) if proot else None
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool", choices=["semgrep", "progpilot", "wpt"], required=True)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--sample", default="", help="file of slug|cve keys to restrict to")
    ap.add_argument("--progpilot-bin", default=PP_PHAR,
                    help="progpilot phar (or set PROGPILOT_BIN)")
    ap.add_argument("--wpt-bin", default=WPT_BIN,
                    help="wp-taint-scan executable (or set WPT_BIN)")
    ap.add_argument("--cap", type=int, default=0,
                    help="per-record tool timeout in seconds; 0 keeps the tool's "
                         "own default from TOOL_TIMEOUTS")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.tool == "progpilot" and not a.progpilot_bin:
        ap.error("progpilot needs --progpilot-bin or PROGPILOT_BIN")
    if a.tool == "wpt" and not a.wpt_bin:
        ap.error("wpt needs --wpt-bin or WPT_BIN")

    config = {"semgrep_bin": os.environ.get("SEMGREP_BIN", "semgrep"),
              "semgrep_configs": ["p/php", "p/security-audit"],
              "progpilot_bin": a.progpilot_bin, "wpt_bin": a.wpt_bin,
              "timeouts": dict(TOOL_TIMEOUTS), "wisp_gda": False}
    if a.cap:
        # one generous timed pass answers every smaller budget, so the cap is
        # a knob rather than a constant (see eval/budget_curve.py)
        config["timeouts"][a.tool] = a.cap
    rows = [r for r in load_rows() if os.path.exists(r["vuln_zip"])]
    if a.sample:
        want = {s.strip() for s in open(a.sample) if s.strip()}
        rows = [r for r in rows if r["slug"] + "|" + r["cve"] in want]

    t0 = time.time()
    details = []
    with Pool(a.workers) as pool:
        for i, d in enumerate(pool.imap_unordered(
                scan_one, [(r, a.tool, config) for r in rows], chunksize=1), 1):
            details.append(d)
            if i % 25 == 0:
                print(f"...{i}/{len(rows)} ({time.time()-t0:.0f}s)", flush=True)

    per_class = {}
    for d in details:
        c = d["cls"]
        tp, tot = per_class.get(c, (0, 0))
        per_class[c] = (tp + (1 if d["hit"] else 0), tot + 1)
    agg_tp = {str(k): sum(d["topk_tp"][str(k)] for d in details) for k in KS}
    agg_n = {str(k): sum(d["topk_n"][str(k)] for d in details) for k in KS}
    ft = sum(d["file_tp"] for d in details)
    nf = sum(d["findings"] for d in details)
    errs = sum(1 for d in details if d["err"])
    with_find = sum(1 for d in details if not d["err"] and d["findings"] > 0)
    none_find = sum(1 for d in details if not d["err"] and d["findings"] == 0)
    rep = {"tool": a.tool, "n_records": len(details),
           "archive_identity": "eval.datasets.patchstack.load_rows; corrected vuln_zip/patched_zip",
           "tool_identity": _tool_identity(
               a.tool, {"semgrep": "semgrep", "progpilot": PP_PHAR, "wpt": WPT_BIN}[a.tool]),
           "timeouts": config["timeouts"],
           "prec_at_k": {k: round(agg_tp[k] / agg_n[k], 4) if agg_n[k] else 0
                         for k in agg_tp},
           "all_findings_precision": round(ft / nf, 4) if nf else 0,
           "records_with_findings": with_find,
           "records_completed_no_findings": none_find,
           "records_error_or_timeout": errs,
           "class_recall": round(sum(1 for d in details if d["hit"]) / len(details), 4)
                           if details else 0,
           "per_class": {c: {"recall": round(tp / tot, 3) if tot else 0,
                             "tp": tp, "total": tot}
                         for c, (tp, tot) in sorted(per_class.items())},
           "err_breakdown": {},
           "elapsed_s": round(time.time() - t0, 1),
           "details": details}
    for d in details:
        if d["err"]:
            rep["err_breakdown"][d["err"]] = rep["err_breakdown"].get(d["err"], 0) + 1
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print(json.dumps({k: rep[k] for k in ("tool", "n_records", "prec_at_k",
          "all_findings_precision", "records_with_findings",
          "records_completed_no_findings", "records_error_or_timeout",
          "err_breakdown", "elapsed_s")}, indent=2))


if __name__ == "__main__":
    main()
