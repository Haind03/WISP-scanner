#!/usr/bin/env python3
"""Peak resident memory per tool per plugin, so the memory ceiling is chosen from evidence.

The equal-budget matrix now budgets memory as well as wall clock. A ceiling picked by eye is a
handicap dressed as a protocol, so this measures what each tool actually needs on a sample of the
corpus, under a deliberately generous ceiling that exists only to keep the host alive.

    python3 -m eval.mem_profile_v3 --sample <file> --n 12 --budget 120 --probe-cap-mb 6144

Writes MEM_PROFILE_V3.json: per tool, the peak resident set for every record, the quantiles, and how
many records would breach each candidate ceiling. That last table is the one that decides the number.
"""
from __future__ import annotations
import os, sys, json, time, argparse, multiprocessing as mp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
sys.path.insert(0, ROOT)

from eval.baseline_matrix_v3 import (load_rows, _unzip, WPT_BIN, PROGPILOT, SEMGREP_LOCAL)
from eval.resource_budget import run_capped, BudgetExceeded
from eval.testset.scan_testset import ToolFailure

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
TOOLS = ["wisp", "semgrep", "progpilot", "wpt"]
CANDIDATES = [1024, 2048, 3072, 4096, 6144]


def _cmd(tool, vzip, vroot, src):
    if tool == "wisp":
        return [sys.executable, "-m", "eval._wisp_worker", vzip, "{}"], ROOT
    if tool == "semgrep":
        return (["semgrep", *sum([["--config", c] for c in SEMGREP_LOCAL], []),
                 "--json", "--quiet", "--metrics=off", "--jobs", "1", "--timeout", "20",
                 "--max-target-bytes", "2000000", vroot], None)
    if tool == "progpilot":
        return ["php", PROGPILOT, vroot], None
    return ([WPT_BIN, "-target", src, "-output-dir", src + "-out",
             "-mem-limit-mb", "2048", "-phparser-workers", "1"],
            os.path.dirname(os.path.dirname(WPT_BIN)))


def probe_one(task):
    r, tool, budget, cap = task
    row = {"slug": r["slug"], "cve": r["cve"], "tool": tool,
           "peak_kb": 0, "verdict": "", "elapsed": None,
           # Per record, because records merged from separate passes were not all measured under
           # the same probe ceiling, and a peak that stopped at the ceiling means something
           # different from one that stopped on its own.
           "budget_s": budget, "probe_cap_mb": cap}
    vzip = r["vuln_zip"]
    if not os.path.isfile(vzip):
        row["verdict"] = "missing_archive"; return row
    vroot = _unzip(vzip)
    if not vroot:
        row["verdict"] = "archive_extract_error"; return row
    src = vroot
    cmd, cwd = _cmd(tool, vzip, vroot, src)
    t0 = time.time()
    try:
        done, peak = run_capped(cmd, budget, cap, cwd=cwd)
        row["peak_kb"], row["verdict"] = peak, f"exit:{done.returncode}"
    except BudgetExceeded as e:
        row["peak_kb"], row["verdict"] = e.peak_kb, e.reason
    except Exception as e:
        row["verdict"] = f"harness:{type(e).__name__}"
    finally:
        import shutil
        shutil.rmtree(vroot, ignore_errors=True)
        shutil.rmtree(src + "-out", ignore_errors=True)
    row["elapsed"] = round(time.time() - t0, 1)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--budget", type=int, default=120)
    ap.add_argument("--probe-cap-mb", type=int, default=6144)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--include-slugs", default="",
                    help="comma-separated slugs always in the sample, regardless of the stride")
    a = ap.parse_args()
    tools = [t.strip() for t in a.tools.split(",") if t.strip()]

    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows()
            if os.path.exists(r["vuln_zip"]) and r["slug"] + "|" + r["cve"] in want]
    # Spread the sample across the archive-size range rather than taking the head, since memory
    # tracks plugin size and the head of a sorted slug list is not a sample of anything.
    rows.sort(key=lambda r: os.path.getsize(r["vuln_zip"]))
    # --n 0 probes nothing by stride, which is how the two records that decided the ceiling get
    # measured on their own at a probe ceiling high enough to see where they actually stop.
    picked = rows[::max(1, len(rows) // a.n)][:a.n] if a.n > 0 else []
    # A stride over the size range is a fair sample and still misses the tail, and the tail is where
    # the memory question lives. The first profile drew fourteen records and found no WISP peak above
    # 0.5 GB, while w3-total-cache, which it did not draw, peaks at 4.76 GB. Named records are forced
    # in so the record that decided the ceiling is in the artifact that justifies it.
    forced = {s.strip() for s in a.include_slugs.split(",") if s.strip()}
    if forced:
        have = {r["slug"] for r in picked}
        picked += [r for r in rows if r["slug"] in forced and r["slug"] not in have]
    rows = picked
    print(f"memory profile: {len(rows)} records x {len(tools)} tools, budget {a.budget}s, "
          f"probe ceiling {a.probe_cap_mb} MB, {a.workers} workers", flush=True)

    out = {"schema_version": "mem-profile-v3", "budget_s": a.budget,
           "probe_cap_mb": a.probe_cap_mb, "workers": a.workers,
           "n_records_this_pass": len(rows), "tools": tools,
           "forced_slugs": sorted(forced), "records": [], "per_tool": {}}
    # A pass measures what it was asked to measure and keeps what an earlier pass already measured.
    # The stratified sample and the two records that decide the ceiling need different probe
    # ceilings and different concurrency, so they are two passes, and re-measuring the first one to
    # add the second would cost two hours for nothing.
    prior = {}
    if os.path.isfile(os.path.join(OUT, "MEM_PROFILE_V3.json")):
        old = json.load(open(os.path.join(OUT, "MEM_PROFILE_V3.json")))
        for d in old.get("records", []):
            prior[(d["slug"], d["cve"], d["tool"])] = d
        out["merged_from_earlier_pass"] = len(prior)

    for tool in tools:
        with mp.Pool(a.workers) as pool:
            det = pool.map(probe_one, [(r, tool, a.budget, a.probe_cap_mb) for r in rows])
        for d in det:
            prior[(d["slug"], d["cve"], d["tool"])] = d
        det = [d for d in prior.values() if d["tool"] == tool]
        out["records"] += det
        peaks = sorted(d["peak_kb"] for d in det if d["peak_kb"])
        q = lambda f: peaks[min(len(peaks) - 1, int(f * len(peaks)))] if peaks else 0
        out["per_tool"][tool] = {
            "n": len(det), "n_measured": len(peaks),
            "peak_mb_median": round(q(0.5) / 1024, 1), "peak_mb_p90": round(q(0.9) / 1024, 1),
            "peak_mb_max": round((peaks[-1] if peaks else 0) / 1024, 1),
            "breaches": {str(c): sum(1 for p in peaks if p > c * 1024) for c in CANDIDATES},
            "verdicts": {v: sum(1 for d in det if d["verdict"] == v)
                         for v in sorted({d["verdict"] for d in det})}}
        t = out["per_tool"][tool]
        print(f"  {tool:10} median {t['peak_mb_median']:7.1f} MB  p90 {t['peak_mb_p90']:7.1f} MB  "
              f"max {t['peak_mb_max']:7.1f} MB  breaches {t['breaches']}", flush=True)

    out["n_records"] = len({(d["slug"], d["cve"]) for d in out["records"]})
    dst = os.path.join(OUT, "MEM_PROFILE_V3.json")
    json.dump(out, open(dst, "w"), indent=1)
    print(f"\nwrote {os.path.relpath(dst, SYS_ROOT)}")
    print("\nrecords over 3072 MB:")
    for d in out["records"]:
        if d["peak_kb"] > 3072 * 1024:
            print(f"  {d['tool']:10} {d['slug'][:38]:40} {d['peak_kb']/1048576:5.2f} GB  {d['verdict']}")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
