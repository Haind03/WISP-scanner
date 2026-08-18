#!/usr/bin/env python3
"""Test a finding-reliability TIER as the primary ranking key, calibrated on
TRAIN and evaluated on a disjoint TEST split.

Motivation (from diag_cf1.py): the advisory-class finding is often a concrete
injection finding sitting in a low-exploitability file, out-ranked by a broad or
heuristic finding in a high-exploitability handler file. File-level entry-point
weight dominates the current score, so a concrete source->sink injection loses to
a missing-guard heuristic in a more-exploitable file. Ranking by a per-finding
reliability tier FIRST (concrete injection > broad taint > heuristic), then by
entry-point, promotes the concrete finding regardless of its file's hook.

Tiers (from the sink string + source, all available at scan time):
  T3 concrete injection : class-defining sink (echo, $wpdb->query, include, eval,
                          move_uploaded_file, ...)
  T2 broad taint        : broad/second-order sink (array_map, getimagesize, copy,
                          proven-taint unserialize, learned method sinks)
  T1 heuristic          : missing-guard (csrf/auth) or non-taint risk pattern
"""
import os, sys, json, argparse

_ENTRY_WEIGHT = {"ajax_nopriv": 5.0, "rest_api": 4.0, "shortcode": 3.0,
                 "ajax_auth": 2.5, "admin": 1.0, "unknown": 0.5}
KS = (1, 3, 5, 10)

_T3_SINKS = ("echo", "print", "$wpdb->query", "->query", "->get_results", "->get_row",
             "->get_var", "->get_col", "mysqli_query", "mysql_query", "pg_query",
             "include", "require", "eval", "system(", "exec(", "shell_exec",
             "passthru", "move_uploaded_file", "wp_handle_upload", "unserialize")
_BROAD_SINKS = ("array_map", "usort", "uasort", "uksort", "call_user_func",
                "register_shutdown_function", "register_tick_function",
                "getimagesize", "get_headers", "header(", "fsockopen", "curl_exec",
                "copy(", "fwrite", "fputs", "put_contents", "loadHTML", "loadXML",
                "appendChild", "createTextNode", "addFile", "get_contents")


def tier(f):
    src = (f.get("source") or "").lower()
    sink = (f.get("sink") or "").lower()
    cls = f["cls"]
    # heuristic tier: missing-guard classes, or the non-taint unserialize risk pattern
    if cls in ("csrf", "auth"):
        return 1
    if "unserialize(untrusted)" in src or f.get("conf", 0.6) <= 0.45:
        return 1
    # concrete injection: a class-defining sink
    if any(s in sink for s in _T3_SINKS):
        # a proven unserialize with real taint stays T2 (risk); only literal sinks T3
        if "unserialize" in sink and cls == "deserial":
            return 2
        return 3
    if any(s in sink for s in _BROAD_SINKS):
        return 2
    return 2  # default moderate


def score(f, wtier, wep, wflow):
    return (wtier * tier(f)
            + wep * _ENTRY_WEIGHT.get(f["ep"], 0.5)
            + (1.0 if f["ip"] else 0.0)
            + wflow * f["conf"])


def metrics(recs, wtier, wep, wflow):
    cf = {k: 0 for k in KS}; pf = {k: 0 for k in KS}; n = len(recs)
    for rec in recs:
        gt = set(rec["gt"]); cls = rec["cls"]
        fs = sorted(rec["findings"], key=lambda f: score(f, wtier, wep, wflow), reverse=True)
        for k in KS:
            top = fs[:k]
            if any(f["file"] in gt for f in top): pf[k] += 1
            if any(f["file"] in gt and f["cls"] == cls for f in top): cf[k] += 1
    return {k: round(cf[k] / n, 4) for k in KS}, {k: round(pf[k] / n, 4) for k in KS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    train = json.load(open(a.train)); test = json.load(open(a.test))
    # (wtier, wep, wflow) grid. wtier=0 recovers the current score.
    grid = [(0, 1, 1),           # baseline
            (2, 1, 1), (3, 1, 1), (5, 1, 1), (8, 1, 1),
            (3, 0.5, 1), (5, 0.5, 1), (8, 0.3, 1),
            (10, 0.2, 1), (100, 1, 1)]
    print(f"{'wtier':>5}{'wep':>5}{'wfl':>4} | {'TRcf1':>6}{'TRcf3':>6}{'TRpf1':>6} "
          f"| {'TEcf1':>6}{'TEcf3':>6}{'TEcf10':>7}{'TEpf1':>6}{'TEpf10':>7}")
    rows = []
    for (wt, we, wf) in grid:
        ctr, ptr = metrics(train, wt, we, wf)
        cte, pte = metrics(test, wt, we, wf)
        rows.append({"w": (wt, we, wf), "train": {"cf": ctr, "pf": ptr},
                     "test": {"cf": cte, "pf": pte}})
        print(f"{wt:>5}{we:>5}{wf:>4} | {ctr[1]:>6}{ctr[3]:>6}{ptr[1]:>6} "
              f"| {cte[1]:>6}{cte[3]:>6}{cte[10]:>7}{pte[1]:>6}{pte[10]:>7}")
    best = max(rows, key=lambda r: (r["train"]["cf"][1], r["train"]["cf"][3]))
    base = rows[0]
    print("\nBEST on TRAIN by cf@1:", best["w"])
    print("  TRAIN:", best["train"]); print("  TEST :", best["test"])
    print("\nBASELINE (wtier=0) TEST:", base["test"])
    print(f"\nTEST cf@1: {base['test']['cf'][1]} -> {best['test']['cf'][1]} "
          f"| TEST cf@10: {base['test']['cf'][10]} -> {best['test']['cf'][10]} "
          f"(wp-taint cf@1 0.13, cf@10 0.21)")
    if a.out:
        json.dump({"rows": rows, "best": best["w"], "baseline_test": base["test"],
                   "best_test": best["test"]}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
