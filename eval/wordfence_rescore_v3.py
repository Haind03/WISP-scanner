#!/usr/bin/env python3
"""Re-score the 100-CVE Wordfence external set at the TRUE geometric endpoints (contract v1).

The shipped wordfence scoring stored only patch-file / class-file / proximity / class-fn indicators,
so the manuscript's "exact-changed-line rung 0.21" was actually the proximity/hunk rung mislabeled
(reviewer issue 5). This rebuilds a PatchMap per record from the Wordfence archives and scores every
tool's shipped findings with eval/patch_geometry.py, giving the real in_patched_file, same_callable,
on_exact_changed_line, within_5, and same_diff_hunk rates under the one contract (deleted files count
at file level only). Writes wordfence100_ladder_true_v3.json. No scanner is re-run.

    python3 -m eval.wordfence_rescore_v3
"""
from __future__ import annotations
import os, sys, json, argparse, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
from eval import patch_geometry as pg
from eval.testset.scan_testset import map_class

TS = os.path.join(SYS_ROOT, "100-CVE-testset")
MAN = os.path.join(TS, "testset_manifest.json")
# The contract rescan, NOT wordfence100_scored_wisp.json beside it. That file is the 2026-07-31 scan,
# taken on engine commit 84f5eb14, and it holds 3631 WISP findings where the contract scan holds
# 3646. Because eval/reproduce_all_v3.py calls this module with no arguments, the default was the
# only thing deciding which engine the manuscript's Wordfence per-finding ladder described, and it
# chose an engine three weeks older than every other number in the paper. A reviewer caught the
# 3631-versus-3646 disagreement between the manuscript and the supplement, which is what that
# mismatch looks like from the outside. Pass --scored to score any other run.
SCORED = os.path.join(SYS_ROOT, "revision-cns-v2", "progpilot_v3", "wordfence100_contract_v3.json")
OUT = os.path.join(TS, "results", "wordfence100_ladder_true_v3.json")
TOOLS = ("wisp", "semgrep", "progpilot", "wpt")
RUNGS = ("in_patched_file", "same_callable_as_change", "on_exact_changed_line",
         "within_5_changed_lines", "same_diff_hunk")


def _resolve(slug, z):
    for p in (os.path.join(TS, "plugins", slug, z),
              *glob.glob(os.path.join(TS, "plugins", slug, "**", z), recursive=True)):
        if os.path.isfile(p):
            return p
    return None


def main():
    man = {r["slug"] + "|" + r["cve"]: r for r in json.load(open(MAN))}
    scored = json.load(open(SCORED))["details"]
    per_tool = {t: {r: {"hit": 0, "n": 0} for r in RUNGS} for t in TOOLS}
    # Record-level, class-free success@K. The supplement's external ladder printed this and
    # labelled the +/-5-line proximity rung `hunk@K`, which contract s2 forbids: proximity@5 and
    # same-hunk are different sets. They are separate columns here, and the exact-changed-line
    # rung is present, which the old table had no column for at all.
    KS = (1, 3, 5, 10)
    at_k = {t: {r: {k: 0 for k in KS} for r in RUNGS} for t in TOOLS}
    # Per record, the earliest rank at which each rung is satisfied (null = never). Everything
    # else - success@K, bootstrap intervals, a different K - is derivable from this, so a
    # consumer never has to re-run the geometry to ask a slightly different question.
    first_rank = {t: {r: [] for r in RUNGS} for t in TOOLS}
    record_keys = []
    n_records = 0
    n_ok = n_err = 0
    for rec in scored:
        key = rec["slug"] + "|" + rec["cve"]
        m = man.get(key)
        if not m:
            continue
        vz, pz = _resolve(rec["slug"], m["vuln_zip"]), _resolve(rec["slug"], m["patched_zip"])
        if not (vz and pz):
            n_err += 1
            continue
        try:
            pm = pg.build_patchmap_from_archives({"slug": rec["slug"], "cve": rec["cve"],
                                                  "vuln_zip": vz, "patched_zip": pz})
        except Exception:
            n_err += 1
            continue
        n_ok += 1
        n_records += 1
        record_keys.append(key)
        adv = map_class(rec.get("cls", ""))
        for t in TOOLS:
            best = {r: None for r in RUNGS}      # earliest rank at which each rung is hit
            for f in (rec.get(t, {}).get("findings") or []):
                cls = [map_class(c) for c in (f.get("classes") or [])] or [map_class(f.get("cls", ""))]
                geom = pg.finding_geometry(pm, {"file": f.get("file", ""), "line": int(f.get("line") or 0),
                                                "reported_classes": cls}, adv)
                rank = int(f.get("rank") or 0)
                for r in RUNGS:
                    per_tool[t][r]["n"] += 1
                    if geom.get(r):
                        per_tool[t][r]["hit"] += 1
                        if rank and (best[r] is None or rank < best[r]):
                            best[r] = rank
            # Contract v1 s4 rule 3, at the record level where it is symmetric: a record whose
            # WISP analysis stopped at a bounded approximation earns nothing here, exactly as a
            # record a baseline timed out on earns nothing. Without this the same quantity
            # appears twice in the paper with two values: this ladder said file@1 0.63 while the
            # record-level external table said 0.54.
            failed = bool((rec.get(t) or {}).get("err")) or (
                t == "wisp" and not ((rec.get("wisp") or {}).get("analysis_status") or
                                     {"complete": True}).get("complete", True))
            for r in RUNGS:
                first_rank[t][r].append(None if failed else best[r])
            if failed:
                continue
            for r in RUNGS:
                for k in KS:
                    if best[r] is not None and best[r] <= k:
                        at_k[t][r][k] += 1

    ladder = {}
    for t in TOOLS:
        ladder[t] = {r: (round(per_tool[t][r]["hit"] / per_tool[t][r]["n"], 4) if per_tool[t][r]["n"] else None,
                        per_tool[t][r]["hit"], per_tool[t][r]["n"]) for r in RUNGS}
    ladder_at_k = {t: {r: {str(k): (round(at_k[t][r][k] / n_records, 4) if n_records else None,
                                    at_k[t][r][k], n_records) for k in KS}
                       for r in RUNGS} for t in TOOLS}
    out = {"n_records_scored": n_ok, "n_records_unresolved": n_err,
           "record_level_at_k": ladder_at_k,
           "record_keys": record_keys,
           "first_rank_per_record": first_rank,
           "record_level_note": "class-free success@K over the full record denominator: a record "
                                "counts at K if some finding of rank <= K satisfies the rung. "
                                "proximity@5 and same-hunk are separate rungs.",
           "note": "per-finding geometric rates over the Wordfence shipped findings, scored against "
                   "freshly built PatchMaps (contract v1: deleted files count at file level only). "
                   "on_exact_changed_line is the TRUE exact-line rung (the old 0.21 was proximity/hunk).",
           "rungs": "(rate, hit, n) per tool", "ladder": ladder}
    json.dump(out, open(OUT, "w"), indent=1)
    print(f"scored {n_ok} records ({n_err} unresolved) -> {os.path.relpath(OUT, SYS_ROOT)}")
    for t in ("wisp", "wpt", "semgrep"):
        L = ladder[t]
        print(f"  {t:8} file={L['in_patched_file'][0]}  callable={L['same_callable_as_change'][0]}  "
              f"EXACT={L['on_exact_changed_line'][0]}  prox5={L['within_5_changed_lines'][0]}  "
              f"hunk={L['same_diff_hunk'][0]}")


if __name__ == "__main__":
    _ap = argparse.ArgumentParser(description=__doc__)
    _ap.add_argument("--scored", help="scored four-tool run to read instead of the default")
    _ap.add_argument("--out", help="output path override")
    _a = _ap.parse_args()
    if _a.scored:
        SCORED = os.path.abspath(_a.scored)
    if _a.out:
        OUT = os.path.abspath(_a.out)
    main()
