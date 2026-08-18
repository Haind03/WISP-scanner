#!/usr/bin/env python3
"""Class-agnostic granularity ladder over a fully materialized finding population.

Supersedes eval/ladder.py. Builds a PatchMap per advisory with eval/patch_geometry.py, then scores
every tool finding on geometry that is computed with NO reference to the advisory class. The class
is a separate field, so the geometric ladder and the class-gated ladder are reported side by side
and a class relabel provably cannot move a geometric number.

Outputs:
  * revision-cns-v2/data/FINDING_POPULATION_V3.jsonl  (one line per finding, all fields)
  * <--out> ladder summary JSON (geometric + class rungs per tool, over the top-3 population)

Findings are read from the shipped caches (no re-scan): WISP from train_cap.json, the three CPU
baselines from matched_100_baselines_final.json. PatchMaps come from the corpus archives.

    python3 -m eval.ladder_v3 --out revision-cns-v2/out/LADDER_V3.json
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import defaultdict
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.testset.scan_testset import map_class
from eval import patch_geometry as pg

SYS_ROOT = os.path.dirname(ROOT)
DATA = os.environ.get("WISP_REVISION_DATA") or os.path.join(
    SYS_ROOT, "final", "supplementary-data", "reproduce", "data")
POP_OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")

TOPK = 3
GEOM_RUNGS = ["in_patched_file", "same_diff_hunk", "same_callable_as_change",
              "within_5_changed_lines", "on_exact_changed_line"]
CLASS_RUNGS = ["class_file", "class_callable", "class_exact_line", "class_proximity_5"]
TOOLS = ("wisp", "semgrep", "progpilot", "wpt")


def _normalize_finding(tool: str, rank: int, raw: dict) -> dict:
    """Common finding shape for the population, from each tool's native record."""
    if tool == "wisp":
        classes = [map_class(raw.get("cls", ""))]
        function = raw.get("function", "")
        source = raw.get("source", "")
        sink = raw.get("sink", "")
        message = raw.get("message", "")
        trace = raw.get("trace", []) or []
    else:
        classes = [map_class(c) for c in (raw.get("classes") or [])] or [map_class(raw.get("rule", ""))]
        function = raw.get("function", "")
        source = raw.get("source_file", "") or raw.get("source", "")
        sink = raw.get("rule", "")
        message = raw.get("message", "")
        trace = raw.get("trace", []) or []
    return {"tool": tool, "rank": rank, "file": raw.get("file", ""),
            "line": int(raw.get("line") or 0), "reported_classes": classes,
            "function": function, "message": message, "source": source,
            "sink": sink, "trace": trace}


def _tool_findings(record_key, wisp_rec, baseline_rec):
    """(tool -> list of native finding dicts in rank order) for one record."""
    out = {t: [] for t in TOOLS}
    out["wisp"] = list((wisp_rec or {}).get("findings", []))
    for t in ("semgrep", "progpilot", "wpt"):
        b = (baseline_rec or {}).get(t) or {}
        fs = sorted(b.get("findings") or [], key=lambda x: x.get("rank") or 0)
        out[t] = fs
    return out


def _one(task):
    """Build the PatchMap and score every finding for one record. Returns population rows (without
    the run-scoped finding_uid, assigned in main) plus the patchmap hash."""
    row, wisp_rec, baseline_rec = task
    key = row["slug"] + "|" + row["cve"]
    advisory_class = map_class(row["cls"])
    try:
        pm = pg.build_patchmap_from_archives(row)
    except Exception as exc:
        return {"key": key, "error": f"{type(exc).__name__}: {exc}"}

    nat = _tool_findings(key, wisp_rec, baseline_rec)
    rows = []
    violations = []
    for tool in TOOLS:
        for rank, raw in enumerate(nat[tool], start=1):
            f = _normalize_finding(tool, rank, raw)
            geom = pg.finding_geometry(pm, f, advisory_class)
            bad = pg.validate_nesting(geom)
            if bad:
                violations.append({"key": key, "tool": tool, "rank": rank, "violations": bad})
            rows.append({
                "record_uid": pm.record_uid, "slug": row["slug"], "cve": row["cve"],
                "tool": tool, "rank": rank,
                # Contract v1 s4 rule 3 acts on this. The ladder itself reports the rungs with
                # non-converged records kept (the robustness arm); carrying the flag per finding
                # is what lets the canonical failure-as-miss arm be derived without a re-run.
                "wisp_converged": (None if tool != "wisp"
                                   else bool((wisp_rec or {}).get("wisp_converged", True))),
                "reported_classes": f["reported_classes"], "advisory_class": advisory_class,
                "file": f["file"], "line": f["line"], "function": f["function"],
                "message": f["message"], "source": f["source"], "sink": f["sink"], "trace": f["trace"],
                "norm_path": pg.normalize_path(f["file"]),
                "geom": geom,
                "archive_hashes": {"vulnerable": pm.vulnerable_archive_sha256,
                                   "patched": pm.patched_archive_sha256},
                "patchmap_hash": pm.hash(),
            })
    return {"key": key, "record_uid": pm.record_uid, "rows": rows,
            "violations": violations, "n_findings": len(rows)}


def _rate(pop_rows, rung, tool, topk=None):
    fs = [r for r in pop_rows if r["tool"] == tool and (topk is None or r["rank"] <= topk)]
    if not fs:
        return None, 0
    hit = sum(1 for r in fs if r["geom"].get(rung))
    return round(hit / len(fs), 4), len(fs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_V3.json"))
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--population", default=POP_OUT)
    ap.add_argument("--wisp", default=os.path.join(DATA, "train_cap.json"),
                    help="WISP finding cache (contract run)")
    # NOT matched_100_baselines_final.json, which sits beside this file and is the 2026-07-28
    # PRE-fix scan. It is kept deliberately, because \ProgpilotDiscarded counts the records the
    # exit-code defect threw away and needs the broken run as evidence, but it holds zero Progpilot
    # findings. Building the population from it on 2026-08-13 dropped Progpilot from the population,
    # which dropped it from the paired family, which took the family from 39 comparisons to 26 while
    # everything still exited zero. The manuscript's central negative claim is about Progpilot.
    ap.add_argument("--baselines", default=os.path.join(DATA, "matched_100_baselines_contract.json"),
                    help="scan_testset output holding the three CPU baselines, post-Progpilot-fix")
    a = ap.parse_args()

    wisp = {r["slug"] + "|" + r["cve"]: r for r in json.load(open(a.wisp))}
    baselines = {d["slug"] + "|" + d["cve"]: d
                 for d in json.load(open(a.baselines))["details"]}
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = sorted(k for k in wisp if k in baselines and k in rows)
    print(f"ladder_v3: {len(keys)} matched records")

    tasks = [(rows[k], wisp[k], baselines[k]) for k in keys]
    results = []
    with Pool(a.workers) as pool:
        for i, d in enumerate(pool.imap_unordered(_one, tasks, chunksize=1), 1):
            results.append(d)
            if i % 20 == 0:
                print(f"  ...{i}/{len(keys)}", flush=True)

    errors = [d for d in results if d.get("error")]
    if errors:
        sys.exit(f"{len(errors)} record(s) failed to build a PatchMap: {errors[0]}")
    violations = [v for d in results for v in d.get("violations", [])]
    if violations:
        for v in violations[:10]:
            print("NESTING VIOLATION:", v)
        sys.exit(f"BUILD FAILED: {len(violations)} nesting-invariant violation(s)")

    # deterministic run_uid over the exact record set + a config descriptor
    from eval import patch_geometry as _pg
    cfg = {"wisp_source": os.path.basename(a.wisp),
           "baseline_source": os.path.basename(a.baselines),
           "normalization_version": pg.NORMALIZATION_VERSION, "diff_algorithm": pg.DIFF_ALGORITHM,
           "diff_context": pg.DIFF_CONTEXT, "topk_population": "all"}
    tch = pg.tool_config_hash(cfg)
    record_uids = [d["record_uid"] for d in results]
    ruid = pg.run_uid(tch, record_uids)

    # assign finding_uid with an occurrence index for identical tuples
    occ = defaultdict(int)
    pop = []
    for d in sorted(results, key=lambda x: x["key"]):
        for r in sorted(d["rows"], key=lambda x: (x["tool"], x["rank"], x["norm_path"], x["line"])):
            sig = (r["record_uid"], r["tool"], r["rank"], r["norm_path"], r["line"],
                   ",".join(sorted(r["reported_classes"])))
            oi = occ[sig]; occ[sig] += 1
            r["finding_uid"] = pg.finding_uid(ruid, r["record_uid"], r["tool"], r["rank"],
                                              r["norm_path"], r["line"], r["reported_classes"], oi)
            r["run_uid"] = ruid
            r["tool_config_hash"] = tch
            pop.append(r)

    os.makedirs(os.path.dirname(a.population), exist_ok=True)
    with open(a.population, "w", encoding="utf-8") as fh:
        for r in pop:
            g = r["geom"]
            fh.write(json.dumps({
                "record_uid": r["record_uid"], "finding_uid": r["finding_uid"], "run_uid": r["run_uid"],
                "wisp_converged": r.get("wisp_converged"),
                "slug": r["slug"], "cve": r["cve"], "tool": r["tool"], "rank": r["rank"],
                "reported_classes": r["reported_classes"], "advisory_class": r["advisory_class"],
                "file": r["file"], "line": r["line"], "function": r["function"],
                "message": r["message"], "source": r["source"], "sink": r["sink"], "trace": r["trace"],
                "in_patched_file": g["in_patched_file"],
                "same_callable_as_change": g["same_callable_as_change"],
                "on_exact_changed_line": g["on_exact_changed_line"],
                "distance_to_nearest_changed_line": g["distance_to_nearest_changed_line"],
                "same_diff_hunk": g["same_diff_hunk"],
                "near_insertion_boundary": g["near_insertion_boundary"],
                "within_5_changed_lines": g["within_5_changed_lines"],
                "finding_at_top_level": g["finding_at_top_level"],
                "change_at_top_level": g["change_at_top_level"],
                "class_match": g["class_match"],
                "archive_hashes": r["archive_hashes"], "tool_config_hash": r["tool_config_hash"],
                "patchmap_hash": r["patchmap_hash"],
            }, sort_keys=True) + "\n")

    # ladder summary over the top-3 population (the adjudication unit).
    # The record manifest is the authoritative input set the run_uid is built over. A record that
    # yields zero findings from every tool never appears in the population, so this manifest, not
    # the population, is what lets a re-run prove it covered the identical inputs.
    records_manifest = sorted(d["key"] for d in results)
    summary = {"unit": "one finding from each tool's top-3, matched-100",
               "run_uid": ruid, "tool_config_hash": tch, "n_records": len(results),
               "n_findings_total": len(pop), "config": cfg,
               "record_uids": sorted(record_uids), "records": records_manifest,
               "geometric": {}, "class_gated": {}}
    print(f"\n{'tool':10}{'n(top3)':>8}  " + "".join(f"{r.split('_')[0][:9]:>10}" for r in GEOM_RUNGS))
    for tool in TOOLS:
        grow, crow = {}, {}
        n3 = None
        for rung in GEOM_RUNGS:
            rate, n3 = _rate(pop, rung, tool, TOPK)
            grow[rung] = rate
        for rung in CLASS_RUNGS:
            rate, _ = _rate(pop, rung, tool, TOPK)
            crow[rung] = rate
        summary["geometric"][tool] = {"n_top3": n3, **grow}
        summary["class_gated"][tool] = {"n_top3": n3, **crow}
        if n3:
            print(f"{tool:10}{n3:>8}  " + "".join(f"{(grow[r] if grow[r] is not None else 0):>10.3f}" for r in GEOM_RUNGS))

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(summary, open(a.out, "w"), indent=1)
    print(f"\nwrote population -> {a.population} ({len(pop)} findings)")
    print(f"wrote summary    -> {a.out}")
    print(f"run_uid={ruid}")


if __name__ == "__main__":
    main()
