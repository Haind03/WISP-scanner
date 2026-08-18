#!/usr/bin/env python3
"""Rebuild each matrix cell's engine block from the per-cell file that produced it.

`eval/baseline_matrix_v3.py` writes the file-level `provenance` block once, when the matrix file is
first created, and then resumes by cell key. So re-measuring only the WISP cells on a new engine
leaves the whole file stamped with the engine of whichever run created it first. On 2026-08-10 that
was wisp-scanner-v1.2; the WISP cells were re-measured on v1.3 on 2026-08-13; the header still said
v1.2. A reviewer read the header, compared it against a manuscript that says v1.3, and correctly
refused to accept that the tables were built from the runs the methods section claims.

The information was never lost: every per-cell file carries the provenance of the run that wrote it.
This module reads those files and lifts each cell's engine identity into the matrix, so the matrix
answers the question at the unit that was measured. It changes no metric, and it refuses to write if
a cell's numbers do not match the file it points at.

    python3 -m eval.matrix_provenance_v3            # rewrite in place
    python3 -m eval.matrix_provenance_v3 --check    # exit 2 if any matrix is stale
"""
from __future__ import annotations
import os, sys, json, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")

# metrics that must agree between the matrix row and the per-cell file it names
_CHECK = ("coverage", "patch_file_success_at_1", "class_emission_failure_as_miss")


def _engine_block(cell_path: str, tool: str) -> dict:
    d = json.load(open(cell_path, encoding="utf-8"))
    wc = (d.get("provenance") or {}).get("wisp_config") or {}
    return {"engine_tag": wc.get("engine_tag"),
            "engine_sha256": wc.get("engine_sha256"),
            "per_key_cap": wc.get("per_key_cap"),
            "applies_to_this_cell": (tool == "wisp"),
            "note": ("the engine that produced this cell" if tool == "wisp" else
                     f"harness engine present at run time; this cell is {tool} output and does not "
                     f"depend on it"),
            "measured_utc": (d.get("provenance") or {}).get("timestamp_utc")}


def rebuild(path: str, check_only: bool = False) -> tuple:
    m = json.load(open(path, encoding="utf-8"))
    cells = m.get("cells") or {}
    changed, problems = [], []
    for ck, row in cells.items():
        cf = row.get("cell_file")
        if not cf:
            problems.append(f"{os.path.basename(path)}:{ck} names no cell_file")
            continue
        cp = os.path.join(SYS_ROOT, cf)
        if not os.path.isfile(cp):
            problems.append(f"{os.path.basename(path)}:{ck} points at a missing {cf}")
            continue
        d = json.load(open(cp, encoding="utf-8"))
        for k in _CHECK:
            if k in row and k in d and row[k] != d[k]:
                problems.append(f"{os.path.basename(path)}:{ck} {k}={row[k]} but its cell file "
                                f"says {d[k]}, so the row and the file are different measurements")
        eng = _engine_block(cp, row.get("tool") or ck.split("@")[0])
        if row.get("engine") != eng:
            changed.append(ck)
            if not check_only:
                row["engine"] = eng
    wisp_engines = sorted({(r.get("engine") or {}).get("engine_tag") for r in cells.values()
                           if (r.get("engine") or {}).get("applies_to_this_cell")} - {None})
    note = ("The 'provenance' block is the stamp of the run that FIRST created this file and "
            "describes that run only. Cells added or re-measured later carry their own 'engine' "
            "block, which is authoritative. WISP cells here were produced by: "
            + (", ".join(wisp_engines) if wisp_engines else "no WISP cell in this file")
            + ". Baseline cells carry the harness engine for the record and do not depend on it.")
    if m.get("engines_producing_wisp_cells") != wisp_engines or m.get("provenance_note") != note:
        changed.append("(file header)")
        if not check_only:
            m["engines_producing_wisp_cells"] = wisp_engines
            m["provenance_note"] = note
    if changed and not check_only and not problems:
        json.dump(m, open(path, "w"), indent=1)
    return changed, problems


def main() -> int:
    check = "--check" in sys.argv
    # Only the live matrices. The archived variants (pre-contract-superseded, v12-engine,
    # pre-membudget, with-contaminated-wpt300, pre-progpilot-fix) are kept on purpose as the record
    # of runs the paper does NOT use, and their rows legitimately disagree with today's cell files
    # because they are different measurements. Rewriting them would erase the history they exist for.
    ARCHIVED = (".pre-contract-superseded", ".v12-engine", ".pre-membudget", ".with-contaminated",
                ".pre-progpilot-fix", ".NOT-REPORTED", ".CONTAMINATED")
    paths = [p for p in sorted(glob.glob(os.path.join(OUT, "BASELINE_MATRIX_V3*.json")))
             if not any(a in os.path.basename(p) for a in ARCHIVED)]
    if not paths:
        print("no matrix file found"); return 1
    rc, any_problem = 0, []
    for p in paths:
        changed, problems = rebuild(p, check_only=check)
        any_problem += problems
        name = os.path.basename(p)
        if problems:
            rc = 2
            print(f"{name}: {len(problems)} problem(s)")
            for x in problems:
                print("  x " + x)
        elif changed:
            rc = 2 if check else rc
            print(f"{name}: {'stale' if check else 'updated'} in {len(changed)} place(s): "
                  + ", ".join(changed[:8]) + (" ..." if len(changed) > 8 else ""))
        else:
            print(f"{name}: per-cell engine provenance current")
    if any_problem:
        print("\nrefusing to write: a matrix row disagrees with the cell file it names")
    return rc


if __name__ == "__main__":
    sys.exit(main())
