"""X. Every WISP cell in the equal-budget matrix must name the engine the paper claims.

On 2026-08-13 the re-measurement pipeline ran stages 3 and 4, printed `skip wisp@25 (already done)`
five times, exited rc=0 in fifteen seconds, and measured nothing. `eval/baseline_matrix_v3.py`
resumes by cell key, the matrix JSONs on disk held the 2026-08-10 cells measured on
wisp-scanner-v1.2, and the equal-budget table would have shipped inside a v1.3 paper as a v1.2
measurement. Nothing failed. The only evidence was one line of log among a hundred.

The matrix's file-level provenance cannot catch this, and that is the deeper point. It is written
once when the file is created and the file then accumulates cells across runs and across days, so a
matrix holding cells from two engines carries one stamp naming whichever engine happened to be first.
The backup of the stale file proves it: the stamp says 2026-08-03 while the newest cell in it was
written on 2026-08-10.

The per-cell files do carry their own stamp, so the check is possible without changing the format.
Each cell in the matrix records `cell_file`, and each cell file records the engine that produced it.

Two things are asserted. Every WISP cell present must name the shipped engine, which catches a stale
cell surviving a re-run. And the expected budgets must all be present, which catches a matrix that is
merely incomplete. Baseline cells are exempt on purpose: Semgrep, Progpilot and wp-taint-scan do not
run the WISP engine, so an engine tag on their cells would mean nothing, and re-running them for an
engine change would move their numbers onto a different day's host for no reason.
"""
from __future__ import annotations
import os, json
from ._common import REPO, SYS_ROOT, MissingInput

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
MATRICES = {
    "BASELINE_MATRIX_V3.json": (25, 60, 300),
    "BASELINE_MATRIX_V3_full1108.json": (25, 60),
}


def _matrix(name: str) -> dict:
    p = os.path.join(OUT, name)
    if not os.path.isfile(p):
        raise MissingInput(p)
    return json.load(open(p, encoding="utf-8"))


def _shipped_tag() -> str:
    from eval import wisp_contract as wc
    return wc.ENGINE_TAG


def _cell_engine(cell: dict) -> tuple:
    """(engine_tag, engine_sha256) from the cell's own file, or (None, reason)."""
    rel = cell.get("cell_file")
    if not rel:
        return None, "the cell records no cell_file, so its engine cannot be established"
    p = os.path.join(SYS_ROOT, rel)
    if not os.path.isfile(p):
        return None, f"the cell file is missing: {rel}"
    cfg = (json.load(open(p, encoding="utf-8")).get("provenance") or {}).get("wisp_config") or {}
    if not cfg.get("engine_tag"):
        return None, f"the cell file records no engine_tag: {rel}"
    return cfg["engine_tag"], cfg.get("engine_sha256", "")


def test_every_wisp_matrix_cell_names_the_shipped_engine():
    want = _shipped_tag()
    bad = []
    for name in MATRICES:
        m = _matrix(name)
        for key, cell in sorted(m.get("cells", {}).items()):
            if not key.startswith("wisp@"):
                continue
            tag, extra = _cell_engine(cell)
            if tag is None:
                bad.append(f"{name}:{key} {extra}")
            elif tag != want:
                bad.append(f"{name}:{key} was measured on {tag}, the paper claims {want}")
    assert not bad, (
        "equal-budget cells that do not belong to the shipped engine:\n  " + "\n  ".join(bad) +
        "\nbaseline_matrix_v3 resumes by cell key and prints 'skip (already done)', so a stale cell "
        "survives a re-run and the stage still exits zero. Delete the WISP cells and re-measure.")


def test_the_wisp_arm_of_each_matrix_is_complete():
    """A partial matrix is the other way this fails, and it also exits zero."""
    missing = []
    for name, budgets in MATRICES.items():
        cells = _matrix(name).get("cells", {})
        for b in budgets:
            if f"wisp@{b}" not in cells:
                missing.append(f"{name}: wisp@{b}")
    assert not missing, (
        f"the WISP arm is incomplete: {missing}. Every budget the paper prints needs a cell, and a "
        f"missing one silently drops a column rather than failing.")


def test_baseline_cells_are_present_and_left_alone():
    """The exemption has to be real: if the baselines vanished, the table is not a comparison."""
    for name, budgets in MATRICES.items():
        cells = _matrix(name).get("cells", {})
        for tool in ("semgrep", "progpilot", "wpt"):
            got = [b for b in budgets if f"{tool}@{b}" in cells]
            assert got, (
                f"{name} has no {tool} cell at any budget, so the equal-budget comparison has lost "
                f"the arm it compares against. If the baselines were dropped during a WISP re-run, "
                f"restore them from the backup rather than re-measuring them on a different day.")
