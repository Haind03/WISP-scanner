"""N. A cell whose records the kernel killed is not a measurement of the tool.

Every number in the equal-budget matrices is a wall-clock verdict under failure-as-miss, so anything
that stops a scan counts against the tool. That rule is correct for a timeout and correct for a
crash, and wrong for an out-of-memory kill, because the kill measures the host. wp-taint-scan is
invoked with `-mem-limit-mb 2048`, so N concurrent workers may ask for N x 2 GB, and on a 15.7 GB
host the kernel starts killing at the budget long enough for processes to actually grow. The 300 s
cells are where that happens, and the damage reads exactly like a weaker engine: fewer records
completed, lower emission, lower patch-file success.

It happened twice and was noticed once. The corpus cell lost 75 of 1108 records at sixteen workers
and was caught. The matched-sample cell lost 4 of 100 at eight and was not, and its numbers shipped.
So the audit belongs in the roll-up, where no number can be produced without passing it, rather than
in a reviewer's attention. These tests pin both ends: the rule must separate host failure from tool
failure, and the shipped cells must satisfy it.
"""
from __future__ import annotations
import os, json, glob
from . import _common as C

from eval.baseline_rollup_v3 import audit_cell, PROFILES

CELL_DIR = os.path.join(C.SYS_ROOT, "revision-cns-v2", "baseline_v3", "cells")
OUT = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out")


def _cell(errs, n=100):
    """A cell of n records whose error strings are given as a count map."""
    det = []
    for err, k in errs.items():
        for _ in range(k):
            det.append({"slug": "s", "cve": "CVE-0000-0000", "err": err, "hit": False,
                        "elapsed": None, "findings": 0, "pf1": 0, "pf3": 0, "pf5": 0, "pf10": 0})
    det += [{"slug": "s", "cve": "CVE-0000-0000", "err": "", "hit": True, "elapsed": 1.0,
             "findings": 1, "pf1": 1, "pf3": 1, "pf5": 1, "pf10": 1}
            for _ in range(n - len(det))]
    return {"details": det}


def test_sigkill_is_refused():
    """One signal-9 record is enough. The kernel killing a scan says nothing about the scanner."""
    a = audit_cell(_cell({"nonzero_exit:-9": 1}), "matched-100", "", "wpt", 300)
    assert not a["clean"], "a cell containing an out-of-memory kill was accepted"
    assert a["host_failures"] == 1, a


def test_ordinary_tool_failures_are_clean():
    """A timeout is the budget doing its job and a non-zero exit is the tool's own verdict.

    A memory-ceiling breach belongs in the same group, and that is the whole point of declaring the
    ceiling: it converts an unattributable kernel kill into a budget the tool was measured against.
    If the audit rejected these it would reject every honest cell, and the failure-as-miss rule
    would have nothing left to score."""
    a = audit_cell(_cell({"timeout": 60, "nonzero_exit:2": 10, "non_converged": 8,
                          "mem_cap_exceeded": 5, "empty_or_invalid_output": 3}),
                   "matched-100", "", "wpt", 300)
    assert a["clean"], f"an ordinary tool failure was mistaken for host failure: {a['problems']}"
    assert a["host_failures"] == 0, a


def test_host_memory_floor_is_refused():
    """The harness catching host pressure must invalidate the cell exactly as a kernel kill does.

    Otherwise the guard would make things worse: it would stop the scan, record the stop as an
    ordinary failure, and produce a cell that looks clean precisely because the guard worked."""
    a = audit_cell(_cell({"host_memory_floor": 1}), "full-1108", "full1108", "wisp", 300)
    assert not a["clean"], "a scan stopped because the host ran out of memory was accepted"
    assert a["host_failures"] == 1, a


def test_archive_error_burst_is_refused_but_a_stray_one_is_not():
    """The threshold has to sit between the two, or it is either useless or unusable.

    A single extraction failure in 1108 is a corrupt archive and appears in clean cells. Thirty
    eight is the memory pressure seen from the other side, and that is the contaminated cell."""
    stray = audit_cell(_cell({"archive_extract_error": 1}, n=1108), "full-1108", "full1108", "wisp", 60)
    burst = audit_cell(_cell({"archive_extract_error": 38}, n=1108), "full-1108", "full1108", "wpt", 300)
    assert stray["clean"], f"a single corrupt archive was treated as contamination: {stray['problems']}"
    assert not burst["clean"], "a burst of extraction failures was accepted"


def _audit_shipped(dataset):
    """Audit every cell the matrix for `dataset` claims to hold. Returns (dirty, missing)."""
    prof = PROFILES[dataset]
    mpath = os.path.join(OUT, prof["matrix"])
    assert os.path.isfile(mpath), f"no matrix at {mpath}"
    cells = json.load(open(mpath))["cells"]
    tag = prof["tag"]
    dirty, missing = [], []
    for ck in sorted(cells):
        tool, budget = ck.split("@")
        f = os.path.join(CELL_DIR, f"{dataset}__{ck}{('__' + tag) if tag else ''}.json")
        if not os.path.isfile(f):
            missing.append(ck); continue
        a = audit_cell(json.load(open(f)), dataset, tag, tool, budget)
        if not a["clean"]:
            dirty.append((ck, a["problems"]))
    return cells, dirty, missing


def test_shipped_matched100_cells_are_clean():
    """RED until the 300 s row is re-measured at a worker count the host can hold."""
    cells, dirty, missing = _audit_shipped("matched-100")
    assert not missing, f"cells claimed by the matrix but absent on disk: {missing}"
    assert not dirty, f"shipped matched-100 cells contaminated by host failure: {dirty}"


def test_shipped_corpus_matrix_is_clean_and_any_missing_row_is_explained():
    """Every reported cell is clean, and a budget that is not reported says why it is not.

    The corpus matrix reports 25 s and 60 s. The 300 s row is absent on purpose: under the declared
    memory ceiling no concurrency measures it on this host without the host itself stopping scans.
    That is a defensible thing to do and an indefensible thing to do quietly, so the test does not
    require a full grid, it requires that an incomplete grid carries its reason in the artifact.
    Deleting the note to make a row disappear turns this test red, which is the point."""
    prof = PROFILES["full-1108"]
    matrix = json.load(open(os.path.join(OUT, prof["matrix"])))
    cells, dirty, missing = _audit_shipped("full-1108")
    assert not missing, f"cells claimed by the matrix but absent on disk: {missing}"
    assert not dirty, f"shipped corpus cells contaminated by host failure: {dirty}"

    budgets = {int(k.split("@")[1]) for k in cells}
    tools = {k.split("@")[0] for k in cells}
    # Whatever budgets are reported, every tool must be present at every one of them. A row with a
    # tool missing is the failure mode this guards against, because the absent tool is always the
    # one that could not be measured, and dropping it silently flatters whoever is left.
    for b in budgets:
        have = {t for t in tools if f"{t}@{b}" in cells}
        assert have == tools, f"budget {b}s reports {sorted(have)} but the matrix has {sorted(tools)}"
    assert len(cells) == len(tools) * len(budgets), (
        f"{len(cells)} cells is not {len(tools)} tools x {len(budgets)} budgets: {sorted(cells)}")

    if budgets != {25, 60, 300}:
        note = matrix.get("reported_budgets_note", "")
        assert len(note) > 80, (
            f"the corpus matrix reports budgets {sorted(budgets)} and carries no explanation for "
            f"the missing one(s); an omitted row must state why in the artifact")
