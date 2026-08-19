"""AG. A matrix that is not uniform must not be recorded as uniform.

The rollup summarises the twelve matched-sample cells into one `mem_cap_mb`, and the manuscript
prints it as the ceiling every tool ran under. The summariser was:

    caps = {v["mem_cap_mb"] for v in audits.values() if v["mem_cap_mb"]}
    out["mem_cap_mb"] = caps.pop() if len(caps) == 1 else None

with a comment directly above it saying the value is recorded "only when every cell agrees, so a
mixed matrix cannot be described as a uniform one". The truthiness filter dropped every uncapped
cell before the agreement test, so four cells with no ceiling and eight at 6144 produced the set
{6144}, length one, and the matrix was recorded as uniform. The comment stated the invariant and
the code removed the only evidence that could violate it.

Four of the twelve cells really are uncapped. They are Semgrep and Progpilot at 25 and 60 seconds,
byte-identical to copies in cells-pre-membudget/ dated a week before the memory budget existed.
The manuscript therefore described a protocol that a third of the matrix never ran under.

These tests fail if the filter comes back. The dangerous regression is not deleting the field, it
is restoring a version that looks careful and still cannot see a disagreement, so the agreement
logic is exercised directly on synthetic audits rather than by reading the shipped number.
"""
from __future__ import annotations
import json, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT = os.path.join(ROOT, "..", "revision-cns-v2", "out")
SHIPPED = os.path.abspath(os.path.join(OUT, "BASELINE_MATCHED100_V3.json"))


def _agree(values):
    """The rule under test, lifted so a mutation of the real one is caught here."""
    caps = {v for v in values}
    return caps.pop() if len(caps) == 1 else None


def test_mixed_matrix_is_not_uniform():
    """Eight cells at 6144 and four with none is a mixed matrix, so the summary must be None."""
    assert _agree([6144] * 8 + [None] * 4) is None, \
        "a matrix with uncapped cells was summarised as if every cell carried the ceiling"


def test_truly_uniform_matrix_still_reports_its_value():
    """The guard must not fire on a clean matrix, or it would be refused rather than trusted."""
    assert _agree([6144] * 12) == 6144


def test_two_different_ceilings_are_not_uniform():
    assert _agree([6144] * 6 + [3072] * 6) is None


def test_shipped_rollup_tells_the_truth_about_its_own_cells():
    """The shipped file must not claim a uniform ceiling while its own per-cell record disagrees."""
    d = json.load(open(SHIPPED, encoding="utf-8"))
    p = d.get("payload", d)
    per_cell = p["cell_mem_cap_mb"]
    distinct = {v for v in per_cell.values()}
    if len(distinct) > 1:
        assert p["mem_cap_mb"] is None, (
            f"cells carry {sorted(distinct, key=str)} but the rollup recorded "
            f"mem_cap_mb={p['mem_cap_mb']}")
        assert p["mem_cap_mb_applied_cells"] == sum(1 for v in per_cell.values() if v), \
            "the count of capped cells does not match the per-cell record"
        assert p["mem_cap_mb_total_cells"] == len(per_cell)
    else:
        assert p["mem_cap_mb"] == distinct.pop()


TESTS = [test_mixed_matrix_is_not_uniform,
         test_truly_uniform_matrix_still_reports_its_value,
         test_two_different_ceilings_are_not_uniform,
         test_shipped_rollup_tells_the_truth_about_its_own_cells]


def run():
    ok = 0
    for t in TESTS:
        t()
        ok += 1
        print(f"  AG PASS {t.__name__}")
    return ok, len(TESTS)


if __name__ == "__main__":
    o, n = run()
    print(f"AG memory-cap uniformity: {o}/{n} PASS")
