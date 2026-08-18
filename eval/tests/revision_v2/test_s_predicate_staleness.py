"""S. A derived count must not outlive the population it was derived from.

`LADDER_PREDICATE_AUDIT_V3.json` holds the three counts the corrected ground-truth prose quotes, and
it is derived from `FINDING_POPULATION_V3.jsonl`. The macro guard cannot protect it. That guard
re-derives every macro from its source JSON and compares, so a stale JSON and the stale macro built
from it agree with each other and the build passes while the paper describes a population that no
longer exists. The only signal is the input being newer than the output.

Two documented paths made this reachable rather than theoretical. `RE-RUN-RUNBOOK.md` section 3
rebuilds the population and then calls the macro builder, and `build_paper_v3.sh` called the macro
builder directly. Both now run the audit first, and the macro builder refuses on a stale input so a
third path added later cannot reintroduce it.

These tests are the reason to believe the refusal works. One proves it fires, one proves it does not
fire on a fresh tree, because a guard that always fires teaches people to bypass it.
"""
from __future__ import annotations
import os, sys, time, json, shutil, tempfile, subprocess
from ._common import REPO, SYS_ROOT, MissingInput

POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
LP = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_PREDICATE_AUDIT_V3.json")


def _require_inputs():
    for p in (POP, LP):
        if not os.path.isfile(p):
            raise MissingInput(p)


def _build_macros():
    return subprocess.run([sys.executable, "-m", "eval.build_paper_macros_v3"],
                          capture_output=True, text=True, cwd=REPO)


def test_macro_build_refuses_a_population_newer_than_its_derived_counts():
    """Touch the population so it is newer, and require the build to stop and name the fix."""
    _require_inputs()
    stamps = (os.path.getatime(POP), os.path.getmtime(POP))
    try:
        now = time.time()
        os.utime(POP, (now, now))
        r = _build_macros()
        out = r.stdout + r.stderr
        assert r.returncode != 0, (
            "the macro build accepted a derived count older than the population it describes, "
            "which the macro guard cannot detect because it compares each macro to that same "
            f"stale JSON:\n{out[-600:]}")
        assert "ladder_predicate_audit_v3" in out, (
            f"the refusal does not name the command that fixes it:\n{out[-600:]}")
    finally:
        os.utime(POP, stamps)


def test_a_fresh_tree_builds():
    """The control. With the shipped files untouched the build must succeed.

    A guard that fires on a clean tree is worse than no guard, because the next person edits it out
    instead of fixing the cause."""
    _require_inputs()
    r = _build_macros()
    assert r.returncode == 0, (
        f"the staleness guard fires on an untouched tree:\n{(r.stdout + r.stderr)[-600:]}")


def test_the_shipped_counts_match_a_recomputation():
    """The counts in the shipped JSON must be what the population actually says.

    The staleness check is about ordering in time. This is about the values themselves, so that a
    JSON which is merely newer than the population cannot pass while holding wrong numbers."""
    _require_inputs()
    rows = [json.loads(l) for l in open(POP, encoding="utf-8") if l.strip()]
    top = [r for r in rows if (r.get("rank") or 10 ** 6) <= 3]
    want = {
        "callable_rung_won_at_top_level": sum(
            1 for r in top if r.get("same_callable_as_change") and r.get("finding_at_top_level")),
        "same_hunk_without_proximity5": sum(
            1 for r in top if r.get("same_diff_hunk") and not r.get("within_5_changed_lines")),
        "proximity5_without_same_hunk": sum(
            1 for r in top if r.get("within_5_changed_lines") and not r.get("same_diff_hunk")),
    }
    got = json.load(open(LP, encoding="utf-8"))
    assert got["n_top_k"] == len(top), f'n_top_k {got["n_top_k"]} != {len(top)}'
    for key, n in want.items():
        assert got[key]["n"] == n, f'{key}: shipped {got[key]["n"]}, population says {n}'
