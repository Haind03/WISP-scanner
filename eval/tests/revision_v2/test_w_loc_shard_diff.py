"""W. v1.3 may change the corpus only where it changed the convergence verdict.

The paper describes v1.3 as a convergence fix rather than a different analysis, and that sentence is
what lets the engine change be adopted mid-revision at all. If v1.3 also moved records that already
converged, the sentence is false and the whole re-measurement is a new experiment rather than a
corrected one.

`eval/monotone_diff_v3.py` checks the claim on the convergence census and can only check it on the
836 records that converge under both engines. `eval/loc_shard_diff_v3.py` checks it on the scored
localization output, the cache 89 macros are built from, across all 1108 records and through a
different code path. The measured answer is that 41 records differ, every one of them rescued from
non-convergence by v1.3, and 223 rescued records did not change at all.

The second test here is about a different worry. The backup shards were written in July by an
`eval/localize.py` that did not pin the Evaluation Contract, so the headline corpus cache rested on
an environment nobody recorded. Records converging under both engines are identical across the two
runs, which means the unpinned July environment agreed with the contract on this corpus. That is
worth guarding, because if a later rebuild makes those records differ, the July numbers were never
reproducible and every claim standing on them needs revisiting.
"""
from __future__ import annotations
import os, json
from ._common import SYS_ROOT, MissingInput

DIFF = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LOC_SHARD_DIFF_V3.json")


def _load() -> dict:
    if not os.path.isfile(DIFF):
        raise MissingInput(DIFF)
    return json.load(open(DIFF, encoding="utf-8"))


def test_no_record_changed_outside_the_set_v13_rescued():
    d = _load()
    assert d["n_changed_outside_the_rescued_set"] == 0, (
        f"v1.3 changed the scored output of {d['n_changed_outside_the_rescued_set']} records it did "
        f"not rescue from non-convergence: {d['changed_outside_the_rescued_set'][:8]}. The paper "
        f"calls v1.3 a convergence fix and that description no longer holds. Either the claim comes "
        f"out of the paper or the engine change does.")
    assert d["verdict"] == "clean"


def test_the_comparison_is_live_rather_than_vacuous():
    """A diff that finds nothing because both sides are the same file proves nothing."""
    d = _load()
    assert d["n_records"] == 1108, f"the shard sets cover {d['n_records']} records, expected 1108"
    assert d["n_changed_any_field"] > 0, (
        "no record differs between the v1.2 and v1.3 shard sets at all, so either the rerun did not "
        "land or the backup was overwritten with a copy of the new set. Check the shards before "
        "reading this as good news.")
    assert 0 < d["n_rescued_by_engine"] < d["n_records"], (
        "the rescued set is empty or is the whole corpus, so the subset test below cannot fail")
    assert d["n_changed_any_field"] < d["n_rescued_by_engine"], (
        f"{d['n_changed_any_field']} records changed but only {d['n_rescued_by_engine']} were "
        f"rescued, which contradicts the subset claim the first test asserts")


def test_the_unpinned_july_environment_agreed_with_the_contract():
    d = _load()
    unchanged_converged = d["n_records"] - d["n_rescued_by_engine"]
    assert unchanged_converged > 0
    assert d["n_changed_outside_the_rescued_set"] == 0, (
        f"records that converged under both engines now differ between the July run and the pinned "
        f"rerun, so the unpinned eval/localize.py did produce output the contract would not have. "
        f"Every number built from the July cache is then unreproducible, not merely unprovenanced.")


def test_most_rescued_records_did_not_move_either():
    """Which is the honest size of the change, and belongs in the paper rather than 264."""
    d = _load()
    assert d["n_rescued_that_did_not_change"] + d["n_changed_any_field"] == d["n_rescued_by_engine"], (
        "the rescued records do not split cleanly into changed and unchanged, so one of the two "
        "counts is measuring something else")
    assert d["n_rescued_that_did_not_change"] > d["n_changed_any_field"], (
        "more rescued records changed their scored output than kept it, which is a much larger "
        "behavioural change than the paper describes and needs saying plainly")
