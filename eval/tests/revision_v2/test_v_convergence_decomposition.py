"""V. The v1.3 convergence gain must stay attributable, and a timeout must never pass as an oscillation.

v1.3 flipped two engine defaults at once, the per-key rebuild cap 4 to 32 and the monotone plugin
property table off to on, and corpus non-convergence fell from 272 of 1108 to 8. A joint measurement
cannot say which default did that, and "we changed two things and it got better" is the first thing a
reviewer will refuse. `eval/convergence_decomposition_v3.py` separates them on the matched 100 using
three caches that were all measured before this question was asked, so the answer costs no scan and
cannot have been tuned to come out well.

Two invariants are guarded here.

The first is the attribution itself. If either default alone drove non-convergence to zero, the other
would be unnecessary and the paper would be claiming a change it did not need. The measured answer is
that neither does, so both belong in the version, and this test fails if a rebuild ever makes one of
them redundant without anyone noticing.

The second is narrower and is a defect the decomposition found. The shipped sensitivity cross-tab
reports 12 plugins oscillating at both caps, and `_converged` builds that set by collapsing three
outcomes into two, so a record killed at its budget lands beside records that finished at a bounded
approximation. One of the 12 did exactly that. The manuscript calls all 12 oscillating, which
describes an analysis that ran to a bounded fixpoint and is false of one that never finished. The
number the paper should print is the genuine count, and this test exists so that folding the timeout
back in is a test failure rather than a rounding of the story.

The three-outcome classifier is shared with `convergence_sensitivity_v3` rather than restated, so the
last test here checks the classifier itself on a synthetic record, and checks that the two-way
classifier it replaced would have got that record wrong. A guard that cannot fail proves nothing.
"""
from __future__ import annotations
import os, json
from ._common import REPO, SYS_ROOT, MissingInput

DECOMP = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "CONVERGENCE_DECOMPOSITION_V3.json")
SENS = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "CONVERGENCE_SENSITIVITY_V3.json")
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")


def _load(path: str) -> dict:
    if not os.path.isfile(path):
        raise MissingInput(path)
    return json.load(open(path, encoding="utf-8"))


def test_neither_default_alone_explains_the_convergence_gain():
    d = _load(DECOMP)
    a = d["attribution"]
    assert a["non_converged_A"] > 0, "the v1.2 arm must show the non-convergence there was to fix"
    assert a["non_converged_C"] == 0, (
        f"v1.3 leaves {a['non_converged_C']} non-converged records on the matched 100, so the "
        f"decomposition no longer describes the shipped engine")
    assert a["non_converged_B"] > 0, (
        "raising the per-key cap alone now reaches zero non-convergence, which would make the "
        "monotone property table an unnecessary second change. Re-read the attribution before "
        "shipping a version that flips two defaults when one would do.")
    assert a["rescued_by_cap_alone"] > 0 and a["rescued_by_monotone_after_cap"] > 0, (
        f"one of the two defaults now rescues nothing: cap {a['rescued_by_cap_alone']}, "
        f"property table {a['rescued_by_monotone_after_cap']}. A default that buys nothing should "
        f"not be in the version.")


def test_the_arms_are_paired_by_record_and_not_by_plugin():
    """The matched sample holds two plugins twice, so slug keying silently drops two records."""
    d = _load(DECOMP)
    assert d["n_records"] == 100, f"decomposition covers {d['n_records']} records, expected 100"
    assert d["n_distinct_slugs"] < d["n_records"], (
        "the sample no longer holds a repeated plugin, so this test has stopped proving that record "
        "keying matters. Check the sample before deleting it.")
    keys = [l.strip() for l in open(SAMPLE, encoding="utf-8") if l.strip()]
    slugs = {k.split("|")[0] for k in keys}
    assert len(keys) - len(slugs) == d["n_records"] - d["n_distinct_slugs"], (
        "the decomposition's own record and slug counts disagree with the sample file")


def test_the_oscillating_count_excludes_the_record_that_timed_out():
    d = _load(DECOMP)
    o = d["oscillating_correction"]
    assert o["as_shipped_ConvOscillating"] == o["genuine_oscillation"] + o["timed_out_at_cap32_not_oscillating"], (
        "the oscillating split does not add up to the shipped count")
    assert o["timed_out_at_cap32_not_oscillating"] >= 1, (
        "no timeout is being separated out any more, so either the cap-32 arm was re-measured on a "
        "quiet host or someone folded the timeout back into the oscillating set. If it was "
        "re-measured, update the manuscript's oscillating figure and then relax this test on "
        "purpose, with the new JSON cited.")
    assert o["genuine_oscillation"] < o["as_shipped_ConvOscillating"], (
        "the corrected count equals the shipped count, so the correction has been lost")


def test_the_corpus_headline_needs_no_timeout_separation():
    """272 and 8 may be read as pure non-convergence only because the corpus census is uncapped."""
    d = _load(DECOMP)
    for arm in ("v12", "v13"):
        c = d["corpus"][arm]
        assert c["unknown_timeout"] == 0 and c["error"] == 0, (
            f"the {arm} corpus census now holds {c['unknown_timeout']} timeouts and {c['error']} "
            f"errors, so its non-convergence count is no longer a pure figure and every sentence "
            f"quoting it needs the separation the matched sample needed")
    assert d["corpus"]["v12"]["non_converged"] > d["corpus"]["v13"]["non_converged"]


def test_the_classifier_separates_a_killed_run_from_a_bounded_one():
    """And the two-way classifier it replaced would have got this record wrong."""
    from eval.convergence_sensitivity_v3 import outcome
    killed = {"slug": "x", "cve": "CVE-0000-0", "wisp_converged": False, "wisp_err": "timeout"}
    bounded = {"slug": "y", "cve": "CVE-0000-1", "wisp_converged": False, "wisp_err": ""}
    fine = {"slug": "z", "cve": "CVE-0000-2", "wisp_converged": True, "wisp_err": ""}
    assert outcome(killed) == "unknown_timeout", (
        "a run killed at its budget is being reported as non-convergence, which credits the engine "
        "with a failure it never demonstrated")
    assert outcome(bounded) == "non_converged"
    assert outcome(fine) == "converged"
    naive = lambda r: "converged" if r.get("wisp_converged") else "non_converged"
    assert naive(killed) != outcome(killed), (
        "the two-way classifier now agrees with the three-way one on a killed run, so this test no "
        "longer demonstrates that the distinction is load-bearing")


def test_the_sensitivity_cross_tab_pairs_records_and_not_plugins():
    """The bug this guards read 18 where the answer is 8, and nothing in the output showed it.

    The cap-4 arm was fetched from the corpus census by plugin slug. The census holds 1108 records
    over 854 slugs, so a plugin with several advisories collapsed to whichever record came last, and
    26 of the 100 sample records were then compared against a different advisory of the same plugin.
    The four cross-tab counts survived it because convergence agreed across those advisories, which
    is luck. The top-3 reordering count did not survive it. It reached no macro and appears in
    neither document, so nothing printed was wrong, and that too is luck.
    """
    s = _load(SENS)
    p = s.get("pairing")
    assert p is not None, (
        "CONVERGENCE_SENSITIVITY_V3.json no longer records how it pairs the two arms, so a reader "
        "cannot tell whether the cap-4 record compared against each cap-32 record was the right one")
    assert p["key"] == "slug|cve", (
        f"the cross-tab pairs arms by {p['key']!r}. A plugin can carry several advisories, so any "
        f"key that is not the record identity compares one advisory's analysis against another's.")
    assert p["would_misresolve_under_slug_keying"] > 0, (
        "no sample record would be misresolved by slug keying any more, so this guard has stopped "
        "demonstrating that the record key matters. Confirm the census really did lose its repeated "
        "plugins before relaxing this.")
    assert p["sample_records_with_ambiguous_slug_in_census"] >= p["would_misresolve_under_slug_keying"], (
        "more records are misresolved than have an ambiguous slug, which cannot happen")


def test_the_sensitivity_file_and_the_decomposition_agree_on_the_shipped_count():
    d, s = _load(DECOMP), _load(SENS)
    shipped = s["matched_sample_cross_tab"]["oscillating_non_converged_at_both"]
    assert d["oscillating_correction"]["as_shipped_ConvOscillating"] == shipped, (
        f"the decomposition thinks the shipped oscillating count is "
        f"{d['oscillating_correction']['as_shipped_ConvOscillating']} and "
        f"CONVERGENCE_SENSITIVITY_V3.json says {shipped}. One of them was rebuilt without the other.")
    assert s["matched_sample_cross_tab"]["non_converged_cap4"] == d["attribution"]["non_converged_A"], (
        "the two files disagree about non-convergence at the contract cap")
