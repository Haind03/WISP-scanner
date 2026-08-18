"""R. The old-versus-new audit for WISP_MONOTONE_PROPS has to be able to fail.

`eval/monotone_diff_v3.py` is the evidence that the accumulating property table is a convergence fix
and not a different analysis. Its whole value is the stability half: every record that converged
before must report the same findings after. An audit that cannot report a disagreement is not
evidence of agreement, and this project has already shipped one guard that passed twice while the
defect it was meant to catch was live, because the guard was scoped to a place the bug had left.

So these tests feed the audit censuses that disagree in each of the ways that matter, and require it
to say so and to exit non-zero. They also feed it the two real serialisations, because the baseline
census on disk names a finding's class `cls` and its sink `sink` while a fresh census names them
`classes` and `rule`. Comparing those raw would report all 1108 records as changed, which is a false
alarm loud enough to get the audit ignored.
"""
from __future__ import annotations
import os, sys, json, tempfile, subprocess
from ._common import REPO


def _census(records, engine_env=None):
    return {"schema_version": "convergence-census-v3",
            "engine_env_overrides": engine_env or {},
            "summary": {}, "records": records}


def _rec(slug, cve, converged, findings, err=""):
    return {"slug": slug, "cve": cve, "cls": "xss", "wisp_err": err,
            "wisp_converged": converged, "wisp_n_findings": len(findings),
            "findings": findings}


def _old_finding(file, line, cls, sink):
    """The baseline census serialisation, as it sits on disk today."""
    return {"file": file, "line": line, "cls": cls, "sink": sink, "conf": 0.5, "ep": "ajax"}


def _new_finding(file, line, cls, rule):
    """The serialisation a fresh census writes, straight out of the scanner."""
    return {"file": file, "line": line, "classes": [cls], "rule": rule,
            "confidence": 0.5, "entry_point": "ajax"}


def _run(base_recs, new_recs):
    with tempfile.TemporaryDirectory() as d:
        bp, np_, op = (os.path.join(d, n) for n in ("base.json", "new.json", "out.json"))
        json.dump(_census(base_recs), open(bp, "w"))
        json.dump(_census(new_recs, {"WISP_MONOTONE_PROPS": "1"}), open(np_, "w"))
        r = subprocess.run([sys.executable, "-m", "eval.monotone_diff_v3",
                            "--base", bp, "--new", np_, "--out", op],
                           capture_output=True, text=True, cwd=REPO)
        res = json.load(open(op)) if os.path.exists(op) else None
        return r.returncode, res, r.stdout + r.stderr


def test_a_clean_case_is_reported_clean():
    """A record that converged before and after, with the same findings, is not a change.

    This is the control. If it fails, every other test here is meaningless because the audit calls
    everything dirty."""
    old = [_old_finding("a.php", 10, "xss", "echo")]
    new = [_new_finding("a.php", 10, "xss", "echo")]
    rc, res, log = _run([_rec("p", "CVE-1", True, old)], [_rec("p", "CVE-1", True, new)])
    assert rc == 0, f"the audit called an unchanged record a change: {log}"
    assert res["stability_check"]["verdict"] == "clean", res["stability_check"]
    assert res["stability_check"]["n_with_same_count_different_findings"] == 0, (
        "the two serialisations were compared raw, so identical findings read as different: "
        f"{res['same_count_different_findings']}")


def test_b_a_changed_finding_count_on_a_stable_record_fails_the_audit():
    """The failure the audit exists to catch. A record that already converged gains a finding."""
    old = [_old_finding("a.php", 10, "xss", "echo")]
    new = [_new_finding("a.php", 10, "xss", "echo"), _new_finding("b.php", 3, "sqli", "query")]
    rc, res, log = _run([_rec("p", "CVE-1", True, old)], [_rec("p", "CVE-1", True, new)])
    assert rc == 1, f"the audit passed a record that changed its finding count: {log}"
    assert res["stability_check"]["n_with_changed_finding_count"] == 1, res["stability_check"]
    assert res["stability_check"]["verdict"] != "clean"


def test_c_same_count_but_different_findings_still_fails():
    """The quieter failure. The count holds while one finding is swapped for another.

    A count-only check would wave this through, and a swapped finding is exactly what the reviewer's
    objection predicts: a property that a sanitizer cleans is resurrected somewhere else."""
    old = [_old_finding("a.php", 10, "xss", "echo")]
    new = [_new_finding("a.php", 99, "xss", "echo")]
    rc, res, log = _run([_rec("p", "CVE-1", True, old)], [_rec("p", "CVE-1", True, new)])
    assert rc == 1, f"the audit passed a swapped finding because the count held: {log}"
    assert res["stability_check"]["n_with_same_count_different_findings"] == 1, (
        res["stability_check"])


def test_d_a_lost_convergence_fails_the_audit():
    """The change must not cost convergence anywhere, and losing it must not read as a rescue."""
    f_old = [_old_finding("a.php", 10, "xss", "echo")]
    f_new = [_new_finding("a.php", 10, "xss", "echo")]
    rc, res, log = _run([_rec("p", "CVE-1", True, f_old)], [_rec("p", "CVE-1", False, f_new)])
    assert rc == 1, f"the audit passed a record that stopped converging: {log}"
    assert res["convergence"]["lost"] == 1, res["convergence"]
    assert res["convergence"]["rescued"] == 0, res["convergence"]


def test_e_a_rescue_is_not_counted_as_an_instability():
    """The wanted outcome. A non-converged record converges and may legitimately report more.

    If this fails the audit is unusable, because the whole point of the change is that these records
    change."""
    old = [_old_finding("a.php", 10, "xss", "echo")]
    new = [_new_finding("a.php", 10, "xss", "echo"), _new_finding("b.php", 3, "sqli", "query")]
    rc, res, log = _run([_rec("p", "CVE-1", False, old)], [_rec("p", "CVE-1", True, new)])
    assert rc == 0, f"the audit read a rescued record as an instability: {log}"
    assert res["convergence"]["rescued"] == 1, res["convergence"]
    assert res["stability_check"]["n_records_converged_in_both"] == 0, res["stability_check"]


def test_f_a_record_with_no_stored_findings_is_not_read_as_an_empty_result():
    """120 baseline records carry a count but no findings, because a merge folded them in.

    Treating a missing list as an empty result would report a fabricated disagreement on every one
    of them. The count still has to be compared, so the guard is on the identity check only."""
    new = [_new_finding("a.php", 10, "xss", "echo")]
    base = _rec("p", "CVE-1", True, [])
    base["wisp_n_findings"] = 1              # counted, findings not stored
    rc, res, log = _run([base], [_rec("p", "CVE-1", True, new)])
    assert rc == 0, f"a record with unstored findings was reported as changed: {log}"
    assert res["stability_check"]["n_with_same_count_different_findings"] == 0, (
        res["same_count_different_findings"])
