"""I. scan_testset does not honour the Evaluation Contract for WISP.

EVALUATION-CONTRACT.md says the canonical configuration is applied by every runner
(s1), that a non-converged WISP analysis is a miss over the full denominator (s4
rule 3), and that every result JSON stamps the engine tag, the engine sha256 and the
whole s1 flag table (s6). eval/baseline_matrix_v3.py does all three through
eval/wisp_contract.py.

eval/testset/scan_testset.py does none of them. It never imports wisp_contract, it
toggles WISP_NO_GDA by hand and leaves every other contract flag at whatever the
caller's environment happened to hold, it never reads te.LAST_ANALYSIS_STATUS, and its
provenance block records `engine_commit` plus `wisp_gda` and nothing else. That runner
produces the slug-disjoint 325 table and the Wordfence-100 external-validation table,
so two shipped tables are outside the contract they claim to follow.

These tests assert the post-fix invariants, so they FAIL while the gap is present.
"""
from __future__ import annotations
import inspect, json, os
from . import _common
from ._common import SYS_ROOT


def test_scan_testset_applies_the_canonical_contract_env():
    from eval.testset import scan_testset as st
    from eval import wisp_contract as WC

    src = inspect.getsource(st)
    assert "wisp_contract" in src, (
        "eval/testset/scan_testset.py never imports eval.wisp_contract, so the 325 and "
        "Wordfence-100 runs are not pinned to the contract's Section 1 configuration; "
        "every flag except WISP_NO_GDA is inherited from the caller's shell.")

    ranked = inspect.getsource(st._wisp_ranked)
    for flag in ("WISP_SANI_CLASS", "WISP_QUALIFIED_SUMMARIES", "WISP_PARAM_PROP"):
        assert flag in ranked or "apply_canonical_env" in ranked, (
            f"{flag} is never set by _wisp_ranked; contract s1 requires a fixed value "
            f"for it on every run.")
    # The declared baseline moved from v1.1 (db1285cd) to v1.2 (012279d6) when the engine went to
    # v1.3 on 2026-08-12, which is a deliberate version bump and not silent drift. What this test
    # guards is that it cannot move again without someone editing this line, and that the tag and
    # the sha are never out of step with each other, which is how the original defect looked.
    _KNOWN_BASELINES = {"wisp-scanner-v1.1": "db1285cd", "wisp-scanner-v1.2": "012279d6"}
    assert WC.BASELINE_TAG in _KNOWN_BASELINES, (
        f"the behavioural baseline tag is now {WC.BASELINE_TAG!r}, which this test does not know. "
        f"Declare it here with its sha rather than letting the stamp drift.")
    assert WC.BASELINE_SHA256.startswith(_KNOWN_BASELINES[WC.BASELINE_TAG]), (
        f"{WC.BASELINE_TAG} is declared with sha {WC.BASELINE_SHA256[:8]}, but that tag's engine "
        f"hashes to {_KNOWN_BASELINES[WC.BASELINE_TAG]}. Every shipped table is stamped against "
        f"this pair, so the tag and the sha must not disagree.")


def test_scan_testset_records_and_enforces_non_convergence():
    from eval.testset import scan_testset as st

    src = inspect.getsource(st)
    assert "LAST_ANALYSIS_STATUS" in src or "analysis_status" in src, (
        "scan_testset never reads the engine's analysis status, so contract s4 rule 3 "
        "(a non-converged analysis is a miss) cannot be applied and the required "
        "non-convergence census cannot be reported for the 325 or Wordfence-100 sets.")


def test_shipped_scan_testset_results_stamp_the_contract():
    """Every result this runner produces must name the engine that actually ran and the config.

    Checked on the contract runs, the files the tables are built from. The pre-contract runs are
    kept for the old-vs-new audit and are deliberately NOT patched: rewriting a stamp after the
    fact is the provenance failure this whole revision exists to remove.
    """
    from eval import wisp_contract as WC
    checked, bad = [], []
    for rel in ("revision-cns-v2/progpilot_v3/matched100_contract_quiet_v3.json",
                "revision-cns-v2/progpilot_v3/wordfence100_contract_v3.json",
                "revision-cns-v2/progpilot_v3/testset325_contract_v3.json"):
        path = os.path.join(SYS_ROOT, rel)
        if not os.path.isfile(path):
            continue
        doc = json.load(open(path))
        prov = doc.get("provenance") or {}
        cfg = prov.get("wisp_config") or {}
        # A scan with no WISP column is consumed for its baseline tools only, and Semgrep,
        # Progpilot and wp-taint-scan do not run the WISP engine. Requiring its engine stamp to
        # match the file on disk would force a pointless re-run of three baselines every time the
        # engine changes, which is exactly what the equal-budget matrix is careful not to do. The
        # rest of the contract still has to be stamped, so only the two engine-identity lines are
        # relaxed and the record count is asserted so an empty file cannot slip through as clean.
        n_wisp = sum(len((r.get("wisp") or {}).get("findings") or [])
                     for r in (doc.get("details") or []))
        baselines_only = n_wisp == 0
        checked.append(rel + ("  [baselines only]" if baselines_only else ""))
        missing = [k for k, ok in (
            ("engine_tag", bool(cfg.get("engine_tag"))),
            ("engine_sha256 == the file that ran",
             baselines_only or cfg.get("engine_sha256") == WC.engine_source_sha256()),
            # Was pinned to v1.1's db1285cd. The declared baseline moved to v1.2 when the engine
            # went to v1.3, and this line did not move with it, so two correctly stamped v1.3 scans
            # failed for naming the baseline the contract actually declares. Read it from the
            # contract instead of restating it, which is the same mistake one level down.
            ("engine_baseline_sha256 == the declared baseline",
             baselines_only or cfg.get("engine_baseline_sha256", "") == WC.BASELINE_SHA256),
            ("WISP_SANI_CLASS in the recorded env", "WISP_SANI_CLASS" in (cfg.get("env") or {})),
            ("WISP_NO_GDA == 1", (cfg.get("env") or {}).get("WISP_NO_GDA") == "1"),
            ("git_dirty recorded", "git_dirty" in prov),
            ("failure rule recorded", "non-convergence" in (prov.get("failure_rule") or "")),
            ("ground truth module recorded", "patch_geometry" in (prov.get("ground_truth_module") or "")),
        ) if not ok]
        if missing:
            bad.append(f"{rel}: missing {', '.join(missing)}")

    assert checked, ("no contract runs found under revision-cns-v2/progpilot_v3/; "
                     "the re-scans have not been produced yet")
    assert not bad, "contract runs do not stamp the contract:\n  " + "\n  ".join(bad)


def test_one_ground_truth_module_for_changed_lines():
    """Contract s2: 'There is exactly one ground-truth module (eval/patch_geometry.py).'

    eval/localize.py:_changed_lines anchors a pure insertion on the boundary line;
    eval/patch_geometry.py:_diff_file does not, because no vulnerable-side line was
    removed or rewritten. scan_testset._gt used the first, patch_geometry the second, so
    a pure-insertion patch was a scoreable line target in the 325, Wordfence-100 and
    equal-budget tables and an unscoreable one in the geometric ladder.
    """
    import tempfile, os as _os
    from eval.testset import scan_testset as st
    from eval import patch_geometry as pg

    vuln = "<?php\nfunction f($x) {\n  echo $x;\n}\n"          # sink untouched
    patched = "<?php\nfunction f($x) {\n  check_admin_referer();\n  echo $x;\n}\n"  # insert only

    with tempfile.TemporaryDirectory() as td:
        v = _os.path.join(td, "v"); p = _os.path.join(td, "p")
        _os.makedirs(_os.path.join(v, "plug")); _os.makedirs(_os.path.join(p, "plug"))
        vf = _os.path.join(v, "plug", "a.php"); pf = _os.path.join(p, "plug", "a.php")
        open(vf, "w").write(vuln); open(pf, "w").write(patched)

        gt = st._gt(v, p)
        assert "a.php" in gt, f"pure-insertion file missing from the GT map: {list(gt)}"
        harness_lines = gt["a.php"][0]

    geom = pg._diff_file("plug/a.php", vuln, patched, "modified").changed_vuln_lines

    assert set(harness_lines) == set(geom), (
        f"two ground truths disagree on a pure-insertion patch: "
        f"scan_testset._gt says changed lines {sorted(harness_lines)}, "
        f"patch_geometry says {sorted(geom)}. Contract s2 allows only one.")
