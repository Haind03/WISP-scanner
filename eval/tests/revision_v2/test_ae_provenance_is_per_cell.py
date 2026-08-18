"""AE. Every result file must say which engine produced it, at the unit that was measured.

The 2026-08-14 reject turned on this. `BASELINE_MATCHED100_V3.json`, `BASELINE_FULL1108_V3.json`
and both matrices carried a single file-level provenance block reading `wisp-scanner-v1.2`, engine
`012279d6`, cap 4, while the manuscript said v1.3, `d07a4bbc`, cap 32. The numbers were in fact
produced by v1.3, and the per-cell files said so, but nothing in the shipped roll-ups let a reviewer
establish that. Their verdict was the right one on the evidence in front of them: a submission that
cannot demonstrate which engine produced its tables has not earned the tables.

Three separate mechanisms caused it and all three are guarded here.

  1. `baseline_matrix_v3` writes the file-level block once, when the matrix is created, and then
     resumes by cell key. Re-measuring the WISP cells left the header describing the first run.
  2. `baseline_rollup_v3` copied that header verbatim into the roll-up, so the stale stamp
     propagated to the artifact a reviewer actually reads.
  3. `TOOL_MANIFEST_V3.json` had its `eval_env_fixed` block typed by hand. By 2026-08-14 it
     contradicted the paper on three points at once, claiming GDA on where the paper disables it and
     class-scoped sanitizer propagation off where both the engine and the manuscript say on, beside
     an engine hash three generations old.

A baseline cell is a special case worth stating: the WISP engine tag is not a property of a Semgrep
result. It is recorded as the harness engine and flagged `applies_to_this_cell: false`, so it reads
as context rather than as a claim.
"""
from __future__ import annotations
import os, json, glob
from ._common import SYS_ROOT, MissingInput

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
ARCHIVED = (".pre-contract-superseded", ".v12-engine", ".pre-membudget", ".with-contaminated",
            ".pre-progpilot-fix", ".NOT-REPORTED", ".CONTAMINATED")
LIVE_MATRICES = [p for p in sorted(glob.glob(os.path.join(OUT, "BASELINE_MATRIX_V3*.json")))
                 if not any(a in os.path.basename(p) for a in ARCHIVED)]
ROLLUPS = ["BASELINE_MATCHED100_V3.json", "BASELINE_FULL1108_V3.json"]


def _load(path):
    if not os.path.isfile(path):
        raise MissingInput(path)
    return json.load(open(path, encoding="utf-8"))


def test_every_matrix_cell_names_the_engine_that_produced_it():
    if not LIVE_MATRICES:
        raise MissingInput("no live BASELINE_MATRIX_V3*.json")
    bad = []
    for p in LIVE_MATRICES:
        m = _load(p)
        for ck, row in (m.get("cells") or {}).items():
            eng = row.get("engine")
            if not eng or not eng.get("engine_tag"):
                bad.append(f"{os.path.basename(p)}:{ck} has no engine block")
            elif "applies_to_this_cell" not in eng:
                bad.append(f"{os.path.basename(p)}:{ck} does not say whether the tag applies to it")
    assert not bad, ("a matrix cell does not record the engine that produced it, so a reader cannot "
                     "tell which engine any given number came from:\n    " + "\n    ".join(bad))


def test_a_baseline_cell_does_not_claim_a_wisp_engine():
    """The WISP engine tag is context for a Semgrep cell, never a property of its result."""
    bad = []
    for p in LIVE_MATRICES:
        for ck, row in (_load(p).get("cells") or {}).items():
            tool = row.get("tool") or ck.split("@")[0]
            eng = row.get("engine") or {}
            if tool != "wisp" and eng.get("applies_to_this_cell"):
                bad.append(f"{os.path.basename(p)}:{ck} is {tool} output but claims the WISP engine "
                           f"applies to it")
            if tool == "wisp" and not eng.get("applies_to_this_cell"):
                bad.append(f"{os.path.basename(p)}:{ck} is WISP output but disclaims its own engine")
    assert not bad, "\n    ".join([""] + bad)


def test_the_rollups_do_not_republish_the_first_run_stamp_as_their_own():
    """The defect a reviewer actually saw: the roll-up's top-level provenance said v1.2."""
    bad = []
    for f in ROLLUPS:
        d = _load(os.path.join(OUT, f))
        if "provenance" in d:
            bad.append(f"{f} still has a bare 'provenance' block; it is the stamp of the run that "
                       f"created the matrix, not of the cells rolled up here, and publishing it "
                       f"unlabelled is what put wisp-scanner-v1.2 on a v1.3 result")
        if not d.get("engine_per_cell"):
            bad.append(f"{f} carries no engine_per_cell, so the engine question is unanswerable "
                       f"from the artifact a reviewer reads")
    assert not bad, "\n    ".join([""] + bad)


def test_the_wisp_cells_of_every_live_artifact_agree_with_the_shipped_engine():
    from eval import wisp_contract as WC
    bad = []
    for f in ROLLUPS:
        d = _load(os.path.join(OUT, f))
        tags = d.get("engines_producing_wisp_cells") or []
        if tags != [WC.ENGINE_TAG]:
            bad.append(f"{f} reports WISP cells produced by {tags}, not [{WC.ENGINE_TAG!r}]")
    for p in LIVE_MATRICES:
        tags = _load(p).get("engines_producing_wisp_cells") or []
        if tags != [WC.ENGINE_TAG]:
            bad.append(f"{os.path.basename(p)} reports WISP cells produced by {tags}, "
                       f"not [{WC.ENGINE_TAG!r}]")
    assert not bad, ("a shipped result was measured on an engine other than the one the paper "
                     "claims:\n    " + "\n    ".join(bad))


def test_the_tool_manifest_reads_its_config_from_the_contract():
    from eval import wisp_contract as WC
    d = _load(os.path.join(OUT, "TOOL_MANIFEST_V3.json"))
    w = (d.get("tools") or {}).get("wisp") or {}
    assert w.get("eval_env_fixed") == WC.CANONICAL_ENV, (
        "TOOL_MANIFEST_V3.json's eval_env_fixed does not equal the evaluation contract. It used to "
        "be a hand-written string and it drifted into claiming GDA on and sanitizer class "
        "propagation off, both the opposite of what the paper and the engine say.\n"
        f"  manifest: {w.get('eval_env_fixed')}\n  contract: {WC.CANONICAL_ENV}")
    assert str(w.get("taint_engine_sha256", "")).startswith(WC.ENGINE_SHA256[:8]), (
        f"TOOL_MANIFEST_V3.json names taint engine {str(w.get('taint_engine_sha256'))[:16]}, the "
        f"shipped engine is {WC.ENGINE_SHA256[:16]}")


def test_old_vs_new_is_derived_from_the_canonical_jsons():
    """The reviewer's second P0. OLD-VS-NEW-RESULTS.csv is the file that answers "what changed since
    the last submission", and its new_value column had drifted onto the previous engine: WISP's top
    rung 0.536 where the paper says 0.550, the bottom rung 0.054 where it says 0.055, and
    non-convergence 272 of 1108 where the shipped census says 8. It also carried 0.7708, a value the
    macro guard bans from the manuscript outright as a superseded headline.

    The old_value column is history and is never regenerated. This checks the derived half."""
    from eval import old_vs_new_v3 as ov
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = ov.main.__wrapped__() if hasattr(ov.main, "__wrapped__") else _check_only(ov)
    out = buf.getvalue()
    assert rc == 0, ("OLD-VS-NEW-RESULTS.csv has derived rows that disagree with the canonical "
                     "JSONs:\n" + out)


def _check_only(ov):
    import sys
    argv = sys.argv[:]
    sys.argv = [argv[0], "--check"]
    try:
        return ov.main()
    finally:
        sys.argv = argv


def test_reproduction_never_passes_a_target_it_did_not_compare():
    """The reviewer's fourth P0. `reproduce_all_v3` used to mark a target REGENERATED when the
    sub-script exited 0 and an output file existed, then count REGENERATED as a pass. Fourteen of
    twenty-seven targets were never compared to anything, and the run still printed REPRODUCTION OK.

    "The script ran" is not "the numbers reproduced"."""
    import re
    from eval import reproduce_all_v3 as rp
    src = open(rp.__file__, encoding="utf-8").read()
    body = src.split("def main(")[-1]
    assert not re.search(r'^\s*\w+\s*=\s*"REGENERATED"', body, re.M), (
        "reproduce_all_v3 still assigns REGENERATED to a target verdict; every target must be "
        "compared to its shipped output by fingerprint")
    assert re.search(r'ok\s*=\s*status\s*==\s*"MATCH"', body), (
        "reproduce_all_v3 does not require MATCH to pass a target")
    assert "def _verify(" in src, "the shared verify helper is gone"
