"""T. Every module that runs the engine for a shipped number must pin the contract, not one flag.

`test_i_scan_testset_contract.py` pins `eval/testset/scan_testset.py` to Contract v1 s1, because that
is where the unpinned-configuration defect was first found. The guard was scoped to that file. The
defect was not.

`eval/localize.py` also runs the engine, and it produced the full-corpus WISP localization cache that
`eval/fullcorpus_failure_as_miss_v3.py` reads through its `wisp_source` glob, which is where 89 of the
paper's macros come from, including the headline corpus class emission quoted eleven times. It set no
flags at all. Its driver, `eval/run_paired_loc.sh`, exported `WISP_NO_GDA=1` and left every other
contract flag to whatever shell happened to run it. Found and fixed 2026-08-12.

So this test does not name the two files that are known to be wrong. It enumerates every module under
`eval/` that imports the engine, and requires each one either to apply the canonical environment or to
be listed below with the reason it does not produce a shipped number. A module added later that runs
the engine and forgets the contract fails here, which is the whole point.
"""
from __future__ import annotations
import os, re
from ._common import REPO

EVAL = os.path.join(REPO, "eval")

# Modules that import the engine but do NOT produce a number any macro or table consumes. Each entry
# carries the reason, so adding one is a claim someone can check rather than a way to silence this.
_NOT_A_PRODUCER = {
    "_wisp_worker.py": "applies it explicitly before importing the engine, checked separately below",
    "selftest_engine.py": "engine unit selftest, fixtures only, no dataset and no shipped number",
    "selftest_gda.py": "same, for the guard-deficit term",
    "measure_convergence.py": "retired 2026-07 probe, superseded by convergence_census_v3",
    "measure_ambiguous_summaries.py": "retired diagnostic, feeds no table",
    "capture_findings.py": "retired cache builder, superseded by produce_train_cap_v3",
    "diagnose_granularity.py": "one-pass diagnostic, feeds no macro",
    "diag_cf1.py": "diagnostic for a single cell, feeds no macro",
    "exact_defect.py": "retired defect-level probe",
    "gda_eval.py": "retired guard-deficit sweep, pre-contract",
    "random_rank.py": "ranking sanity probe, pre-contract",
    "recall.py": "retired recall probe, pre-contract",
    "build_adjudication_v2.py": "retired v2 adjudication builder, unreachable from the pipeline",
    "build_defect_adjudication.py": "builds the unrun defect-level study packet, scans nothing",
    "eval_psabench.py": "external capability probe, reported as indicative only",
    "eval_sastphp.py": "external capability probe, reported as indicative only",
    "eval_stivalet_3way.py": "external capability probe, reported as indicative only",
}

_APPLIES = re.compile(r"apply_canonical_env\s*\(")
_IMPORTS_ENGINE = re.compile(r"from wisp\.engine import .*taint_engine|import wisp\.engine\.taint_engine|"
                             r"from wisp\.engine\.taint_engine import")


def _modules_touching_the_engine():
    out = {}
    for root, _dirs, files in os.walk(EVAL):
        if os.sep + "tests" in root:
            continue
        for f in files:
            if not f.endswith(".py"):
                continue
            p = os.path.join(root, f)
            src = open(p, encoding="utf-8", errors="replace").read()
            if _IMPORTS_ENGINE.search(src):
                out[f] = src
    return out


def test_every_engine_running_module_pins_the_contract_or_says_why_not():
    mods = _modules_touching_the_engine()
    assert mods, "no module under eval/ imports the engine, which cannot be right"
    offenders = []
    for name, src in sorted(mods.items()):
        if _APPLIES.search(src):
            continue
        if name in _NOT_A_PRODUCER:
            continue
        offenders.append(name)
    assert not offenders, (
        "these modules run the engine without applying the contract's canonical environment, so "
        "every flag except any they set by hand comes from the caller's shell:\n  "
        + "\n  ".join(offenders)
        + "\nEither call wisp_contract.apply_canonical_env() before importing the engine, or add "
          "the module to _NOT_A_PRODUCER with the reason it feeds no shipped number.")


def test_localize_applies_it_before_importing_the_engine():
    """Order matters and is easy to get wrong. The engine reads its flags at import time."""
    src = open(os.path.join(EVAL, "localize.py"), encoding="utf-8").read()
    i_apply = src.find("apply_canonical_env(")
    i_engine = src.find("from wisp.engine import")
    assert i_apply != -1, "eval/localize.py does not apply the canonical environment at all"
    assert i_engine != -1, "eval/localize.py no longer imports the engine, so this test is stale"
    assert i_apply < i_engine, (
        "eval/localize.py applies the contract AFTER importing the engine, which is too late: the "
        "engine reads WISP_* at import, so the flags in force would be the caller's shell values")


def test_the_exemption_list_is_not_a_dumping_ground():
    """Every exemption must name a module that exists and must carry a reason."""
    mods = _modules_touching_the_engine()
    stale = [m for m in _NOT_A_PRODUCER if m not in mods]
    assert not stale, (
        "these modules are exempted from the contract check but no longer import the engine, so the "
        f"exemption is stale and hides nothing real: {stale}")
    empty = [m for m, why in _NOT_A_PRODUCER.items() if len(why) < 20]
    assert not empty, f"exemptions without a real reason: {empty}"


# Added 2026-08-13. The two tests above ask whether each module pins the contract. This one asks
# whether the contract pins the engine, which is the same question one level up and went unasked
# until v1.3 made the answer matter. `apply_canonical_env` only touches the keys named in
# CANONICAL_ENV, and the two variables that define v1.3 were not among them, so they resolved to
# whatever the invoking shell had. A shell exporting WISP_PER_KEY_CAP=4 would have produced v1.2
# analysis under a v1.3 stamp, and the stamp would have said so while every other field agreed.
def test_the_contract_pins_the_two_engine_defining_flags():
    from eval import wisp_contract as wc
    for flag in ("WISP_PER_KEY_CAP", "WISP_MONOTONE_PROPS"):
        assert flag in wc.CANONICAL_ENV, (
            f"{flag} is not in CANONICAL_ENV, so apply_canonical_env leaves it as the caller's "
            f"shell set it. This is the flag that decides which engine actually ran.")


def test_the_contract_overrides_a_shell_that_asks_for_v12():
    """And the recovery of v1.2 stays possible as an explicit, recorded override."""
    import os
    from eval import wisp_contract as wc
    keep = {k: os.environ.get(k) for k in ("WISP_PER_KEY_CAP", "WISP_MONOTONE_PROPS")}
    try:
        os.environ["WISP_PER_KEY_CAP"] = "4"
        os.environ["WISP_MONOTONE_PROPS"] = "0"
        wc.apply_canonical_env()
        assert os.environ["WISP_PER_KEY_CAP"] == "32" and os.environ["WISP_MONOTONE_PROPS"] == "1", (
            "a shell asking for the v1.2 configuration survives apply_canonical_env, so a run can be "
            "stamped v1.3 while analysing as v1.2")
        stamp = wc.config_stamp()
        assert stamp["per_key_cap"] == "32" and stamp["monotone_props"] == "1", (
            "the stamp reports the shell's values rather than the contract's")
        wc.apply_canonical_env({"WISP_PER_KEY_CAP": "4", "WISP_MONOTONE_PROPS": "0"})
        assert os.environ["WISP_PER_KEY_CAP"] == "4" and os.environ["WISP_MONOTONE_PROPS"] == "0", (
            "an explicit override can no longer recover v1.2, which the paper needs in order to "
            "show the change is reversible")
    finally:
        for k, v in keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# Added 2026-08-13, same shape as the two above and found the same way. The contract's failure policy
# needs a convergence census, and two consumers named CORPUS_CONVERGENCE_CENSUS_CORRECTED_V3.json in
# their own source. That is the v1.2 census. After the v1.3 adoption eval/auth_split_v3.py rebuilt
# itself against v1.3 localization output while still withholding credit from 272 records that the
# shipped engine converges, and its authorization table moved from 0.6592 to 0.8873 once the census
# matched the engine. Nothing in the output said which census it used.
_CENSUS_MAY_NAME_A_FILE = {
    "convergence_sensitivity_v3.py":
        "it IS the historical cap-4 experiment, so naming the v1.2 census is its subject matter",
    "monotone_diff_v3.py":
        "it compares the two censuses against each other and must name both",
    "convergence_decomposition_v3.py":
        "it reports both engines side by side and names both censuses deliberately",
    "convergence_census_v3.py":
        "it produces a census, so it names the output file it writes",
    "wisp_contract.py":
        "it is the resolver every other module is supposed to ask",
}


def test_no_module_picks_a_convergence_census_by_filename():
    import glob
    bad = []
    for path in sorted(glob.glob(os.path.join(EVAL, "*.py"))):
        name = os.path.basename(path)
        if name in _CENSUS_MAY_NAME_A_FILE:
            continue
        src = open(path, encoding="utf-8").read()
        if "CORPUS_CONVERGENCE_CENSUS" in src:
            bad.append(name)
    assert not bad, (
        f"these modules choose a convergence census by filename instead of asking "
        f"wisp_contract.census_path(): {bad}. A hardcoded census outlives the engine it describes, "
        f"and the failure policy then withholds credit from records the shipped engine converges.")


def test_the_resolver_returns_the_shipped_census_not_the_baseline():
    from eval import wisp_contract as wc
    shipped, baseline = os.path.basename(wc.census_path()), os.path.basename(wc.census_path(True))
    assert shipped != baseline, (
        "census_path() returns the baseline census for the shipped engine, so every consumer of the "
        "failure policy is scoring v1.3 output against v1.2 convergence")
    assert os.path.isfile(wc.census_path()), f"the shipped census {shipped} is not on disk"
