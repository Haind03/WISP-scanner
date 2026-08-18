#!/usr/bin/env python3
"""The single source of truth for the WISP Evaluation Contract v1.

Every runner (the equal-budget matrix, the test-set scanner, the ladder generator) imports the
canonical configuration and the failure policy from here, so no two tables can be produced under
different settings. See revision-cns-v2/EVALUATION-CONTRACT.md for the rationale.

Nothing in this module runs a scanner; it only fixes environment values and defines the failure rule.
"""
from __future__ import annotations
import os

# ---- canonical engine identity ------------------------------------------------------------------
# ENGINE_SHA256 used to be a bare constant that every result JSON copied into its
# provenance without anyone comparing it to the file on disk. An edit to the engine
# therefore kept stamping the old sha while running something else, which is the exact
# dirty-provenance failure the contract exists to prevent. The stamp now carries BOTH the
# behavioural baseline and the sha of the file that actually ran, and engine_matches_baseline
# says plainly whether they are the same bytes.
#
# wisp-scanner-v1.2 differed from v1.1 in one inert hook: the per-definition rebuild cap was
# read from WISP_PER_KEY_CAP, defaulting to 4. With that variable unset both the per-key cap
# and the global bound max(64, |definitions| * 4) were exactly v1.1's, so results were
# comparable across those two tags.
#
# wisp-scanner-v1.3 is NOT behaviour-preserving and is not claimed to be. It changes two defaults:
# the plugin-wide property table is no longer cleared on every outer round, and the per-definition
# rebuild cap is 32 rather than 4. Together they take corpus non-convergence from 272 of 1108 to 8.
# The reason this is a version bump and not a silent fix is that non-convergence is a miss under the
# contract's failure policy, so results move even though the analysis does not.
#
# What did NOT change is pinned by measurement, not by assertion. On the 836 records that converge
# under both v1.2 and v1.3, finding counts and finding identities are unchanged and the totals are
# 39,033 against 39,033. The comparison is revision-cns-v2/out/MONOTONE_PROPS_DIFF_V3.json, produced
# by eval/monotone_diff_v3.py, which exits non-zero on any instability.
#
# v1.2 behaviour is recoverable with WISP_MONOTONE_PROPS=0 and WISP_PER_KEY_CAP=4.
# Four different things, kept apart on purpose. The first two are PROVENANCE: they are the build
# labels the result JSONs stamped when each run happened, and the regression suite binds shipped
# results to them, so repurposing either one silently decouples the guard from what it guards. An
# earlier attempt set ENGINE_TAG to the release name and four tests caught it, which is the suite
# working.
ENGINE_TAG = "wisp-scanner-v1.3"        # build label stamped in every run manifest
BASELINE_TAG = "wisp-scanner-v1.2"      # build label of the convergence ablation's baseline arm
# The third is the PUBLISHED name. The repository releases one engine and a later paper goes to
# v1.1, so the release name is not the development build label and is not stamped in any result.
RELEASE_TAG = "wisp-scanner-v1.0"
# The fourth is what the baseline arm actually was: a configuration of the one engine, produced by
# setting these two variables, not an older release anyone checked out. The paper names the
# configuration rather than a tag, because that is what was run and it stays checkable from the
# single released version.
BASELINE_CONFIG = "WISP_PER_KEY_CAP=4 WISP_MONOTONE_PROPS=0"
BASELINE_SHA256 = "012279d6c67e9454075b139d7231b0853c10d7a3845233c86b1565e30d039b1a"

_ENGINE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "wisp", "engine", "taint_engine.py")


# ---- which convergence census describes the engine that ran -------------------------------------
# The contract's failure policy zeroes non-converged records, so every consumer of that policy needs
# a census, and until 2026-08-13 two of them named CORPUS_CONVERGENCE_CENSUS_CORRECTED_V3.json
# directly. That file is the v1.2 census. After the v1.3 adoption it reports 272 non-converged
# records where the shipped engine has 8, so eval/auth_split_v3.py rebuilt itself against v1.3
# localization output while still withholding credit from 272 records, and the numbers it printed
# belonged to neither engine. Naming a census by filename is the defect. Ask for the one that matches
# the engine instead.
_CENSUS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                           "revision-cns-v2", "out")
CENSUS_SHIPPED = "CORPUS_CONVERGENCE_CENSUS_MONOTONE_V3.json"     # wisp-scanner-v1.3
CENSUS_BASELINE = "CORPUS_CONVERGENCE_CENSUS_CORRECTED_V3.json"   # wisp-scanner-v1.2


def census_path(baseline: bool = False) -> str:
    """Path to the convergence census for the shipped engine, or for the declared baseline.

    Falls back to the baseline census only when the shipped one is absent, which is the case when
    running from a bundle that ships one census. A caller that needs to know which it got should
    read the returned basename rather than assume."""
    want = CENSUS_BASELINE if baseline else CENSUS_SHIPPED
    p = os.path.join(_CENSUS_DIR, want)
    if os.path.isfile(p) or baseline:
        return p
    # Substituting the previous engine's census is a different measurement, not a graceful
    # degradation. It was silent until 2026-08-14, and the submission bundle shipped only the
    # baseline census, so a reviewer running the shipped kit recomputed the full-corpus contract
    # tables against v1.2 convergence and got numbers the paper does not report. The reproduction
    # said REGENERATED and passed. Say it loudly instead: stderr for a human, and an env marker any
    # caller can promote to a hard failure.
    import sys as _sys
    os.environ["WISP_CENSUS_FELL_BACK"] = CENSUS_BASELINE
    print(f"WARNING: {want} is absent, falling back to {CENSUS_BASELINE}. That census describes "
          f"a different engine, so anything computed from it is not comparable to the shipped "
          f"results.", file=_sys.stderr)
    return os.path.join(_CENSUS_DIR, CENSUS_BASELINE)


def engine_source_sha256(path: str = _ENGINE_FILE) -> str:
    import hashlib
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return ""


# The sha of the engine that will actually run in this process.
ENGINE_SHA256 = engine_source_sha256()

# ---- canonical environment (Evaluation Contract v1, Section 1) -----------------------------------
# A value of None means "unset" (the harness removes the variable so the engine default applies).
CANONICAL_ENV: dict[str, str | None] = {
    "WISP_NO_GDA": "1",              # [AUTHOR] guard-deficit ranking term OFF
    "WISP_SANI_CLASS": "1",          # class-scoped sanitizer propagation ON (engine default)
    "WISP_QUALIFIED_SUMMARIES": "1",
    "WISP_PARAM_PROP": "1",
    "WISP_RECEIVER_GUARD": "0",
    "WISP_GUARD_ORDER": "0",
    "WISP_NO_RANK": None,            # ranking ON, default flow/guard weights
    "WISP_RANK_WFLOW": "1.0",
    "WISP_RANK_WGUARD": "0.5",
    "WISP_RANK_WGUARD_CENTER": "0.0",
    # The two knobs that define v1.3. They were left out until 2026-08-13 on the reasoning that the
    # engine's compiled-in defaults already carry the right values, which is true and is not the
    # point. apply_canonical_env only touches the keys named here, so anything it does not name is
    # inherited from whatever shell invoked the run. That is the same unpinned-configuration defect
    # test_i and test_t were written for, sitting one level up in the contract itself, and on the two
    # variables that decide the analysis. Naming them changes no value, both already resolve to these
    # strings, and it makes the resolution the contract's rather than the caller's.
    "WISP_PER_KEY_CAP": "32",
    "WISP_MONOTONE_PROPS": "1",
    # the LLM verifier is never enabled here (no --verify anywhere in the eval path)
}

# named sensitivity variants the contract requires reporting alongside the canonical run
SENSITIVITY_VARIANTS: dict[str, dict[str, str | None]] = {
    "gda_on": {"WISP_NO_GDA": None},        # guard-deficit ranking term ON
    "sani_off": {"WISP_SANI_CLASS": "0"},   # sanitizer class propagation OFF
}


# The overrides in force once the contract has been applied in this process, or None before that.
# It exists because of a specific failure. eval/localize.py applies the contract at module scope,
# which it must, since the engine reads its flags at import and localize imports the engine. But
# eval/testset/scan_testset.py imports eval/localize.py, so ANY caller of scan_testset triggers a
# second, bare application. A worker that had just declared an arm, say the v1.2 baseline, had that
# arm silently replaced by the canonical values one import later, and then imported the engine. The
# 2026-08-13 engine control ran its two arms that way and produced byte-identical results twice
# before anyone noticed the baseline arm had never run.
_APPLIED: dict | None = None


def apply_canonical_env(overrides: dict | None = None) -> dict:
    """Set process env to the canonical contract, optionally with a declared override, and return
    the effective {flag: value} mapping so a runner can record it in its provenance stamp.

    A bare call after an arm has been declared keeps the arm. Import side effects must not cancel an
    experiment. To go back to the canonical configuration on purpose, call reset_canonical_env().
    """
    global _APPLIED
    if overrides:
        _APPLIED = dict(overrides)
    elif _APPLIED:
        overrides = _APPLIED
    else:
        _APPLIED = {}
    effective = dict(CANONICAL_ENV)
    if overrides:
        effective.update(overrides)
    for k, v in effective.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return {k: (v if v is not None else "unset") for k, v in effective.items()}


def reset_canonical_env() -> dict:
    """Drop any declared arm and return to the canonical contract. The explicit form of what a bare
    apply_canonical_env() used to do by accident."""
    global _APPLIED
    _APPLIED = None
    return apply_canonical_env()


def config_stamp(overrides: dict | None = None) -> dict:
    """A provenance stamp naming the engine and the exact config every result JSON must carry."""
    eff = dict(CANONICAL_ENV)
    if overrides:
        eff.update(overrides)
    actual = engine_source_sha256()
    return {"engine_tag": ENGINE_TAG,
            "engine_sha256": actual,
            "engine_source_sha256": actual,
            "engine_baseline_config": BASELINE_CONFIG,
            "engine_baseline_tag": BASELINE_CONFIG,
            "engine_baseline_sha256": BASELINE_SHA256,
            "engine_matches_baseline": actual == BASELINE_SHA256,
            "engine_baseline_relation":
                "identical bytes" if actual == BASELINE_SHA256 else
                "the released engine changes two defaults against the baseline configuration, an "
                "accumulating plugin property table and a per-definition rebuild cap of 32, so it is "
                "not behaviour-preserving and does not claim to be. Corpus non-convergence falls from 272 of 1108 to 8. On the 836 records "
                "that converge under both, findings are identical and total 39,033 either way "
                "(revision-cns-v2/out/MONOTONE_PROPS_DIFF_V3.json, eval/monotone_diff_v3.py). "
                "WISP_MONOTONE_PROPS=0 with WISP_PER_KEY_CAP=4 recovers v1.2.",
            # From the effective contract, not from this process's environment. A parent that hands
            # an arm to a child subprocess never applies that arm to itself, so reading os.environ
            # here stamped the parent's canonical values onto the child's declared arm: the
            # 2026-08-13 baseline control recorded per_key_cap 32 while asking for 4.
            "per_key_cap": eff.get("WISP_PER_KEY_CAP", "32"),
            "monotone_props": eff.get("WISP_MONOTONE_PROPS", "1"),
            "llm_verify": "disabled",
            "env": {k: (v if v is not None else "unset") for k, v in eff.items()},
            "contract": "EVALUATION-CONTRACT.md v1"}


# ---- failure policy (Evaluation Contract v1, Section 4) ------------------------------------------
def worker_miss_reason(worker_result: dict) -> str | None:
    """The one failure-as-miss rule for a WISP worker result. Returns a short reason string when the
    record is a miss (timeout is handled by the parent before this), else None.

    A record is a miss if the worker did not finish cleanly, or if the analysis did not converge
    (a per-key or global stabilization cap fired), because a capped summary table is a conservative
    approximation, not a clean success."""
    if not worker_result.get("ok"):
        return worker_result.get("error", "wisp_error")
    status = worker_result.get("analysis_status") or {}
    if status.get("complete") is False:
        return "non_converged"
    return None
