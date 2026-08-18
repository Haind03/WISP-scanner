"""Y. A declared experimental arm must survive every import between declaring it and running it.

The engine reads its flags once, at import. So a runner that wants a non-default arm must set the
environment before `wisp.engine.taint_engine` is first imported, and nothing between those two points
may put the canonical values back.

Something did. `eval/localize.py` applies the contract at module scope, which is correct for its own
use and was added on 2026-08-12 to close a real defect: it ran the engine with flags inherited from
whatever shell invoked it. But `eval/testset/scan_testset.py` imports `eval/localize.py`, so any
caller reaching `_wisp_ranked` triggers a second, bare application of the contract. A worker that had
just declared the v1.2 baseline arm had that arm replaced by the canonical values one import later,
and then imported the engine, which read the canonical values.

The consequence was not a crash. The 2026-08-13 engine control ran its two arms twice, on an idle
host, and both times the arms were byte-identical: 3851 findings, one non-converged record, the same
records. The baseline arm had never run. The only visible trace was a config stamp reporting
per_key_cap 32 for a run that had asked for 4, and that stamp was itself wrong for a second reason,
it read the parent process's environment rather than the effective contract.

Both are fixed. A bare `apply_canonical_env()` after an arm has been declared keeps the arm, and
`reset_canonical_env()` is the explicit way back. `config_stamp` reads the effective mapping.

These tests import the engine in subprocesses, because the flags are read once per process and a
test that has already imported the engine cannot observe the thing it is checking.
"""
from __future__ import annotations
import os, sys, json, subprocess
from ._common import REPO

_PROBE = r'''
import os, sys, json
sys.path.insert(0, %r)
from eval import wisp_contract as WC
arm = json.loads(sys.argv[1])
if arm:
    WC.apply_canonical_env(arm)
%s
import wisp.engine.taint_engine as te
print(json.dumps({"cap": te._PER_KEY_UPDATE_CAP, "mono": bool(te._MONOTONE_PROPS),
                  "env_cap": os.environ.get("WISP_PER_KEY_CAP"),
                  "stamp_cap": WC.config_stamp(arm or None)["per_key_cap"]}))
'''


def _probe(arm: dict, middle: str = "") -> dict:
    src = _PROBE % (REPO, middle)
    r = subprocess.run([sys.executable, "-c", src, json.dumps(arm)],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, f"probe failed: {r.stderr[-400:]}"
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_the_engine_default_is_the_shipped_configuration():
    d = _probe({})
    assert (d["cap"], d["mono"]) == (32, True), (
        f"the engine's compiled-in defaults are cap={d['cap']} monotone={d['mono']}, which is not "
        f"the shipped configuration the contract and the paper describe")


def test_a_declared_arm_reaches_the_engine():
    d = _probe({"WISP_PER_KEY_CAP": "4", "WISP_MONOTONE_PROPS": "0"})
    assert (d["cap"], d["mono"]) == (4, False), (
        f"a declared baseline arm did not reach the engine: cap={d['cap']} monotone={d['mono']}. "
        f"An experiment that cannot be requested is an experiment that silently runs the default.")


def test_the_arm_survives_importing_scan_testset():
    """The exact path that broke it: scan_testset imports localize, which reapplies the contract."""
    d = _probe({"WISP_PER_KEY_CAP": "4", "WISP_MONOTONE_PROPS": "0"},
               middle="from eval.testset.scan_testset import _wisp_ranked")
    assert (d["cap"], d["mono"]) == (4, False), (
        f"importing eval.testset.scan_testset cancelled the declared arm: cap={d['cap']} "
        f"monotone={d['mono']}. Some module on that import path applies the contract at module "
        f"scope with no overrides, which turns an import into an experimental decision.")


def test_the_arm_survives_importing_localize_directly():
    d = _probe({"WISP_PER_KEY_CAP": "4"}, middle="import eval.localize")
    assert d["cap"] == 4, (
        f"importing eval.localize cancelled the declared arm, cap={d['cap']}. Its module-level "
        f"pinning is deliberate and must stay, so the contract has to distinguish a bare "
        f"reapplication from a request to return to canonical.")


def test_the_stamp_reports_the_arm_and_not_the_callers_environment():
    """A parent hands an arm to a child and never applies it to itself, so os.environ lies."""
    d = _probe({"WISP_PER_KEY_CAP": "4"})
    assert d["stamp_cap"] == "4", (
        f"config_stamp recorded per_key_cap {d['stamp_cap']} for a run that declared 4. A stamp "
        f"that reports the wrong arm is worse than no stamp, because it is evidence.")


def test_reset_is_explicit_and_still_works():
    src = _PROBE % (REPO, "WC.reset_canonical_env()")
    r = subprocess.run([sys.executable, "-c", src,
                        json.dumps({"WISP_PER_KEY_CAP": "4", "WISP_MONOTONE_PROPS": "0"})],
                       cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
    d = json.loads(r.stdout.strip().splitlines()[-1])
    assert (d["cap"], d["mono"]) == (32, True), (
        f"reset_canonical_env did not return to the canonical configuration: cap={d['cap']} "
        f"monotone={d['mono']}. Without a working reset the sticky arm becomes its own trap.")
