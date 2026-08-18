"""D. Timeout provenance mismatch.

The manuscript reports Progpilot at a "25 s suggested cap" and claims the matched
result is invariant "at 25 s and at 60 s". But the scored artifact
`matched_100_baselines_final.json`, which feeds the ladder / localization tables,
records progpilot's timeout as 60 s and was run only once. No 25 s run backs the
invariance claim, and the headline cap the paper states (25 s) is not the cap the
numbers were produced under (60 s).

Desired invariant: the Progpilot cap the manuscript states must equal the cap the runs
recorded. Neither side is hard-coded here. The manuscript's figure is read from the macro it
now prints, and the run's figure from the contract run's provenance, so this checks the
property rather than a copy of it: an earlier version of this test carried the literal 25 and
would have had to be edited by hand every time either side legitimately changed.
"""
from __future__ import annotations
import json, os, re
from ._common import data, Evidence, SYS_ROOT

MACROS = os.path.join(SYS_ROOT, "2026-07-07", "latex", "PAPER_MACROS_V3.tex")
CONTRACT_RUNS = ("testset325_contract_v3.json", "wordfence100_contract_v3.json",
                 "matched100_contract_quiet_v3.json")


def _manuscript_cap():
    """The Progpilot cap the manuscript prints, via the macro it prints it with."""
    if not os.path.isfile(MACROS):
        return None
    m = re.search(r"\\newcommand\{\\CapProgpilot\}\{(\d+)\}",
                  open(MACROS, encoding="utf-8").read())
    return int(m.group(1)) if m else None


def _contract_run_cap():
    for name in CONTRACT_RUNS:
        p = os.path.join(SYS_ROOT, "revision-cns-v2", "progpilot_v3", name)
        if os.path.isfile(p):
            prov = json.load(open(p)).get("provenance") or {}
            return _effective_progpilot_timeout(prov)[0], name
    return None, None


def _effective_progpilot_timeout(prov: dict):
    """Prefer an explicit --progpilot-timeout flag in the command; else the
    timeouts_seconds table the harness recorded."""
    cmd = prov.get("command") or []
    if isinstance(cmd, list):
        for i, tok in enumerate(cmd):
            if tok == "--progpilot-timeout" and i + 1 < len(cmd):
                return int(cmd[i + 1]), "command flag"
    ts = prov.get("timeouts_seconds") or {}
    if "progpilot" in ts:
        return int(ts["progpilot"]), "timeouts_seconds"
    return None, "absent"


def test_progpilot_timeout_matches_manuscript():
    ev = Evidence("D. timeout provenance mismatch")
    run_cap, run_name = _contract_run_cap()
    stated = _manuscript_cap()
    ev.show(f"contract run {run_name}: Progpilot cap = {run_cap} s")
    ev.show(f"manuscript prints Progpilot cap = {stated} s (via \\CapProgpilot)")

    assert run_cap is not None, "no contract run found to read a Progpilot cap from"
    assert stated is not None, (
        "the manuscript does not print the Progpilot cap through a macro, so the stated cap "
        "and the cap that ran can drift again")
    assert stated == run_cap, (
        f"BUG D: the numbers were produced with a {run_cap} s Progpilot cap but the manuscript "
        f"states {stated} s")


if __name__ == "__main__":
    test_progpilot_timeout_matches_manuscript()
