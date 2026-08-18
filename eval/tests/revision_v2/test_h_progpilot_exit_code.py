"""H. Progpilot findings discarded on a nonzero exit code.

Progpilot writes non-fatal PHP notices to stderr and then exits 1, *while still
printing a complete JSON findings array on stdout*. Two runners in this tree
disagree about what to do with that:

  * eval/fullcorpus_atk.py::_progpilot_ranked_lenient parses stdout regardless of
    the exit code, and is what the full-corpus table and the equal-budget matrix use;
  * eval/testset/scan_testset.py::_progpilot_ranked raises ToolFailure on any
    nonzero exit, and is what the matched-100 ladder, the slug-disjoint 325 and the
    Wordfence-100 table use.

The consequence is not cosmetic. On matched-100 the strict runner threw away 34 of
100 records as `nonzero_exit:1` and the manuscript then reported Progpilot at 0.00
on every rung as if that were a capability result. The Evaluation Contract (s5)
requires one Progpilot run under one cap across every table, so the two runners
must agree.

This test asserts the post-fix invariant, so it FAILS while the bug is present.
"""
from __future__ import annotations
import json, os, subprocess
from . import _common
from ._common import SYS_ROOT, data

PROGPILOT_JSON = json.dumps([
    {"source_name": ["$_GET"], "source_line": [10], "source_file": ["/x/p/a.php"],
     "sink_name": "get_results", "sink_line": 42, "sink_file": "/x/p/a.php",
     "vuln_name": "sql_injection", "vuln_cwe": "CWE_89", "vuln_id": "deadbeef"},
])
# Progpilot's real shape: notices on stderr, findings on stdout, exit code 1.
NOISY_RUN = subprocess.CompletedProcess(
    args=["php", "progpilot.phar", "/x/p"], returncode=1,
    stdout=PROGPILOT_JSON, stderr="PHP Notice:  Undefined index: foo\n")


def _run_both(monkey_result):
    """Call both runners against the same simulated Progpilot process."""
    from eval.testset import scan_testset as st
    from eval import fullcorpus_atk as fc

    cfg = {"progpilot_bin": "progpilot.phar", "timeouts": {"progpilot": 60}}
    real = subprocess.run
    out = {}
    for name, fn, mod in (("strict", st._progpilot_ranked, st),
                          ("lenient", fc._progpilot_ranked_lenient, fc)):
        mod.subprocess.run = lambda *a, **k: monkey_result
        try:
            out[name] = fn("/x/p", cfg)
        except Exception as exc:                      # ToolFailure or anything else
            out[name] = exc
        finally:
            mod.subprocess.run = real
    return out


def test_progpilot_runners_agree_on_nonzero_exit():
    res = _run_both(NOISY_RUN)
    strict, lenient = res["strict"], res["lenient"]

    assert isinstance(lenient, list) and len(lenient) == 1, (
        f"fixture broken: the lenient runner should parse 1 finding, got {lenient!r}")

    assert not isinstance(strict, Exception), (
        f"scan_testset._progpilot_ranked discarded a valid findings array because "
        f"Progpilot exited 1 ({strict!r}); fullcorpus_atk parsed {len(lenient)} finding(s) "
        f"from the same stdout. The matched-100 ladder, the 325 and Wordfence-100 all "
        f"use the strict runner, so Progpilot is scored 0 where it did emit.")

    assert strict == lenient or (
        [(r["file"], r["line"]) for r in strict] ==
        [(r["file"], r["line"]) for r in lenient]), (
        f"the two Progpilot runners parse the same stdout differently: "
        f"strict={strict!r} lenient={lenient!r}")


def test_no_progpilot_record_is_dropped_for_its_exit_code():
    """No shipped per-record result may carry a nonzero_exit Progpilot failure."""
    # The files the current pipeline READS, not every file on disk. The pre-fix runs are kept
    # for the old-vs-new audit and still carry their nonzero_exit records; that is a record of
    # what happened, not a live defect. What must be clean is what the tables are built from.
    checked = []
    for rel in ("revision-cns-v2/progpilot_v3/matched100_contract_quiet_v3.json",
                "revision-cns-v2/progpilot_v3/wordfence100_contract_v3.json",
                "revision-cns-v2/progpilot_v3/testset325_contract_v3.json"):
        path = os.path.join(SYS_ROOT, rel)
        if not os.path.isfile(path):
            continue
        det = json.load(open(path)).get("details") or []
        bad = [r for r in det
               if str(((r.get("progpilot") or {}).get("err") or "")).startswith("nonzero_exit")]
        checked.append((rel, len(det), len(bad)))

    assert checked, ("no contract-run Progpilot result files found; the re-scans under "
                     "revision-cns-v2/progpilot_v3/ have not been produced yet")
    offenders = [c for c in checked if c[2]]
    assert not offenders, (
        "shipped results still drop Progpilot records on the exit code: " +
        "; ".join(f"{rel}: {n}/{tot} records scored nonzero_exit" for rel, tot, n in offenders))
