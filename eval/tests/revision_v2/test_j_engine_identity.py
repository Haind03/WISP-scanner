"""J. The engine on disk must be the engine every shipped table is stamped with.

The original defect: `eval/wisp_contract.py` hard-coded the sha of `wisp/engine/taint_engine.py` at
tag wisp-scanner-v1.1, every result JSON copied that constant into its provenance, and the constant
was never checked against the file. So an edit to the engine kept stamping v1.1 while running
something else. That happened once already.

Through v1.2 the rule had two halves: the stamp must name the file that ran, and any accepted build
must be behaviourally identical to v1.1 with the difference confined to plumbing that is inert unless
a sensitivity variable is set.

**v1.3 breaks the second half deliberately, and that is why this file changed.** It turns on an
accumulating plugin property table and raises the per-definition rebuild cap from 4 to 32, which
takes corpus non-convergence from 272 of 1108 to 8. Non-convergence is a miss under the contract's
failure policy, so shipped numbers move even though no analysis rule changed. The wrong response to a
red identity test is to relax it until it passes. The right response is to state the new version, say
what it does not preserve, and pin the things that must still hold:

  * the stamp still names the file that actually ran,
  * the contract declares v1.2 as the baseline and does NOT claim behaviour preservation,
  * the two v1.3 defaults are recoverable, so the sensitivity arm the contract asks for is real,
  * with those variables set back, the global update bound is exactly v1.1's expression, and
  * the claim that v1.3 leaves already-converging records alone is backed by a stored 1108-record
    comparison rather than by this docstring.

That last test is the one that matters. Everything else here is bookkeeping.
"""
from __future__ import annotations
import hashlib, json, os, re, subprocess
from . import _common
from ._common import REPO, SYS_ROOT, MissingInput

ENGINE = os.path.join(REPO, "wisp", "engine", "taint_engine.py")
V11_SHA = "db1285cd2ab41ee0b4340266fb46c68f7ea3427fa39ddc31fc5e538747cd13ee"
V12_SHA = "012279d6c67e9454075b139d7231b0853c10d7a3845233c86b1565e30d039b1a"
V12_COMMIT = "71fd3c8"
DIFF_JSON = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "MONOTONE_PROPS_DIFF_V3.json")


def _sha(text: bytes) -> str:
    return hashlib.sha256(text).hexdigest()


def _source_at(commit: str) -> bytes | None:
    try:
        return subprocess.check_output(
            ["git", "show", f"{commit}:wisp/engine/taint_engine.py"], cwd=REPO,
            stderr=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None


def test_contract_stamps_the_engine_that_actually_ran():
    """Unchanged from v1.2. This is the test the original defect defeated."""
    from eval import wisp_contract as WC
    on_disk = _sha(open(ENGINE, "rb").read())
    stamp = WC.config_stamp()
    assert stamp.get("engine_source_sha256") == on_disk, (
        f"the contract stamp does not record the engine file that ran: "
        f"stamp says engine_sha256={stamp.get('engine_sha256', '')[:8]}..., "
        f"engine_source_sha256={str(stamp.get('engine_source_sha256'))[:8]}..., "
        f"but wisp/engine/taint_engine.py hashes to {on_disk[:8]}...")


def test_the_contract_declares_v13_against_the_v12_baseline():
    """A version bump has to be declared, not inferred from a hash that stopped matching."""
    from eval import wisp_contract as WC
    assert WC.ENGINE_TAG == "wisp-scanner-v1.3", WC.ENGINE_TAG
    assert WC.BASELINE_TAG == "wisp-scanner-v1.2", WC.BASELINE_TAG
    assert WC.BASELINE_SHA256 == V12_SHA, (
        "the declared baseline is not the v1.2 engine, so the relation the stamp describes is "
        "against something else")
    stamp = WC.config_stamp()
    assert stamp["engine_matches_baseline"] is False, (
        "v1.3 is not byte-identical to v1.2 and must not claim to be")
    rel = stamp["engine_baseline_relation"]
    assert "not behaviour-preserving" in rel, (
        f"the stamp does not say plainly that v1.3 changes behaviour: {rel!r}")


# Top-level names v1.3 is allowed to introduce or touch, each with the reason it is here. A line
# regex cannot express this, because a helper's body contains no keyword that identifies it. So the
# check maps every changed line to its enclosing top-level construct and tests the construct.
_V13_ALLOWED_BLOCKS = {
    # the two declared defaults
    "_PER_KEY_UPDATE_CAP": "the per-definition rebuild cap, default raised from 4 to 32",
    "_MONOTONE_PROPS": "the accumulating plugin property table, default turned on",
    # the site the second default gates
    "_collect_tainted_props": "where the property table is either accumulated or cleared",
    "_stabilize_summaries": "the worklist, which gained trace bookkeeping behind _STABILIZE_TRACE",
    # inert diagnostics, off unless WISP_STABILIZE_TRACE names a file. These are how the cause was
    # found after two wrong guesses, and they are kept so the diagnosis is reproducible rather than
    # a claim in a commit message. They must stay inert.
    "_STABILIZE_TRACE": "trace output path, empty unless set",
    "_DANGER_FIELDS": "the monotone summary fields the trace compares",
    "_field_delta": "which field differed between two summaries, trace only",
    "_effect_identity": "a sink effect's logical identity, trace only",
    "_danger_projection": "the monotone part of a summary, trace only",
}


def _enclosing_block(lines, idx):
    """Name of the top-level def or assignment that line `idx` belongs to, or None at module level."""
    for i in range(idx, -1, -1):
        l = lines[i]
        if not l or l[0] in " \t)]}":
            continue
        m = re.match(r"(?:def|class)\s+(\w+)", l) or re.match(r"(\w+)\s*(?::[^=]+)?=", l)
        if m:
            return m.group(1)
        if l.startswith(("import ", "from ", "@", "#")):
            continue
        return None
    return None


def test_the_v13_defaults_are_the_only_engine_difference_from_v12():
    """The diff against v1.2 must be confined to the declared blocks.

    A version bump is a licence to change the two declared defaults and the sites they gate. It is
    not a licence to land unrelated engine edits under cover of the same bump, so every changed line
    is attributed to a named block and every block must be on the list above."""
    base = _source_at(V12_COMMIT)
    if base is None:
        raise MissingInput(f"git cannot resolve {V12_COMMIT}, so the v1.2 source is unavailable")
    if _sha(base) != V12_SHA:
        raise AssertionError(f"{V12_COMMIT} does not carry the v1.2 engine")

    import difflib
    a = base.decode("utf-8", "replace").splitlines()
    b = open(ENGINE, encoding="utf-8").read().splitlines()
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    offending = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        for j in range(j1, j2):                       # added or replaced lines, in the NEW file
            line = b[j]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            blk = _enclosing_block(b, j)
            if blk not in _V13_ALLOWED_BLOCKS:
                offending.setdefault(blk, []).append(line.strip()[:90])
        for i in range(i1, i2):                       # deleted lines, attributed in the OLD file
            line = a[i]
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            blk = _enclosing_block(a, i)
            if blk not in _V13_ALLOWED_BLOCKS:
                offending.setdefault(blk, []).append("(removed) " + line.strip()[:80])
    assert not offending, (
        "the engine differs from wisp-scanner-v1.2 in blocks v1.3 does not declare:\n  "
        + "\n  ".join(f"{k}: {v[:3]}" for k, v in list(offending.items())[:6]))


def test_the_trace_instrumentation_is_inert_by_default():
    """The diagnostics shipped with v1.3 must do nothing unless a trace file is named.

    They are permitted in the engine because they are how the non-convergence cause was found. That
    permission depends on them being off, so it is tested rather than assumed."""
    src = open(ENGINE, encoding="utf-8").read()
    assert re.search(r'_STABILIZE_TRACE\s*=\s*os\.environ\.get\("WISP_STABILIZE_TRACE",\s*""\)',
                     src), "the trace path is not an environment-readable default of empty"
    import wisp.engine.taint_engine as te
    assert te._STABILIZE_TRACE == "", (
        f"the trace is active in a default process: {te._STABILIZE_TRACE!r}")


def test_v12_behaviour_is_recoverable():
    """The sensitivity arm has to be real, so both defaults must read from the environment."""
    src = open(ENGINE, encoding="utf-8").read()
    assert re.search(r'os\.environ\.get\("WISP_PER_KEY_CAP",\s*"32"\)', src), (
        "the per-key cap is not an environment-readable default of 32")
    assert re.search(r'os\.environ\.get\("WISP_MONOTONE_PROPS",\s*"1"\)', src), (
        "the property-table accumulation is not an environment-readable default of 1")


def test_global_cap_at_the_recovered_cap_matches_v11_exactly():
    """With the cap set back to 4 the global bound must be the v1.1 expression, unchanged.

    v1.3 raises the default, it does not rewrite the formula. If the expression itself drifted, the
    recovery path would not recover anything and the sensitivity arm would be a different engine."""
    src = open(ENGINE, encoding="utf-8").read()
    m = re.search(r"^\s*max_updates = (.+)$", src, re.M)
    assert m, "max_updates assignment not found in the engine"
    expr = m.group(1).split("#")[0].strip()
    ns = {"definitions": {}, "_PER_KEY_UPDATE_CAP": 4, "max": max, "len": len}
    for n_defs in (0, 1, 17, 250, 4000):
        ns["definitions"] = {i: None for i in range(n_defs)}
        got = eval(expr, {"__builtins__": {}}, ns)
        want = max(64, n_defs * 4)
        assert got == want, (
            f"with {n_defs} definitions and the cap set back to 4 the global update bound is "
            f"{got}, but wisp-scanner-v1.1 used {want}: the recovery path does not recover v1.1's "
            f"bound, so the sensitivity arm and the main tables are two different engines.")


def test_the_no_regression_claim_rests_on_a_stored_comparison():
    """v1.3 claims it leaves already-converging records alone. That claim needs evidence on disk.

    Without this, the claim lives in a comment and a comment cannot be checked. The comparison is
    produced by eval/monotone_diff_v3.py, whose own six tests prove it can report a failure."""
    if not os.path.isfile(DIFF_JSON):
        raise MissingInput(DIFF_JSON)
    d = json.load(open(DIFF_JSON, encoding="utf-8"))
    s = d["stability_check"]
    assert s["verdict"] == "clean", s
    assert s["n_with_changed_finding_count"] == 0, s
    assert s["n_with_same_count_different_findings"] == 0, s
    assert s["findings_base"] == s["findings_new"], s
    assert s["n_records_converged_in_both"] >= 800, (
        f"the no-regression claim rests on only {s['n_records_converged_in_both']} records, which "
        f"is too narrow a base for a corpus-wide engine change")
    assert d["convergence"]["lost"] == 0, d["convergence"]
    assert d["convergence"]["rescued"] > 0, (
        "the comparison shows no rescued record, so this JSON is not the v1.2 versus v1.3 "
        "comparison the version bump rests on")
