"""P. The endpoint-transfer analysis must count records, not plugins, and must not shrink its own
denominator.

Both bugs guarded here were live in the first draft of `eval/endpoint_transfer_v3.py` and both
inflate every rate in a direction that flatters the tools:

  1. Collapsing to the plugin. The corpus puts 1108 records on 854 plugins, so a plugin with three
     records that a tool hit once would have counted as a hit for the whole plugin.
  2. Taking the plugin list from the finding population. That file only holds records that yielded a
     finding, so the records every tool missed would have silently left the denominator, which is
     exactly what failure-as-miss exists to prevent.

The third test pins the analysis to a number that was published independently of it, because a
statistic that only agrees with itself is not checked at all.
"""
from __future__ import annotations
import os, json
from ._common import SYS_ROOT, MissingInput

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
ET = os.path.join(OUT, "ENDPOINT_TRANSFER_V3.json")
POP = os.path.join(OUT, "CORPUS_FINDING_POPULATION_V3.jsonl")
RECS = os.path.join(OUT, "CORPUS1108_WISP_CONTRACT_V3.json")


def _load(path, what):
    if not os.path.isfile(path):
        raise MissingInput(f"{what} not present: {os.path.relpath(path, SYS_ROOT)}")
    return path


def _et():
    return json.load(open(_load(ET, "endpoint transfer result"), encoding="utf-8"))


def test_denominator_is_every_declared_record():
    """The Patchstack denominator must be all 1108 records, not the 1087 that yielded findings."""
    d = _et()
    declared = d["sources"]["patchstack"]["records"]
    with_findings = d["sources"]["patchstack"]["records_with_findings"]
    assert declared == 1108, f"Patchstack denominator is {declared}, expected the full 1108"
    assert with_findings < declared, (
        "every record yielded a finding, so this test can no longer tell the two denominators "
        "apart and needs a new fixture")
    # A rate computed over the smaller denominator would be larger by exactly this factor, so if
    # anyone re-points the script at the population file the inflation is bounded and visible.
    inflation = declared / with_findings
    assert inflation > 1.0


def test_rates_are_record_level_not_plugin_level():
    """Recompute one cell straight from the population and require the shipped value to match.

    Plugin-collapsed counting moves the answer whenever a plugin carries more than one record, which
    the corpus does at 1108 records on 854 plugins. Measured on the shipped data it moves it from
    0.343 to 0.292, because collapsing merges several record hits into one while the denominator
    stays at the record count. The direction is beside the point. What matters is that the number
    changes by two orders of magnitude more than this test's tolerance."""
    d = _et()
    pop = _load(POP, "corpus finding population")
    recs = _load(RECS, "corpus record list")

    n_records = len(json.load(open(recs, encoding="utf-8"))["details"])
    hits, plugins_with_a_hit = set(), set()
    for line in open(pop, encoding="utf-8"):
        r = json.loads(line)
        if r["rank"] != 1 or r["tool"] != "wisp":
            continue
        if r["in_patched_file"] and not r.get("credit_withheld_non_convergence"):
            hits.add((r["slug"], r["cve"]))
            plugins_with_a_hit.add(r["slug"])

    expected = round(len(hits) / n_records, 3)
    got = float(d["per_rung"]["in_patched_file"]["patchstack_rate"]["wisp"])
    assert abs(got - expected) < 5e-4, (
        f"WISP patched-file success@1 on Patchstack is {got}, recomputing from the population "
        f"gives {expected} ({len(hits)} record hits over {n_records} records)")

    plugin_rate = len(plugins_with_a_hit) / n_records
    assert plugin_rate != expected or len(plugins_with_a_hit) == len(hits), (
        "plugin-collapsed and record-level counting agree here, so this test cannot detect the "
        "collapse and needs a corpus where some plugin carries several records")


def test_contract_withholding_is_applied():
    """Non-convergence must cost credit, so the contract rate stays below the un-withheld one."""
    pop = _load(POP, "corpus finding population")
    d = _et()
    n_records = len(json.load(open(_load(RECS, "corpus record list"), encoding="utf-8"))["details"])
    kept = set()
    withheld_any = False
    for line in open(pop, encoding="utf-8"):
        r = json.loads(line)
        if r["rank"] != 1 or r["tool"] != "wisp":
            continue
        if r.get("credit_withheld_non_convergence"):
            withheld_any = True
        if r["in_patched_file"]:
            kept.add((r["slug"], r["cve"]))
    assert withheld_any, "no record is marked non-convergent, so this test proves nothing"
    contract = float(d["per_rung"]["in_patched_file"]["patchstack_rate"]["wisp"])
    assert contract < len(kept) / n_records, (
        "the contract arm is not below the kept arm, so the withholding was not applied")


def test_wordfence_side_reproduces_the_published_external_table():
    """The Wordfence column must equal the record-level rates the paper's external table prints.

    Those values are computed by a different script, so an agreement here is a real cross-check
    rather than the statistic agreeing with itself.

    This used to hardcode {wisp 0.54, wpt 0.45, semgrep 0.33, progpilot 0.30}, and on 2026-08-14
    that made it the wrong way round: the external table had moved to 0.62 for WISP under
    wisp-scanner-v1.3 while `endpoint_transfer_v3` still read a 2026-07-31 ladder holding 0.54, so
    the paper printed both numbers for one quantity and this test defended the stale one. A
    hardcoded expectation cannot tell "the analysis drifted" from "the analysis was corrected".
    Reading the table makes it a cross-check again, and the three baselines are unchanged at 0.45,
    0.33 and 0.30, which is what says the move is WISP's engine and not the scoring."""
    d = _et()
    ext_path = os.path.join(OUT, "EXTERNAL_TABLE_V3.json")
    ext = json.load(open(_load(ext_path, "published external table"), encoding="utf-8"))
    got = d["per_rung"]["in_patched_file"]["wordfence_rate"]
    for tool in ("wisp", "wpt", "semgrep", "progpilot"):
        want = float(ext["cells"][tool]["patch-file@1"]["rate"])
        assert abs(float(got[tool]) - want) < 5e-3, (
            f"Wordfence patched-file success@1 for {tool} is {got[tool]} in the endpoint-transfer "
            f"analysis and {want} in the external table the paper prints. One quantity, two files, "
            f"two answers, which is how a stale scan hides.")


def test_a_leader_flip_is_reported_not_smoothed():
    """Where the two sources disagree on the leading tool, the JSON must say so plainly."""
    d = _et()
    s = d["summary"]
    assert s["n_leader_agree"] <= s["n_rungs"]
    for rung, p in d["per_rung"].items():
        agrees = p["leader_patchstack"] == p["leader_wordfence"]
        assert p["leader_agrees"] == agrees, (
            f"{rung} reports leader_agrees={p['leader_agrees']} but names "
            f"{p['leader_patchstack']} and {p['leader_wordfence']}")
    assert s["rungs_leader_disagrees"] or s["n_leader_agree"] == s["n_rungs"], (
        "the disagreement list is empty while not every rung agrees")


def test_construct_validity_is_not_claimed():
    """The artifact must state in its own words that this is not defect-level evidence."""
    d = _et()
    txt = (d.get("not_answered", "") + " " + d.get("question", "")).lower()
    assert "human" in txt and "defect" in txt, (
        "the result does not record that naming the disclosed defect is out of its scope, which is "
        "the one thing a reader is most likely to over-read from it")
