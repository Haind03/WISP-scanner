"""Z. The matched-100 baselines the ladder reads must be the post-Progpilot-fix scan.

Progpilot exits non-zero on plugins where it nevertheless produced findings, and the harness used to
discard those runs as failures. That was found and fixed on 2026-08-02, and the fix is the reason the
paper reports Progpilot at all rather than a row of zeros.

`eval/ladder_v3.py` used to default `--baselines` to
`final/supplementary-data/reproduce/data/matched_100_baselines_final.json`, which is dated 2026-07-28
and is the pre-fix scan. Across its 100 records Progpilot has zero findings, 34 of them carrying
`nonzero_exit:1` and another 27 carrying no error at all and still nothing. That file is kept on
purpose, because the macro counting the discarded records needs the broken run as its evidence, so
the fix is to stop pointing the ladder at it rather than to delete it.

Rebuilding the finding population from it on 2026-08-13 silently dropped Progpilot from the
population, which dropped it from the paired family, which took the family from 39 comparisons to 26,
and every comparison against Progpilot went with it. Nothing failed: `paired_family_v3` recorded
`baselines_absent_from_population: ["progpilot"]` in its own output and carried on, and the manuscript
would have been rebuilt around a family missing a third of itself.

The default is now `matched_100_baselines_contract.json`, the post-Progpilot-fix contract rescan
shipped beside it, 242 Progpilot findings, 46 timeouts, no exit-code discards.

These tests read the file the ladder would actually use, so that a reviewer running the shipped
reproduction kit with defaults cannot silently reproduce a different paper.
"""
from __future__ import annotations
import os, json, collections
from ._common import REPO, SYS_ROOT, MissingInput

TOOLS = ("progpilot", "semgrep", "wpt")


def _ladder_default_baselines() -> str:
    """The path eval/ladder_v3.py would actually use, read out of its own argument parser rather
    than restated here, so renaming the default in the module is caught instead of bypassed."""
    import argparse, unittest.mock as mock
    from eval import ladder_v3
    captured = {}
    real_add = argparse.ArgumentParser.add_argument

    def spy(self, *args, **kw):
        if args and args[0] == "--baselines":
            captured["path"] = kw.get("default")
        return real_add(self, *args, **kw)

    with mock.patch.object(argparse.ArgumentParser, "add_argument", spy), \
         mock.patch.object(argparse.ArgumentParser, "parse_args", lambda self, *a, **k: (_ for _ in ()).throw(SystemExit(0))):
        try:
            ladder_v3.main()
        except SystemExit:
            pass
        except Exception:
            pass
    return captured.get("path")


def _records(path: str) -> list:
    if not os.path.isfile(path):
        raise MissingInput(path)
    d = json.load(open(path, encoding="utf-8"))
    return d["details"] if isinstance(d, dict) and "details" in d else d


def _counts(recs: list) -> tuple:
    found = collections.Counter()
    errs = collections.Counter()
    for r in recs:
        for t in TOOLS:
            v = r.get(t)
            if isinstance(v, dict):
                found[t] += len(v.get("findings") or [])
                if t == "progpilot":
                    errs[v.get("err") or "none"] += 1
    return found, errs


def test_the_ladders_default_baselines_carry_progpilot_findings():
    p = _ladder_default_baselines()
    assert p, "eval/ladder_v3.py no longer exposes a DATA dir, so this test cannot find its input"
    found, errs = _counts(_records(p))
    assert found["progpilot"] > 0, (
        f"the baselines file the ladder reads by default has {found['progpilot']} Progpilot "
        f"findings, so a population built from it drops Progpilot entirely and the paired family "
        f"loses every comparison against it. Progpilot error breakdown: {dict(errs)}. The post-fix "
        f"scan is revision-cns-v2/progpilot_v3/matched100_contract_quiet_v3.json.")


def test_no_progpilot_record_was_discarded_for_its_exit_code():
    """The specific defect. A non-zero exit is not a failure to produce findings."""
    p = _ladder_default_baselines()
    _, errs = _counts(_records(p))
    discarded = {k: v for k, v in errs.items() if "nonzero_exit" in str(k)}
    assert not discarded, (
        f"the baselines file records {discarded} Progpilot runs discarded for a non-zero exit "
        f"status. That is the 2026-08-02 defect, not a capability of the tool, and a file carrying "
        f"it is a pre-fix scan.")


def test_the_population_built_from_it_holds_all_four_tools():
    pop = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
    if not os.path.isfile(pop):
        raise MissingInput(pop)
    c = collections.Counter()
    with open(pop, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                c[json.loads(line)["tool"]] += 1
    missing = [t for t in ("wisp",) + TOOLS if c[t] == 0]
    assert not missing, (
        f"the matched-100 finding population has no findings for {missing}, so every paired "
        f"comparison against them is absent from the family rather than failing. Tool counts: "
        f"{dict(c)}")


def test_the_paired_family_still_contains_progpilot():
    """The family is where the absence would actually be spent, so check it where it lands."""
    fam = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "PAIRED_FAMILY_V3.json")
    if not os.path.isfile(fam):
        raise MissingInput(fam)
    d = json.load(open(fam, encoding="utf-8"))
    absent = d.get("baselines_absent_from_population") or []
    assert not absent, (
        f"the paired family reports these baselines missing from the population: {absent}. Every "
        f"comparison against a missing baseline is absent rather than failing, so the corrected "
        f"family silently shrinks and the manuscript is rebuilt around a smaller one.")
    assert "progpilot" in (d.get("baselines_present") or []), (
        f"progpilot is not among the family's baselines: {d.get('baselines_present')}")
