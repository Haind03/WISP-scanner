"""M. The two corpus-ladder failure-policy arms must be two views of one measurement.

The corpus ladder is reported under two failure policies: the contract arm, which withholds credit
for a record whose analysis did not converge, and the kept arm, which does not, and which is the
arm the matched-sample ladder uses. The first version scored the corpus twice, once per arm, and
masked each finding's geometry as it went. That is how two numbers for one quantity start: the two
runs shared no artifact, so nothing would have caught them drifting apart, and the population file
that shipped as evidence recorded only the masked view, from which the kept arm could not be
recovered at all.

The population now stores geometry as measured plus the withheld flag, and each arm is an
aggregation over it. These tests pin that down from both ends: the aggregation must apply the
policy it claims, and the shipped population must be the unmasked kind, or the verification that
runs on every build would be comparing the contract arm against itself.
"""
from __future__ import annotations
import os, json
from . import _common as C

from eval import corpus_ladder_v3 as CL

POP = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out", "CORPUS_FINDING_POPULATION_V3.jsonl")
CONTRACT = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out", "CORPUS_LADDER_V3.json")
KEPT = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out", "CORPUS_LADDER_KEPT_V3.json")

RUNG = "in_patched_file"


def _unit(slug, tool, hit, withheld):
    u = {"slug": slug, "cve": "CVE-0000-0000", "tool": tool, "rank": 1,
         "advisory_class": "xss", "credit_withheld_non_convergence": withheld,
         "raw_geometry": True, "class_match": hit}
    for r in CL.RUNGS:
        u[r] = hit
    return u


def test_contract_withholds_and_kept_does_not():
    """One population, two arms, and the only difference is the withheld findings."""
    units = [_unit("a", "wisp", True, False),
             _unit("b", "wisp", True, True),
             _unit("c", "wisp", False, False),
             _unit("d", "semgrep", True, False)]
    contract = CL.aggregate(units, ["wisp", "semgrep"], "contract", 4, 0)
    kept = CL.aggregate(units, ["wisp", "semgrep"], "kept", 4, 0)

    # WISP: 2 of 3 hits raw, 1 of 3 once the withheld finding is charged.
    assert kept["per_tool"]["wisp"][RUNG]["count"] == 2, kept["per_tool"]["wisp"][RUNG]
    assert contract["per_tool"]["wisp"][RUNG]["count"] == 1, contract["per_tool"]["wisp"][RUNG]
    # The denominator does not move: a withheld finding is a miss, not a deletion.
    assert kept["per_tool"]["wisp"][RUNG]["n"] == contract["per_tool"]["wisp"][RUNG]["n"] == 3
    # A tool with nothing withheld is identical in both arms, rung by rung.
    for r in CL.RUNGS + ("class_match",):
        assert kept["per_tool"]["semgrep"][r] == contract["per_tool"]["semgrep"][r], r
    # The policy each file claims is the policy it was aggregated under.
    assert contract["failure_policy"].startswith("contract: ")
    assert kept["failure_policy"].startswith("kept: ")


def test_arms_coincide_when_nothing_is_withheld():
    """No non-convergence, no difference. The arms may only diverge where rule 3 bites."""
    units = [_unit("a", "wisp", True, False), _unit("b", "wisp", False, False)]
    contract = CL.aggregate(units, ["wisp"], "contract", 2, 0)
    kept = CL.aggregate(units, ["wisp"], "kept", 2, 0)
    assert contract["per_tool"] == kept["per_tool"]


def test_shipped_population_is_unmasked():
    """The evidence file must record geometry as measured, not geometry already charged.

    A masked population would make the kept arm silently reproduce the contract arm, and the
    build's verification would pass while comparing one number with itself.
    """
    if not os.path.isfile(POP):
        raise AssertionError("corpus finding population is missing: " + POP)
    units = [json.loads(l) for l in open(POP, encoding="utf-8") if l.strip()]
    assert units, "corpus finding population is empty"
    assert all(u.get("raw_geometry") for u in units), \
        "population predates the raw-geometry schema, so the kept arm cannot be derived from it"
    withheld = [u for u in units if u.get("credit_withheld_non_convergence")]
    assert withheld, "no withheld finding in the population, so the two arms cannot be told apart"
    assert any(u[RUNG] for u in withheld), \
        "every withheld finding scores zero at every rung, which is the signature of a masked population"


def test_shipped_arms_agree_with_the_population():
    """Both shipped arm files must be reproducible from the shipped population."""
    for path, policy in ((CONTRACT, "contract"), (KEPT, "kept")):
        if not os.path.isfile(path):
            raise AssertionError("missing shipped arm: " + path)
    units = [json.loads(l) for l in open(POP, encoding="utf-8") if l.strip()]
    tools = sorted({u["tool"] for u in units})
    for path, policy in ((CONTRACT, "contract"), (KEPT, "kept")):
        shipped = json.load(open(path, encoding="utf-8"))
        fresh = CL.aggregate(units, tools, policy, shipped["records_scored"],
                             shipped["records_unresolved"])
        assert fresh["per_tool"] == shipped["per_tool"], \
            f"{os.path.basename(path)} does not match a recomputation from the population"
    # And the two arms must actually differ, on WISP and on WISP alone.
    c = json.load(open(CONTRACT, encoding="utf-8"))["per_tool"]
    k = json.load(open(KEPT, encoding="utf-8"))["per_tool"]
    assert c["wisp"][RUNG] != k["wisp"][RUNG], \
        "the arms are identical for WISP, so rule 3 charged nothing"
    for tool in c:
        if tool != "wisp":
            assert c[tool] == k[tool], f"{tool} differs between arms but has no non-convergence mode"


if __name__ == "__main__":
    test_contract_withholds_and_kept_does_not()
    test_arms_coincide_when_nothing_is_withheld()
    test_shipped_population_is_unmasked()
    test_shipped_arms_agree_with_the_population()
    print("all pass")
