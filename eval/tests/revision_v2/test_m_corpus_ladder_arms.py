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

The later tests cover the primary_effect block, the corpus-scale drop from the patched-file rung to
the exact-changed-line rung. It shipped for a while as a point estimate with no interval, and the
interval it needs is not available from the file: the two rungs are nested on the same findings, so
differencing the endpoints of their two marginal intervals is not a 95 percent interval for the
difference. These tests pin the difference to the paired quantity it claims to be, and pin the
interval to something narrower than that invalid construction, so a future edit cannot quietly
replace the paired resample with the subtraction.
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
        assert fresh["primary_effect"] == shipped.get("primary_effect"), \
            f"{os.path.basename(path)} primary_effect does not match a recomputation from the " \
            f"population"
    # And the two arms must actually differ, on WISP and on WISP alone.
    c = json.load(open(CONTRACT, encoding="utf-8"))["per_tool"]
    k = json.load(open(KEPT, encoding="utf-8"))["per_tool"]
    assert c["wisp"][RUNG] != k["wisp"][RUNG], \
        "the arms are identical for WISP, so rule 3 charged nothing"
    for tool in c:
        if tool != "wisp":
            assert c[tool] == k[tool], f"{tool} differs between arms but has no non-convergence mode"


def test_primary_effect_is_the_paired_difference():
    """The drop must be the difference measured on the same findings, under the arm's own policy.

    Hand-checkable: 4 WISP findings, 3 in a patched file, 1 of those on the exact changed line, and
    one of the file hits is withheld for non-convergence. Kept arm 3/4 - 1/4 = 0.5. Contract arm
    charges the withheld finding at every rung, so 2/4 - 1/4 = 0.25. A difference computed off the
    two rungs separately, or one that dropped the withheld finding from the denominator instead of
    scoring it a miss, gives neither number.
    """
    def u(slug, infile, exact, withheld):
        d = _unit(slug, "wisp", False, withheld)
        d["in_patched_file"] = infile
        d["on_exact_changed_line"] = exact
        return d

    units = [u("a", True, True, False), u("b", True, False, False),
             u("c", True, False, True), u("d", False, False, False)]
    kept = CL.aggregate(units, ["wisp"], "kept", 4, 0)
    contract = CL.aggregate(units, ["wisp"], "contract", 4, 0)
    k = kept["primary_effect"]["wisp"]["drop_to_exact_changed_line"]
    c = contract["primary_effect"]["wisp"]["drop_to_exact_changed_line"]
    assert k["diff"] == 0.5, k
    assert c["diff"] == 0.25, c
    # and it is the paired difference of the two rungs the same arm reports, count for count
    for arm in (kept, contract):
        pt = arm["per_tool"]["wisp"]
        de = arm["primary_effect"]["wisp"]["drop_to_exact_changed_line"]
        assert pt["in_patched_file"]["n"] == pt["on_exact_changed_line"]["n"], \
            "the two rungs must share a denominator or the difference is not paired"
        expect = (pt["in_patched_file"]["count"] - pt["on_exact_changed_line"]["count"]) \
            / pt["in_patched_file"]["n"]
        assert abs(de["diff"] - expect) < 5e-5, (de, expect)


def test_primary_effect_ships_for_every_tool_in_both_arms():
    """Every scored tool carries the block, with an interval that brackets its own estimate."""
    for path in (CONTRACT, KEPT):
        d = json.load(open(path, encoding="utf-8"))
        pe = d.get("primary_effect")
        assert pe, "no primary_effect block in " + os.path.basename(path)
        assert set(pe) == set(d["per_tool"]), \
            "primary_effect covers %s but the ladder scores %s" % (sorted(pe), sorted(d["per_tool"]))
        for tool, blk in pe.items():
            de = blk["drop_to_exact_changed_line"]
            lo, hi = de["ci95"]
            assert lo < de["diff"] < hi, (tool, de)
            # and the estimate must belong to the same population as the rungs printed beside it.
            # A block left behind by an earlier run would still look like a plausible drop, and
            # nothing else in the file would contradict it.
            f = d["per_tool"][tool]["in_patched_file"]
            e = d["per_tool"][tool]["on_exact_changed_line"]
            expect = (f["count"] - e["count"]) / f["n"]
            assert abs(de["diff"] - expect) < 1e-4, \
                "%s %s: drop %s but the rungs in the same file say %.4f, so the block was " \
                "computed on a different population" % (
                    os.path.basename(path), tool, de["diff"], expect)


def test_primary_effect_interval_is_not_the_marginal_difference():
    """The interval must come from resampling the difference, not from subtracting two intervals.

    Subtracting the marginal endpoints (lo_file - hi_exact, hi_file - lo_exact) treats two rungs
    measured on the same findings as independent. They are nested and positively correlated, so
    that construction is always wider than the paired resample. Requiring strictly narrower is what
    catches a future edit that goes back to arithmetic on the two rung intervals: it would produce
    exactly the naive width, and this test would fail.
    """
    for path in (CONTRACT, KEPT):
        d = json.load(open(path, encoding="utf-8"))
        for tool, blk in d["primary_effect"].items():
            de = blk["drop_to_exact_changed_line"]
            f = d["per_tool"][tool]["in_patched_file"]["ci95"]
            e = d["per_tool"][tool]["on_exact_changed_line"]["ci95"]
            naive = (f[0] - e[1], f[1] - e[0])
            paired = de["ci95"][1] - de["ci95"][0]
            assert paired < (naive[1] - naive[0]), \
                "%s %s: the drop interval %s is no narrower than differencing the marginals %s, " \
                "which is the construction it exists to replace" % (
                    os.path.basename(path), tool, de["ci95"], list(naive))


def test_primary_effect_follows_the_arm():
    """The drop must move with the failure policy, and only where rule 3 bites."""
    c = json.load(open(CONTRACT, encoding="utf-8"))["primary_effect"]
    k = json.load(open(KEPT, encoding="utf-8"))["primary_effect"]
    assert c["wisp"] != k["wisp"], \
        "the WISP drop is identical in both arms, so the block ignored the failure policy"
    for tool in c:
        if tool != "wisp":
            assert c[tool] == k[tool], \
                f"{tool} drop differs between arms but has no non-convergence mode"


if __name__ == "__main__":
    test_contract_withholds_and_kept_does_not()
    test_arms_coincide_when_nothing_is_withheld()
    test_shipped_population_is_unmasked()
    test_shipped_arms_agree_with_the_population()
    test_primary_effect_is_the_paired_difference()
    test_primary_effect_ships_for_every_tool_in_both_arms()
    test_primary_effect_interval_is_not_the_marginal_difference()
    test_primary_effect_follows_the_arm()
    print("all pass")
