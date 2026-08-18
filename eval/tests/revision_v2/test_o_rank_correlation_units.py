"""O. The rank-correlation section must not be able to answer one question and label it another.

Section~\\ref{sec:rankcorr} exists because "does the coarse rung order things the way the fine rung
does" is four questions, not one, and they disagree. That makes two specific failure modes cheap:

  1. Computing a correlation over the wrong axis and still getting a plausible number. A rho of
     +0.35 looks like an answer whatever it was computed on, so these tests drive the statistic
     with synthetic populations whose true rank correlation is known by construction.
  2. Letting the pooled rows into the multiple-comparison family. Pooled is a re-reading of the
     per-tool evidence, so counting it would shrink every adjusted p using the same data twice.

The third test pins the failure policy, because a reading that silently credits withheld findings
would report the kept arm under the contract label.
"""
from __future__ import annotations
import os, json
import numpy as np
from . import _common as C

from eval import rank_correlation_v3 as RK

RESULT = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out", "RANK_CORRELATION_V3.json")


def _u(slug, tool, coarse, fine, rank=1, cls="xss", withheld=False):
    return {"slug": slug, "cve": "CVE-0000-0000", "tool": tool, "rank": rank,
            "advisory_class": cls, "in_patched_file": coarse, "on_exact_changed_line": fine,
            "credit_withheld_non_convergence": withheld, "raw_geometry": True}


def _shipped():
    if not os.path.isfile(RESULT):
        raise C.MissingInput("RANK_CORRELATION_V3.json (run eval.rank_correlation_v3)")
    return json.load(open(RESULT, encoding="utf-8"))


def test_group_reading_recovers_a_known_ordering():
    """Four groups built so the two rungs rank them identically must give rho = +1, and the
    same groups with the fine rung reversed must give -1. A statistic computed on the wrong axis
    cannot pass both halves."""
    rng = np.random.default_rng(0)
    units = []
    # group i gets i+1 coarse hits out of 4 and i fine hits, so the two rungs rank the groups
    # identically at different levels, which is the shape the section is asking about
    for i, tool in enumerate(("a", "b", "c", "d")):
        for j in range(4):
            units.append(_u("slug%d" % j, tool, j <= i, j <= i - 1))
    for u in units:
        u["_key"] = u["tool"]
    agree = RK.reading_by_group(units, ("a", "b", "c", "d"), "contract", "test", rng)
    assert agree["rho"] is not None and agree["rho"] > 0.9, agree

    flipped = []
    for u in units:
        v = dict(u)
        v["on_exact_changed_line"] = not v["in_patched_file"]
        flipped.append(v)
    dis = RK.reading_by_group(flipped, ("a", "b", "c", "d"), "contract", "test", rng)
    assert dis["rho"] is not None and dis["rho"] < -0.9, dis


def test_contract_arm_withholds_where_the_kept_arm_credits():
    """The same population read under the two arms must differ exactly on the withheld findings."""
    units = [_u("s1", "wisp", True, True, withheld=True),
             _u("s2", "wisp", True, True, withheld=False)]
    assert RK.hit(units[0], RK.COARSE, "contract") == 0
    assert RK.hit(units[0], RK.COARSE, "kept") == 1
    assert RK.hit(units[1], RK.COARSE, "contract") == 1


def test_plugin_reading_is_ranked_on_slugs_not_findings():
    """Two slugs, one with many findings and one with few, must count once each. If the reading
    ranked findings instead, the big slug would dominate and n_units would not be the slug count."""
    rng = np.random.default_rng(0)
    units = ([_u("big", "wisp", True, False) for _ in range(50)]
             + [_u("small", "wisp", False, True)])
    r = RK.reading_by_plugin(units, "contract", rng)
    assert r["n_units"] == 2, r
    assert r["slugs_scoring_zero_at_fine_rung"] == 0.5, r


def test_pooled_rows_are_excluded_from_the_holm_family():
    """Pooled aggregates the same findings the per-tool rows already carry. Counting it would use
    one body of evidence twice in the correction that is supposed to protect against exactly that."""
    d = _shipped()
    members = d["holm_family"]["members"]
    assert members, d["holm_family"]
    assert not [m for m in members if m.endswith("/pooled")], members
    for unit in ("by_plugin", "by_class"):
        assert d[unit]["contract"]["pooled"].get("p_holm") is None, unit


def test_every_reported_cell_carries_an_interval():
    """A cell with a rho and no interval reads as a result and is not one."""
    d = _shipped()
    for arm, cellv in d["by_tool"].items():
        assert cellv["ci95"] and len(cellv["ci95"]) == 2, arm
    for unit in ("by_plugin", "by_class"):
        for arm, tools in d[unit].items():
            for tool, cellv in tools.items():
                assert cellv["ci95"] and len(cellv["ci95"]) == 2, (unit, arm, tool)
    for tool, rungs in d["by_own_rank"].items():
        for rung, cellv in rungs.items():
            assert cellv["ci95"] and len(cellv["ci95"]) == 2, (tool, rung)


def test_no_tool_level_sign_is_licensed_by_its_own_p_value():
    """The supplement declines to report a sign for the four-tool ranking. Whichever way the arms
    come out, that refusal has to stay licensed by the data rather than by habit.

    Until 2026-08-13 this test asserted the opposite thing, that the three arms disagree in sign, and
    the supplement declined the sign on that basis. Under wisp-scanner-v1.3 the three arms agree,
    all negative, so the old assertion failed and the paragraph that rested on it was false. The
    stable reason to decline was never the disagreement. It is that a rank correlation over four
    units cannot reject its null at any effect size, which is what this now checks. If a p-value ever
    drops below alpha the section has to be rewritten to report the sign, and this test says so by
    failing."""
    d = _shipped()
    bad = {k: v["p"] for k, v in d["by_tool"].items()
           if v.get("p") is not None and v["p"] < 0.05}
    assert not bad, (
        f"a tool-level rank correlation is now significant: {bad}. The supplement declines to report "
        f"a sign for the four-tool ranking on the grounds that four units cannot support one. That "
        f"is no longer the whole story and the section must be rewritten rather than kept.")
    signs = set(d["disagreement"]["by_tool_signs"].values())
    assert len(signs) == 1, (
        f"the tool-level arms disagree in sign again: {d['disagreement']['by_tool_signs']}. The "
        f"supplement currently says they agree. Restore the instability wording, which is in the "
        f"git history of WISP-paper-CnS-supplement.tex, rather than leaving the two out of step.")
