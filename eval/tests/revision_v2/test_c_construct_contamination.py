"""C. Construct contamination of the human bottom rung.

In the retired v2 sheets, 165 of 200 rows carried reported_class != advisory_class and every
one of those 165 was marked UR by BOTH reviewers. A rung described as class-agnostic was in
practice decided by class match.

This one cannot be "fixed" the way A and B were. It is a property of labels two people wrote,
and rewriting somebody's label to make a test pass would be fabricating data. What can be done,
and is what this test now checks, is threefold:

  1. the contamination is still recorded on the retired sheets, so the finding is not quietly
     lost when the study that produced it is withdrawn;
  2. the v3 label schema makes the collapse *expressible but not forced* - class agreement and
     root-cause relation are separate axes, and LOCATION_ONLY exists as a reason code, so a
     cross-class finding can be judged on location; and
  3. a guard in eval/validate_adjudication_v3.py measures the collapse on any future filled
     sheet and fails if every adjudicated cross-class packet comes back UNRELATED from both
     reviewers.

Nothing structural can stop two reviewers from collapsing the axes anyway. The point of (3) is
that if it happens again it will be visible in the validator rather than discovered by a
reviewer of the paper.
"""
from __future__ import annotations
import inspect

from ._common import read_csv, verdict, Evidence


def test_v2_contamination_is_still_on_record():
    """The historical defect must stay measurable, not be erased with the study."""
    ev = Evidence("C. contamination on the retired v2 sheets")
    A = read_csv("filled_A.csv")
    B = read_csv("filled_B.csv")
    assert len(A) == 200 and len(B) == 200, "expected both 200-row reviewer sheets"
    cross = [i for i, r in enumerate(A)
             if r.get("reported_class", "").strip() != r.get("advisory_class", "").strip()]
    ur_A = [i for i in cross if verdict(A[i], "reviewer_A") == "UR"]
    ur_B = [i for i in cross if verdict(B[i], "reviewer_B") == "UR"]
    ev.show(f"cross-class rows: {len(cross)}/{len(A)}; UR by A: {len(ur_A)}, by B: {len(ur_B)}")
    assert len(cross) == 165 and len(ur_A) == 165 and len(ur_B) == 165, (
        "the recorded contamination has changed; if these sheets were edited, say so, because "
        "the paper's account of why the study was withdrawn rests on these counts")


def test_v3_schema_lets_a_cross_class_finding_be_judged_on_location():
    """The collapse must be expressible but not forced by the label design."""
    ev = Evidence("C. v3 label axes")
    from eval import adjudication_v3_common as C

    assert "class_relation" in C.TIER2_LABEL_AXES and "root_cause_relation" in C.TIER2_LABEL_AXES, (
        "class agreement and root-cause relation are not separate axes, so a single verdict "
        "column can collapse them again")
    assert "verdict" not in C.TIER2_LABEL_AXES and "UR" not in C.TIER2_LABEL_AXES, (
        "a single mixed verdict column is back")
    # a cross-class finding must have somewhere to land other than UNRELATED
    rc = set(C.ROOT_CAUSE_RELATION)
    assert {"RELATED_AREA_DIFFERENT_DEFECT", "INSUFFICIENT_EVIDENCE"} <= rc, (
        f"root_cause_relation offers no middle ground: {sorted(rc)}")
    assert "LOCATION_ONLY" in C.REASON_CODE, (
        "no LOCATION_ONLY reason code, so a reviewer judging purely on location has no way to "
        "say so")
    ev.show(f"class_relation      = {C.CLASS_RELATION}")
    ev.show(f"root_cause_relation = {C.ROOT_CAUSE_RELATION}")
    ev.show("LOCATION_ONLY reason code present = True")


def test_validator_guards_against_the_collapse_recurring():
    ev = Evidence("C. collapse guard in the v3 validator")
    from eval import validate_adjudication_v3 as V
    src = inspect.getsource(V.validate_tier2)
    has = ("root_cause_relation" in src and "UNRELATED" in src
           and "cross-class" in src.lower())
    ev.show(f"validate_tier2 measures the cross-class collapse = {has}")
    assert has, (
        "eval/validate_adjudication_v3.py does not check whether every adjudicated cross-class "
        "packet came back UNRELATED from both reviewers, so bug C could recur unnoticed")
