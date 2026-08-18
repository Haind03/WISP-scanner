"""E. Sanitizer default: code and manuscript must agree (Prompt 6 resolution).

The pre-fix bug was a mismatch: the engine enables class-scoped sanitizer
propagation by default (`_sani_class_enabled()` reads
`os.environ.get("WISP_SANI_CLASS", "1")`, True with no override, and every primary
corpus run used that default), while the prose called it "off by default". Prompt 6
resolves the mismatch by correcting the prose, not by changing a shipped default
just to match text. The class-carrying default is the stronger, coverage-preserving
behavior and is what produced every reported number.

Post-fix invariant (this test now PASSES): with no env override the engine default
is ON, and the manuscript states class propagation is enabled by default and no
longer calls the sanitizer flag "off by default".
"""
from __future__ import annotations
import os, glob, re
from ._common import Evidence, SYS_ROOT

from wisp.engine import taint_engine as te

# locate the main manuscript by suffix, without hard-coding the working-tree filename
_MATCHES = glob.glob(os.path.join(SYS_ROOT, "2026-07-07", "latex", "*-CnS-elsarticle.tex"))
MAIN_TEX = _MATCHES[0] if _MATCHES else ""


def test_sanitizer_default_matches_manuscript():
    ev = Evidence("E. sanitizer default: code/manuscript agreement")

    # 1. the engine default with no override
    saved = os.environ.pop("WISP_SANI_CLASS", None)
    try:
        default_on = te._sani_class_enabled()
    finally:
        if saved is not None:
            os.environ["WISP_SANI_CLASS"] = saved
    ev.show(f"_sani_class_enabled() with WISP_SANI_CLASS unset -> {default_on} (engine default)")
    assert default_on is True, (
        "engine default must remain ON (class-carrying); Prompt 6 does not change a shipped default "
        "to match prose")

    # 2. where the working manuscript is present, it must now describe the flag as
    #    enabled by default, not off by default. If only a shipped bundle is present
    #    (no working tex), the code-default check above is the invariant.
    if MAIN_TEX and os.path.isfile(MAIN_TEX):
        tex = open(MAIN_TEX, encoding="utf-8").read()
        # Matching one exact string made this test brittle rather than strict: a 2026-08-14 rewrite
        # of the same paragraph said "This is on by default", which is the required claim, and the
        # test failed anyway. A check that cannot tell a rewording from a regression will eventually
        # be silenced by whoever is holding the pen. The invariant is the claim, so accept the ways
        # the claim can be written and keep failing on its negation, which the second assert covers.
        flat = " ".join(tex.split())
        enabled = bool(re.search(
            r"(class )?propagation is \\emph\{enabled by default\}"
            r"|class propagation is (\\emph\{)?enabled by default"
            r"|(This|It) is (\\emph\{)?(on|enabled)( by default| by default\})", flat, re.I))
        stale = re.search(r"carries the class through assignments and returns,\s*kept off by default", tex)
        ev.show(f'main tex states class propagation is enabled by default: {enabled}')
        ev.show(f'stale "off by default" phrasing for the sani flag present: {bool(stale)}')
        assert enabled, ("manuscript must state class propagation is enabled by default to match the "
                         "engine default")
        assert not stale, ("manuscript still describes the sanitizer class-carry flag as off by "
                           "default, contradicting the engine default")
    else:
        ev.show("working manuscript not present in this tree; code-default invariant is authoritative")


if __name__ == "__main__":
    test_sanitizer_default_matches_manuscript()
