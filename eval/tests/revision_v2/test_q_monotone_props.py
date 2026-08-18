"""Q. Accumulating the plugin property table must not make disproved taint immortal.

`WISP_MONOTONE_PROPS=1` stops `_collect_tainted_props` from clearing TAINTED_PROPS on every outer
round, which is what lets the driver's "stop when nothing changed" test fire instead of exhausting
its round cap. On the 12 records that fail at every cap it takes convergence from 0 of 12 to 7 of 12,
and to 11 of 12 with a raised per-key cap.

The second reviewer's objection is that accumulation has no deletion path. `_build_summary` starts
from an empty summary and recreates `tainted_params_to_props` conditionally, so an effect that later
rounds stop producing simply stays in the table. Worse, `_tv_join` INTERSECTS the safety classes of a
value, so a raw label recorded in an early round, whose safety set is empty, drags every later
sanitized observation back down to raw. Emission reads the table directly, so this is a correctness
question and not only a convergence one: the predicted symptom is a bogus XSS on a property that a
sanitizer wrapper actually cleans.

The engine's own selftest already covers the easy shape, where the sanitizer sits directly in the
setter and is therefore visible on the first build. That case cannot expose the bug. These cases put
the sanitizer behind a wrapper chain, and in a second file, so the property is collected before the
chain resolves and the raw value has a round in which to be recorded.
"""
from __future__ import annotations
import os, sys, types, tempfile, importlib
from ._common import REPO, MissingInput  # noqa: F401  (REPO adds repo root to sys.path)

RAW_SEED = """<?php
class Deferred_Safe_Property {
  function set_it($v){ $this->slot = wisp_wrap_outer($v); }
  function seed(){ $this->set_it($_GET['html']); }
  function out(){ echo $this->slot; }
}
"""
# Second file, so the wrapper chain is not resolvable while the first file is first walked.
SANITIZER_CHAIN = """<?php
function wisp_wrap_outer($v){ return wisp_wrap_inner($v); }
function wisp_wrap_inner($v){ return esc_html($v); }
"""


def _classes_with(monotone: bool, files: dict) -> set:
    """Run the engine over a synthetic plugin with the flag in the requested state.

    The flag is read at import time, so the engine module is reloaded under the chosen environment
    rather than mutated in place."""
    old = os.environ.get("WISP_MONOTONE_PROPS")
    os.environ["WISP_MONOTONE_PROPS"] = "1" if monotone else "0"
    try:
        import wisp.engine.taint_engine as te
        te = importlib.reload(te)
        if not hasattr(te, "_MONOTONE_PROPS"):
            # This engine build has no accumulation flag, so setting the variable does nothing and
            # all three cases would pass while testing nothing at all. Three green tests that cannot
            # fail are worse than three absent ones, so say so instead.
            raise MissingInput(
                "this engine build has no _MONOTONE_PROPS flag, so the accumulation cases would "
                "pass vacuously; these tests belong with the engine that carries the flag")
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for name, body in files.items():
                p = os.path.join(d, name)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(body)
                paths.append(p)
            plugin = types.SimpleNamespace(
                php_files=paths, root=d, slug="monotone-probe", cleanup=lambda: None)
            return {f.vuln_class for f in te.detect(plugin)}
    finally:
        if old is None:
            os.environ.pop("WISP_MONOTONE_PROPS", None)
        else:
            os.environ["WISP_MONOTONE_PROPS"] = old
        import wisp.engine.taint_engine as te2
        importlib.reload(te2)


def test_deferred_sanitizer_is_not_reported_with_the_flag_off():
    """Baseline: the engine as shipped does not call this XSS. If it does, the fixture is wrong."""
    got = _classes_with(False, {"a_seed.php": RAW_SEED, "z_chain.php": SANITIZER_CHAIN})
    assert "xss" not in got, (
        "the shipped engine already reports this sanitized property as XSS, so the fixture cannot "
        f"tell us anything about the accumulation change: {sorted(got)}")


def test_accumulation_does_not_resurrect_a_sanitized_property():
    """The predicted failure: a raw value recorded before the wrapper chain resolved stays raw.

    If this fails, accumulation is trading convergence for false positives and needs a deletion
    path, not a wider cap."""
    got = _classes_with(True, {"a_seed.php": RAW_SEED, "z_chain.php": SANITIZER_CHAIN})
    assert "xss" not in got, (
        "accumulating TAINTED_PROPS resurrected taint on a property that a sanitizer wrapper "
        f"cleans, which is the reviewer's predicted regression: {sorted(got)}")


def test_the_real_flow_is_still_found_with_the_flag_on():
    """The other direction. A genuinely unsanitized setter must still be reported, or the flag has
    bought convergence by making the analysis blind."""
    unsafe = """<?php
class Plain_Property_Flow {
  function set_it($v){ $this->slot = $v; }
  function seed(){ $this->set_it($_GET['html']); }
  function out(){ echo $this->slot; }
}
"""
    got = _classes_with(True, {"only.php": unsafe})
    assert "xss" in got, (
        f"the unsanitized setter flow disappeared with accumulation on: {sorted(got)}")
