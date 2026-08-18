"""F. Fixpoint completion status is surfaced, not silently dropped (Prompt 6 fix).

Pre-fix, `_stabilize_summaries` returned a bare bool that every call site in
`detect()` discarded, so a plugin whose summary table did not converge was reported
as if it were complete. Prompt 6 replaces the bool with a structured
`_StabilizeStatus` (converged flag, updates, rounds, capped keys, pending count,
global-cap flag), has `detect()` aggregate it across passes, and attaches it to the
returned finding list as `analysis_status`. A record whose table stops at a bounded
approximation is marked incomplete rather than counted as a clean success.

Post-fix invariant (this test now PASSES): the status is structured, a synthetic
non-converging call graph is reported as not converged, and detect() surfaces
non-convergence through analysis_status["complete"].
"""
from __future__ import annotations
import os, tempfile, shutil, itertools
from ._common import Evidence

from wisp.engine import taint_engine as te


def _force_nonconvergence():
    """Patch _build_summary so every rebuild differs while still returning a valid
    _Summary detect() can consume. Returns the original for restoration."""
    real = te._build_summary
    counter = itertools.count()
    def always_changes(*a, **k):
        s = real(*a, **k)
        s.name = f"{s.name}~{next(counter)}"   # never equals the previous summary
        return s
    te._build_summary = always_changes
    return real


class _Plugin:
    def __init__(self, root, files):
        self.root, self.php_files = root, files

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


def _write_plugin(text):
    d = tempfile.mkdtemp()
    f = os.path.join(d, "p.php")
    open(f, "w").write(text)
    return _Plugin(d, [f])


def test_nonconvergence_is_surfaced():
    ev = Evidence("F. fixpoint completion status")

    # 1. the return is a structured status with the required fields
    st = te._stabilize_summaries({}, {}, callers={})
    for field in ("converged", "updates", "rounds", "capped_keys", "pending_count",
                  "max_updates", "hit_global_cap"):
        assert hasattr(st, field), f"status missing field {field}"
    ev.show(f"empty stabilize -> converged={st.converged} fields ok")
    assert st.converged is True and st.to_dict()["n_capped_keys"] == 0

    # 2. a synthetic cyclic graph that always "changes" must NOT converge, and must
    #    report the caps it hit rather than a clean fixpoint
    saved = te._build_summary
    te._build_summary = lambda *a, **k: object()          # every rebuild differs
    try:
        N = 32
        definitions = {f"f{i}": (None, None, f"rel{i}", f"abs{i}") for i in range(N)}
        callers = {f"f{i}": [f"f{(i - 1) % N}"] for i in range(N)}   # ring re-queues forever
        status = te._stabilize_summaries(definitions, {}, callers=callers)
    finally:
        te._build_summary = saved
    ev.show(f"cyclic ring -> converged={status.converged} capped={len(status.capped_keys)} "
            f"pending={status.pending_count} global_cap={status.hit_global_cap}")
    assert status.converged is False, "the synthetic cyclic case must be reported as non-convergent"
    assert status.capped_keys or status.hit_global_cap, "a cap must be recorded on non-convergence"

    # 3. detect() surfaces convergence through analysis_status. A normal plugin
    #    converges; a forced non-converging build reports complete=False.
    plug = _write_plugin("<?php function h(){ echo $_GET['q']; } add_action('wp_ajax_nopriv_h','h');")
    try:
        res = te.detect(plug)
    finally:
        plug.cleanup()
    ev.show(f"detect() normal plugin -> analysis_status={res.analysis_status}")
    assert hasattr(res, "analysis_status"), "detect() must attach analysis_status"
    assert res.analysis_status["complete"] is True
    assert res.analysis_status["sani_class_propagation"] in (True, False)

    # force non-convergence inside detect() and confirm it is surfaced, not hidden
    plug2 = _write_plugin("<?php function a($x){ b($x); } function b($x){ a($x); echo $x; } "
                          "function h(){ a($_GET['q']); } add_action('wp_ajax_nopriv_h','h');")
    saved = _force_nonconvergence()
    try:
        res2 = te.detect(plug2)
    finally:
        te._build_summary = saved
        plug2.cleanup()
    ev.show(f"detect() forced non-convergence -> complete={res2.analysis_status.get('complete')} "
            f"n_capped={res2.analysis_status.get('n_capped_keys')}")
    assert res2.analysis_status["complete"] is False, (
        "a plugin whose summary table did not converge must be reported incomplete, not as a clean "
        "success")


if __name__ == "__main__":
    test_nonconvergence_is_surfaced()
