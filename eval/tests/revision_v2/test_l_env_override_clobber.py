"""L. `_wisp_ranked` clobbers the caller's contract-env override.

Introduced 2026-08-02 while bringing `eval/testset/scan_testset.py` under the Evaluation Contract.
`_wisp_ranked` was made to apply the canonical env itself:

    saved = {k: os.environ.get(k) for k in WC.CANONICAL_ENV}
    overrides = {"WISP_NO_GDA": None} if config.get("wisp_gda") else {}
    WC.apply_canonical_env(overrides)

`apply_canonical_env` starts from the full canonical mapping and applies only the overrides it is
handed, so a flag the CALLER already set is reset to its canonical value. `eval/_wisp_worker.py`
does exactly that: it resolves a sensitivity variant, or the ablation's `sani_class`, applies it,
and then calls `_wisp_ranked`, whose second application throws the override away.

Every arm of a sensitivity run therefore executed under the same configuration. The symptom that
exposed it: the sanitizer ablation of 2026-08-03 returned a paired class-emission delta of exactly
0.0000 with zero records separating the two arms, where the pre-contract run of 2026-07-30 had
+0.0411 and three separating records.

The observation point is the engine call itself. `_wisp_ranked` loads the plugin before it touches
the environment, so a fake path fails too early to see anything. Stubbing `load_plugin` and
`te.detect` runs the real env logic and records exactly what the engine would have read.
"""
from __future__ import annotations
import os

from ._common import Evidence


class _FakePlugin:
    php_files = ["fake.php"]

    def cleanup(self):
        pass


def _observe(config, caller_overrides):
    """Return the WISP_SANI_CLASS the engine would run under, given a caller that already applied
    `caller_overrides` before handing control to `_wisp_ranked`."""
    from eval import wisp_contract as WC
    from eval.testset import scan_testset as ST

    seen = {}

    def fake_detect(plug):
        seen["value"] = os.environ.get("WISP_SANI_CLASS", "<unset>")
        return []

    saved = {k: os.environ.get(k) for k in WC.CANONICAL_ENV}
    real_load, real_detect = ST.l1_ingest.load_plugin, ST.te.detect
    try:
        WC.apply_canonical_env(caller_overrides)          # what _wisp_worker does
        before = os.environ.get("WISP_SANI_CLASS", "<unset>")
        ST.l1_ingest.load_plugin = lambda _p: _FakePlugin()
        ST.te.detect = fake_detect
        ST._wisp_ranked("/nonexistent/not-a-plugin.zip", config)
    finally:
        ST.l1_ingest.load_plugin, ST.te.detect = real_load, real_detect
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return before, seen.get("value", "<engine never ran>")


def test_caller_env_override_survives_wisp_ranked():
    ev = Evidence("L. sensitivity override survives _wisp_ranked")

    before, after = _observe({"wisp_gda": True, "sani_class": "0", "env": {"WISP_SANI_CLASS": "0"}},
                             {"WISP_SANI_CLASS": "0"})
    ev.show(f"caller set WISP_SANI_CLASS={before}, engine would have seen {after}")
    assert after == "0", (
        f"_wisp_ranked reset WISP_SANI_CLASS from {before!r} to {after!r}. Every sensitivity arm "
        f"that routes through eval/_wisp_worker.py runs under the canonical configuration instead "
        f"of its own, so an ablation compares a configuration against itself.")

    # and the canonical default must still hold when the caller asks for nothing
    before_d, after_d = _observe({"wisp_gda": True}, {})
    ev.show(f"no caller override: canonical WISP_SANI_CLASS={after_d}")
    assert after_d == "1", (
        f"the canonical sanitizer setting is no longer applied when the caller overrides nothing "
        f"(saw {after_d!r}); the contract's Section 1 default has been lost")


def test_ablation_arms_are_not_identical_by_construction():
    """The two arms must resolve to different environments before a single plugin is scanned."""
    ev = Evidence("L. the two ablation arms differ")
    _, on = _observe({"wisp_gda": True, "sani_class": "1", "env": {"WISP_SANI_CLASS": "1"}},
                     {"WISP_SANI_CLASS": "1"})
    _, off = _observe({"wisp_gda": True, "sani_class": "0", "env": {"WISP_SANI_CLASS": "0"}},
                      {"WISP_SANI_CLASS": "0"})
    ev.show(f"ON arm -> WISP_SANI_CLASS={on}, OFF arm -> WISP_SANI_CLASS={off}")
    assert on != off, (
        f"both ablation arms resolve to WISP_SANI_CLASS={on!r}, so the ablation measures nothing")
