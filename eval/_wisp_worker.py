#!/usr/bin/env python3
"""Scan ONE plugin with WISP, in a child process the parent can kill at a wall-clock budget.

WISP has no in-process per-plugin timeout, so the fair harness runs it here, in its own process
group (start_new_session in the parent), and kills the group at the budget. This is a real timeout,
not an elapsed-time check after the scan already finished. On a clean finish it writes a JSON object
to stdout (findings plus the analysis status); if the parent kills the group, nothing is written and
the parent records a dropped partial.

Configuration is the single Evaluation Contract (eval/wisp_contract.py): GDA off, sanitizer class
propagation on, LLM verifier disabled. The caller may request a named sensitivity variant
(config {"variant": "gda_on"|"sani_off"}) or pass explicit env overrides (config {"env": {...}}); the
old ablation caller's {"sani_class": "0"|"1"} is still honored. The worker always emits the analysis
status and the effective config so the parent can enforce the failure policy and stamp provenance.

    python3 -m eval._wisp_worker <vuln_zip> <config_json>
"""
from __future__ import annotations
import os, sys, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main():
    vzip = sys.argv[1]
    cfg = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}

    from eval import wisp_contract as WC              # noqa: E402
    overrides: dict = {}
    if cfg.get("variant") in WC.SENSITIVITY_VARIANTS:
        overrides.update(WC.SENSITIVITY_VARIANTS[cfg["variant"]])
    if isinstance(cfg.get("env"), dict):
        overrides.update(cfg["env"])
    if cfg.get("sani_class") in ("0", "1"):           # back-compat with the on/off ablation
        overrides["WISP_SANI_CLASS"] = cfg["sani_class"]
    eff = WC.apply_canonical_env(overrides)

    from eval.testset.scan_testset import _wisp_ranked  # noqa: E402
    import wisp.engine.taint_engine as te              # noqa: E402
    # _wisp_ranked reads config["wisp_gda"]; derive it from the effective canonical env.
    ranked_cfg = dict(cfg)
    ranked_cfg["wisp_gda"] = (eff.get("WISP_NO_GDA") == "unset")
    # _wisp_ranked applies the canonical env again. Hand it the overrides resolved here so the
    # arm's flag survives that second application instead of being reset to the canonical value.
    ranked_cfg["env"] = dict(overrides)
    try:
        ranked = _wisp_ranked(vzip, ranked_cfg)
        status = dict(te.LAST_ANALYSIS_STATUS)
        sys.stdout.write(json.dumps({"ok": True, "ranked": ranked,
                                     "analysis_status": status,
                                     "config": WC.config_stamp(overrides)}))
    except Exception as e:                       # ToolFailure or any engine error
        sys.stdout.write(json.dumps({"ok": False, "error": f"{type(e).__name__}:{e}"}))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
