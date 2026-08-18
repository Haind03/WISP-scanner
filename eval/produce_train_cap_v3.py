#!/usr/bin/env python3
"""Regenerate the matched-100 WISP finding cache (train_cap.json) under the Evaluation Contract.

Runs WISP on each matched-100 record in its own subprocess under the canonical contract (GDA off,
sanitizer class propagation on, LLM verifier disabled, and the engine defaults the contract pins), at
a generous per-plugin budget so a pathological plugin cannot hang the batch, and writes the
train_cap.json the ladder consumes. Each record records its analysis convergence status, so the
ladder and the summaries can report the non-convergence census and a with/without sensitivity.

`--engine-env KEY=VALUE` runs a declared arm instead, for example the v1.2 baseline with
WISP_MONOTONE_PROPS=0 and WISP_PER_KEY_CAP=4. An overridden run writes an object rather than a bare
list, carrying the overrides and the config stamp, so two arms can never again be mistaken for each
other after the fact.

    python3 -m eval.produce_train_cap_v3 --out <DATA>/train_cap.json [--budget 300] [--limit N]
    python3 -m eval.produce_train_cap_v3 --out <...>/ctl_v12.json \\
        --engine-env WISP_MONOTONE_PROPS=0 --engine-env WISP_PER_KEY_CAP=4
"""
from __future__ import annotations
import os, sys, json, time, signal, argparse, subprocess
import multiprocessing as mp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.testset.scan_testset import map_class

BUDGET = 300


def _run_worker(vzip, budget, env_overrides=None):
    """WISP on one plugin via the contract worker; returns (findings_or_None, analysis_status, err).

    The config argument used to be the literal "{}", so this runner had no way to ask for anything
    but the canonical contract. That is how the 2026-08-13 engine control produced two arms that were
    byte-identical: the baseline arm was requested by exporting WISP_MONOTONE_PROPS=0 and
    WISP_PER_KEY_CAP=4 in the invoking shell, the worker applies the contract itself, and a shell
    variable is not a request the contract can see. Both arms ran the shipped engine and the control
    established nothing about the engine at all.

    Overrides now travel in the config, which is the channel eval/_wisp_worker.py already reads and
    the one eval/convergence_census_v3.py already uses. Since the contract pins both flags as of the
    same day, this is the only way left to run the baseline arm, which is the correct outcome: the
    baseline has to be asked for explicitly and recorded, not inherited from an environment.
    """
    cfg = json.dumps({"env": env_overrides} if env_overrides else {})
    cmd = [sys.executable, "-m", "eval._wisp_worker", vzip, cfg]
    p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        return None, {"complete": False}, "timeout"
    if p.returncode != 0 or not out.strip():
        return None, {}, f"harness_exit:{p.returncode}"
    d = json.loads(out)
    if not d.get("ok"):
        return None, {}, d.get("error", "wisp_error")
    return d["ranked"], (d.get("analysis_status") or {}), ""


def _one(task):
    row, budget, env_overrides = task
    ranked, status, err = _run_worker(row["vuln_zip"], budget, env_overrides)
    findings = []
    for f in (ranked or []):
        cls = (f.get("classes") or [""])[0]
        findings.append({
            "cls": map_class(cls), "file": f.get("file", ""), "line": int(f.get("line") or 0),
            "function": f.get("function", ""),
            "sink_file": f.get("sink_file", ""), "sink_line": f.get("sink_line", 0),
            "sink_function": f.get("sink_function", ""),
            "ep": f.get("entry_point", "unknown"),
            "ip": bool(f.get("sink_file") and f.get("sink_file") != f.get("file")),
            "conf": f.get("confidence", 0.0), "sink": f.get("rule", ""),
            "source": f.get("source", ""), "message": f.get("message", ""),
            "trace": f.get("trace", []) or []})
    return {"slug": row["slug"], "cve": row["cve"], "cls": map_class(row["cls"]),
            "gt": None, "findings": findings,
            "wisp_err": err, "wisp_converged": status.get("complete"),
            "wisp_n_findings": len(findings)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=os.path.join(
        os.path.dirname(ROOT), "revision-cns-v2", "baseline_v3", "matched100.sample"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--budget", type=int, default=BUDGET)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    # Repeatable KEY=VALUE passed to the engine through the worker's config, not through this
    # process's environment. The arm is then recorded in the output rather than being a property of
    # whoever launched it.
    ap.add_argument("--engine-env", action="append", default=[],
                    metavar="KEY=VALUE", help="engine flag override, repeatable")
    a = ap.parse_args()
    env_overrides = {}
    for kv in a.engine_env:
        if "=" not in kv:
            raise SystemExit(f"--engine-env expects KEY=VALUE, got {kv!r}")
        k, v = kv.split("=", 1)
        env_overrides[k] = v

    # An overridden run writes an object, the canonical run writes the bare list eleven modules read.
    # Letting an arm land on the canonical path would either break those readers or, worse, feed the
    # ladder a baseline-engine cache under the shipped name.
    if env_overrides and os.path.basename(a.out) == "train_cap.json":
        raise SystemExit("refusing to write an overridden arm to train_cap.json, which is the "
                         "canonical cache the ladder reads. Give the arm its own filename.")

    want = {l.strip() for l in open(a.sample) if l.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want and os.path.isfile(r["vuln_zip"])]
    if a.limit:
        rows = rows[:a.limit]
    arm = ("contract config" if not env_overrides
           else "OVERRIDDEN " + " ".join(f"{k}={v}" for k, v in sorted(env_overrides.items())))
    print(f"WISP matched-100 re-scan ({arm}, budget {a.budget}s): {len(rows)} records, "
          f"{a.workers} workers", flush=True)
    t0 = time.time()
    with mp.Pool(a.workers) as pool:
        recs = pool.map(_one, [(r, a.budget, env_overrides) for r in rows])
    nc = sum(1 for r in recs if r["wisp_converged"] is False)
    to = sum(1 for r in recs if r["wisp_err"] == "timeout")
    from eval import wisp_contract as _WC
    out = {"schema_version": "train-cap-v3", "records": recs,
           "engine_env_overrides": env_overrides,
           "config": _WC.config_stamp(env_overrides or None)} if env_overrides else recs
    json.dump(out, open(a.out, "w"), indent=1)
    print(f"wrote {len(recs)} records -> {a.out}  ({time.time()-t0:.0f}s; "
          f"{nc} non-converged, {to} timed out)", flush=True)


if __name__ == "__main__":
    main()
