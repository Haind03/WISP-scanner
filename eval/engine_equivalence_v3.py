#!/usr/bin/env python3
"""Prove the running engine is behaviourally identical to wisp-scanner-v1.1.

Every shipped table is stamped with the v1.1 engine (taint_engine.py sha db1285cd). The
working tree carries v1.2, which adds one hook: the per-definition rebuild cap is read
from WISP_PER_KEY_CAP instead of being the literal 4. The claim that this is inert when
the variable is unset must be demonstrated, not asserted: a reading of the diff is not
evidence that the findings and the convergence status are the same.

This script checks out v1.1 into a throwaway git worktree, runs both builds on the same
plugins under the canonical environment, and compares, per record:

  * the full ranked finding list (file, line, class, rank), and
  * the analysis status (converged, capped keys, global cap).

Any difference is reported per record and the script exits non-zero.

    python3 -m eval.engine_equivalence_v3 --n 12
"""
from __future__ import annotations
import os, sys, json, shutil, argparse, tempfile, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.datasets.patchstack import load_rows
from eval import wisp_contract as WC

BASELINE_COMMIT = "d705be9"
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "ENGINE_EQUIVALENCE_V3.json")


def run_worker(tree: str, vzip: str, timeout: int) -> dict:
    """Run eval._wisp_worker inside `tree` and return its parsed result."""
    env = dict(os.environ)
    env.pop("WISP_PER_KEY_CAP", None)          # the claim is about the DEFAULT
    env["PYTHONHASHSEED"] = "0"
    try:
        p = subprocess.run([sys.executable, "-m", "eval._wisp_worker", vzip, "{}"],
                           cwd=tree, capture_output=True, text=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    out = (p.stdout or "").strip()
    if not out:
        return {"ok": False, "error": f"no_output rc={p.returncode} {p.stderr[-200:]}"}
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return {"ok": False, "error": "unparseable"}


def signature(res: dict) -> dict:
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error", "")}
    st = res.get("analysis_status") or {}
    return {
        "ok": True,
        "findings": [[f.get("file", ""), f.get("line", 0),
                      (f.get("classes") or [None])[0]] for f in (res.get("ranked") or [])],
        "converged": st.get("complete"),
        "n_capped_keys": st.get("n_capped_keys"),
        "hit_global_cap": st.get("hit_global_cap"),
        "updates": st.get("updates"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=12, help="records to compare")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = [l.strip() for l in open(SAMPLE) if l.strip()][:a.n]
    sel = [rows[k] for k in keys if k in rows]

    wt = tempfile.mkdtemp(prefix="wisp-v11-")
    shutil.rmtree(wt, ignore_errors=True)
    try:
        subprocess.run(["git", "worktree", "add", "--detach", wt, BASELINE_COMMIT],
                       cwd=ROOT, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        sys.exit(f"could not create the v1.1 worktree: {exc.stderr}")

    baseline_engine = os.path.join(wt, "wisp", "engine", "taint_engine.py")
    got = WC.engine_source_sha256(baseline_engine)
    if got != WC.BASELINE_SHA256:
        subprocess.run(["git", "worktree", "remove", "--force", wt], cwd=ROOT)
        sys.exit(f"worktree engine sha {got[:8]} is not the v1.1 baseline "
                 f"{WC.BASELINE_SHA256[:8]}")
    # _wisp_worker landed after the tag; copy the runner in without touching the engine.
    for mod in ("_wisp_worker.py", "wisp_contract.py"):
        src = os.path.join(ROOT, "eval", mod)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(wt, "eval", mod))

    diffs, records = [], []
    try:
        for r in sel:
            key = r["slug"] + "|" + r["cve"]
            new = signature(run_worker(ROOT, r["vuln_zip"], a.timeout))
            old = signature(run_worker(wt, r["vuln_zip"], a.timeout))
            same = new == old
            rec = {"key": key, "identical": same}
            if not same:
                rec["v11"] = old
                rec["v12"] = new
                diffs.append(key)
            else:
                rec["n_findings"] = len(new.get("findings") or [])
                rec["converged"] = new.get("converged")
            records.append(rec)
            print(f"  {'SAME ' if same else 'DIFF '} {key} "
                  f"n={len(new.get('findings') or [])} converged={new.get('converged')}",
                  flush=True)
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", wt], cwd=ROOT,
                       capture_output=True)

    res = {
        "schema_version": "engine-equivalence-v3",
        "claim": "wisp-scanner-v1.2 with WISP_PER_KEY_CAP unset is behaviourally "
                 "identical to wisp-scanner-v1.1 (findings and analysis status)",
        "baseline_tag": WC.BASELINE_TAG, "baseline_sha256": WC.BASELINE_SHA256,
        "baseline_commit": BASELINE_COMMIT,
        "engine_tag": WC.ENGINE_TAG, "engine_sha256": WC.ENGINE_SHA256,
        "n_records": len(records),
        "n_identical": sum(1 for r in records if r["identical"]),
        "n_differing": len(diffs),
        "differing_keys": diffs,
        "records": records,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    print(f"\n{res['n_identical']}/{res['n_records']} identical; wrote {a.out}")
    if diffs:
        sys.exit(f"ENGINE NOT EQUIVALENT on {len(diffs)} record(s): {diffs}")
    print("ENGINE EQUIVALENCE HOLDS on this sample")


if __name__ == "__main__":
    main()
