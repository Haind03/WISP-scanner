#!/usr/bin/env python3
"""Prove the engine in this working tree is behaviourally identical to the engine at a git ref.

The original use was the convergence ablation: every shipped table was stamped with the v1.1
engine (taint_engine.py sha db1285cd), the working tree carried v1.2, which adds one hook (the
per-definition rebuild cap is read from WISP_PER_KEY_CAP instead of being the literal 4), and the
claim that the hook is inert when the variable is unset had to be demonstrated rather than
asserted. A reading of the diff is not evidence that the findings and the convergence status are
the same.

The second use is provenance: the result JSONs record that the working tree was dirty at scan
time, and only one of the fifteen files in wisp/ was hashed at run time. Checking the tree out
clean at the released tag and comparing the full ranked finding list bounds what the other
fourteen files could have been doing.

Both uses are the same measurement, so the ref and its expected engine hash are arguments rather
than constants. An equivalence prover that can only prove one fixed pair is a guard scoped to
where the last bug was found.

This script checks --ref out into a throwaway git worktree, verifies the checked-out engine hashes
to --expect-sha and ABORTS BEFORE SCANNING ANYTHING if it does not, then runs both builds on the
same plugins under the canonical environment and compares, per record:

  * the full ranked finding list (file, line, class, rank), and
  * the analysis status (converged, capped keys, global cap, updates).

Any difference is reported per record and the script exits non-zero.

    python3 -m eval.engine_equivalence_v3 --n 12
    python3 -m eval.engine_equivalence_v3 --ref wisp-scanner-v1.0 --expect-sha d07a4bbc --n 14 \
        --out ../revision-cns-v2/out/ENGINE_CLEANTREE_EQUIVALENCE_V3.json
"""
from __future__ import annotations
import os, sys, json, shutil, argparse, tempfile, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.datasets.patchstack import load_rows
from eval import wisp_contract as WC

# Defaults reproduce the original invocation exactly: the v1.1 comparison arm, guarded against the
# contract's BASELINE_SHA256. Note that these two defaults no longer agree with each other, because
# BASELINE_SHA256 was later repurposed from v1.1 to the v1.2 configuration. The default invocation
# therefore aborts on the guard, which is the correct behaviour for a stale pair and is exactly
# what --ref / --expect-sha exist to fix. Neither default was silently re-pointed, because changing
# them would change what the recorded ENGINE_EQUIVALENCE_V3.json claimed to have compared.
BASELINE_COMMIT = "d705be9"
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "ENGINE_EQUIVALENCE_V3.json")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                          text=True).stdout.strip()


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


def status_of(sig: dict) -> dict:
    """The analysis-status half of a signature, so findings and status can be judged apart."""
    return {k: sig.get(k) for k in ("ok", "error", "converged", "n_capped_keys",
                                    "hit_global_cap", "updates")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=12, help="records to compare")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--ref", default=BASELINE_COMMIT,
                    help="git ref checked out into the throwaway worktree (the baseline arm)")
    ap.add_argument("--expect-sha", default=WC.BASELINE_SHA256, dest="expect_sha",
                    help="sha256 of wisp/engine/taint_engine.py that --ref MUST produce. "
                         "A prefix of at least 8 hex chars is accepted. Checked before any "
                         "scan runs, so a wrong checkout aborts rather than measuring.")
    a = ap.parse_args()

    expect = (a.expect_sha or "").strip().lower()
    if len(expect) < 8:
        sys.exit(f"--expect-sha must be at least 8 hex characters, got {expect!r}")

    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = [l.strip() for l in open(SAMPLE) if l.strip()][:a.n]
    sel = [rows[k] for k in keys if k in rows]

    wt = tempfile.mkdtemp(prefix="wisp-eqv-")
    shutil.rmtree(wt, ignore_errors=True)
    try:
        subprocess.run(["git", "worktree", "add", "--detach", wt, a.ref],
                       cwd=ROOT, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        sys.exit(f"could not create the worktree at {a.ref}: {exc.stderr}")

    baseline_engine = os.path.join(wt, "wisp", "engine", "taint_engine.py")
    got = WC.engine_source_sha256(baseline_engine)
    if not got.startswith(expect):
        subprocess.run(["git", "worktree", "remove", "--force", wt], cwd=ROOT)
        sys.exit(f"ABORT before scanning: worktree engine sha {got[:8]} at ref {a.ref} "
                 f"is not the expected {expect[:8]}")
    print(f"guard OK: {a.ref} -> engine {got[:8]} matches --expect-sha {expect[:8]}", flush=True)

    ref_commit = git("rev-parse", a.ref)
    tree_commit = git("rev-parse", "HEAD")
    tree_dirty = bool(git("status", "--porcelain"))

    # _wisp_worker landed after the tag; copy the runner in without touching the engine.
    for mod in ("_wisp_worker.py", "wisp_contract.py"):
        src = os.path.join(ROOT, "eval", mod)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(wt, "eval", mod))

    diffs, status_diffs, records = [], [], []
    try:
        for r in sel:
            key = r["slug"] + "|" + r["cve"]
            new = signature(run_worker(ROOT, r["vuln_zip"], a.timeout))
            old = signature(run_worker(wt, r["vuln_zip"], a.timeout))
            same = new == old
            same_findings = new.get("findings") == old.get("findings") and \
                new.get("ok") == old.get("ok")
            same_status = status_of(new) == status_of(old)
            rec = {"key": key, "identical": same,
                   "identical_findings": same_findings,
                   "identical_status": same_status,
                   "n_findings_tree": len(new.get("findings") or []),
                   "n_findings_ref": len(old.get("findings") or []),
                   "converged_tree": new.get("converged"),
                   "converged_ref": old.get("converged"),
                   "ok_tree": new.get("ok"), "ok_ref": old.get("ok")}
            if not same:
                rec["ref_arm"] = old
                rec["tree_arm"] = new
                diffs.append(key)
            if not same_status:
                status_diffs.append(key)
            records.append(rec)
            print(f"  {'SAME ' if same else 'DIFF '} {key} "
                  f"findings {len(old.get('findings') or [])}/{len(new.get('findings') or [])} "
                  f"converged {old.get('converged')}/{new.get('converged')}",
                  flush=True)
    finally:
        subprocess.run(["git", "worktree", "remove", "--force", wt], cwd=ROOT,
                       capture_output=True)

    res = {
        "schema_version": "engine-equivalence-v3",
        "claim": f"the engine in the working tree is behaviourally identical to the engine at "
                 f"git ref {a.ref} (full ranked finding list and analysis status), on the first "
                 f"{len(records)} records of matched100.sample, WISP_PER_KEY_CAP unset",
        "baseline_ref": a.ref,
        "baseline_commit": ref_commit or a.ref,
        "baseline_expect_sha256": expect,
        "baseline_engine_sha256": got,
        "baseline_tag": WC.BASELINE_TAG, "baseline_sha256": WC.BASELINE_SHA256,
        "engine_tag": WC.ENGINE_TAG, "engine_sha256": WC.ENGINE_SHA256,
        "tree_commit": tree_commit, "tree_git_dirty": tree_dirty,
        "sample": SAMPLE,
        "n_records": len(records),
        "n_identical": sum(1 for r in records if r["identical"]),
        "n_identical_findings": sum(1 for r in records if r["identical_findings"]),
        "n_identical_status": sum(1 for r in records if r["identical_status"]),
        "n_differing": len(diffs),
        "differing_keys": diffs,
        "status_differing_keys": status_diffs,
        "records": records,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    print(f"\n{res['n_identical']}/{res['n_records']} identical "
          f"(findings {res['n_identical_findings']}/{res['n_records']}, "
          f"status {res['n_identical_status']}/{res['n_records']}); wrote {a.out}")
    if diffs:
        sys.exit(f"ENGINE NOT EQUIVALENT on {len(diffs)} record(s): {diffs}")
    print("ENGINE EQUIVALENCE HOLDS on this sample")


if __name__ == "__main__":
    main()
