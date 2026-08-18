#!/usr/bin/env python3
"""Sanitizer class-propagation ablation + convergence census on matched-100 (Prompt 6).

Runs WISP over the matched-100 manifest twice at the same wall-clock budget, once with class-scoped
sanitizer propagation ON (the engine default, WISP_SANI_CLASS unset) and once OFF (WISP_SANI_CLASS=0,
the ablation), under the same subprocess process-group timeout as the fair matrix. For each record it
captures class emission, patch-file success@K, finding count, and the analysis status returned by
detect() (converged, capped keys, pending). Reports the on/off delta and the count of records whose
summary table did NOT reach a fixpoint, so a capped record is never reported as a clean success.

    python3 -m eval.wisp_sani_ablation_v3 --sample <file> --budget 60 --workers 8
"""
from __future__ import annotations
import os, sys, json, time, signal, argparse, shutil, subprocess, hashlib
import multiprocessing as mp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip
from eval.testset.scan_testset import ToolFailure, _gt, _score, map_class

OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
WINDOW = 5
KS = (1, 3, 5, 10)


def _run_wisp(vzip, budget, sani):
    """WISP on one plugin in its own process group; kill at budget. Returns (ranked, status)."""
    cmd = [sys.executable, "-m", "eval._wisp_worker", vzip,
           json.dumps({"wisp_gda": True, "sani_class": sani})]
    p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, start_new_session=True)
    try:
        out, _err = p.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.wait()
        raise ToolFailure("timeout")
    if p.returncode != 0 or not out.strip():
        raise ToolFailure(f"harness_exit:{p.returncode}")
    d = json.loads(out)
    if not d.get("ok"):
        raise ToolFailure(d.get("error", "wisp_error"))
    return d["ranked"], d.get("analysis_status", {})


def scan_one(task):
    r, budget, sani = task
    res = {"slug": r["slug"], "cve": r["cve"], "cls": map_class(r["cls"]), "sani": sani,
           "err": "", "hit": False, "findings": 0, "converged": None, "n_capped_keys": None,
           "pending_count": None}
    for k in KS:
        res[f"pf{k}"] = 0
    vzip, pzip = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(vzip) and os.path.isfile(pzip)):
        res["err"] = "missing_archive"; return res
    vroot, proot = _unzip(vzip), _unzip(pzip)
    try:
        if not (vroot and proot):
            res["err"] = "archive_extract_error"; return res
        gt = _gt(vroot, proot)
        try:
            ranked, status = _run_wisp(vzip, budget, sani)
        except ToolFailure as e:
            res["err"] = str(e); return res
        except Exception as e:
            res["err"] = f"harness:{type(e).__name__}"; return res
        res["findings"] = len(ranked)
        res["converged"] = status.get("complete", status.get("converged"))
        res["n_capped_keys"] = status.get("n_capped_keys")
        res["pending_count"] = status.get("pending_count")
        res["sani_class_propagation"] = status.get("sani_class_propagation")
        class_emit, pf, cf, ch, cfn = _score(ranked, gt, res["cls"], WINDOW)
        res["hit"] = bool(class_emit)
        for k in KS:
            res[f"pf{k}"] = pf[k]
    finally:
        for d in (vroot, proot):
            if d:
                shutil.rmtree(d, ignore_errors=True)
    return res


def _arm(rows, budget, sani, workers):
    with mp.Pool(workers) as pool:
        det = pool.map(scan_one, [(r, budget, sani) for r in rows])
    n = len(det)
    done = [d for d in det if not d["err"]]
    nd = len(done)
    non_converged = [f"{d['slug']}|{d['cve']}" for d in done if d["converged"] is False]
    capped = [f"{d['slug']}|{d['cve']}" for d in done if (d["n_capped_keys"] or 0) > 0]
    agg = {"sani_class": sani, "sani_meaning": "ON (engine default, class-carrying)" if sani == "1"
           else "OFF (ablation, sanitized stored clean)",
           "n": n, "completed": nd,
           "coverage": round(nd / n, 4) if n else 0,
           "timeouts": sum(1 for d in det if d["err"] == "timeout"),
           "other_err": sum(1 for d in det if d["err"] and d["err"] != "timeout"),
           "class_emission_failure_as_miss": round(sum(1 for d in det if d["hit"]) / n, 4) if n else 0,
           "non_converged_records": len(non_converged),
           "non_converged_slugs": non_converged,
           "records_with_capped_keys": len(capped),
           "capped_slugs": capped}
    for k in KS:
        agg[f"patch_file_success_at_{k}"] = round(sum(d[f"pf{k}"] for d in det) / n, 4) if n else 0
    agg["details"] = det
    return agg


def _paired_completed(on_details, off_details):
    """Delta on records that completed (no timeout/error) in BOTH arms.

    A per-arm class-emission or pf@1 rate under failure-as-miss is confounded by
    which plugins happened to finish inside the budget, and that timeout draw
    varies run to run (it can flip the naive delta's sign). Restricting to the
    records completed in both arms removes the coverage confound and isolates the
    sanitizer setting's effect on the shared plugin set."""
    on = {(r["slug"], r["cve"]): r for r in on_details}
    off = {(r["slug"], r["cve"]): r for r in off_details}
    both = [k for k in on if not on[k]["err"] and k in off and not off[k]["err"]]
    n = len(both)
    if not n:
        return {"n_paired": 0}
    on_emit = round(sum(1 for k in both if on[k]["hit"]) / n, 4)
    off_emit = round(sum(1 for k in both if off[k]["hit"]) / n, 4)
    on_pf1 = round(sum(on[k]["pf1"] for k in both) / n, 4)
    off_pf1 = round(sum(off[k]["pf1"] for k in both) / n, 4)
    on_only = [f"{k[0]}|{k[1]}" for k in both if on[k]["hit"] and not off[k]["hit"]]
    off_only = [f"{k[0]}|{k[1]}" for k in both if off[k]["hit"] and not on[k]["hit"]]
    return {"n_paired": n,
            "class_emission_on": on_emit, "class_emission_off": off_emit,
            "class_emission_delta_on_minus_off": round(on_emit - off_emit, 4),
            "patch_file_success_at_1_on": on_pf1, "patch_file_success_at_1_off": off_pf1,
            "patch_file_success_at_1_delta_on_minus_off": round(on_pf1 - off_pf1, 4),
            "records_on_emits_off_does_not": on_only,
            "records_off_emits_on_does_not": off_only,
            "non_converged_on": sum(1 for k in both if on[k]["converged"] is False),
            "non_converged_off": sum(1 for k in both if off[k]["converged"] is False),
            "note": "primary ablation measure: timeouts dropped, shared plugin set. The per-arm "
                    "failure-as-miss deltas are timeout-confounded and can flip sign across runs."}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--budget", type=int, default=60)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()

    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows()
            if os.path.exists(r["vuln_zip"]) and r["slug"] + "|" + r["cve"] in want]

    def _git(*x):
        try:
            return subprocess.check_output(["git", "-C", ROOT, *x],
                                           stderr=subprocess.DEVNULL).decode().strip()
        except Exception:
            return ""
    prov = {"engine_commit": _git("rev-parse", "HEAD"),
            "engine_dirty": bool(_git("status", "--porcelain")),
            "taint_engine_sha256": hashlib.sha256(
                open(os.path.join(ROOT, "wisp", "engine", "taint_engine.py"), "rb").read()).hexdigest(),
            "budget_s": a.budget, "n_records": len(rows), "window": WINDOW, "ks": list(KS),
            "host": os.uname().sysname + " " + os.uname().release, "python": sys.version.split()[0],
            "note": "class-scoped sanitizer propagation default is ON; OFF is the ablation. Every "
                    "primary corpus run used the ON default.",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    print(f"sani ablation on {len(rows)} records @ {a.budget}s\n")
    on = _arm(rows, a.budget, "1", a.workers)
    print(f"ON  (default): cov={on['coverage']:.2f} emit={on['class_emission_failure_as_miss']:.3f} "
          f"pf@1={on['patch_file_success_at_1']:.3f} timeouts={on['timeouts']} "
          f"non_converged={on['non_converged_records']} capped={on['records_with_capped_keys']}", flush=True)
    off = _arm(rows, a.budget, "0", a.workers)
    print(f"OFF (ablation): cov={off['coverage']:.2f} emit={off['class_emission_failure_as_miss']:.3f} "
          f"pf@1={off['patch_file_success_at_1']:.3f} timeouts={off['timeouts']} "
          f"non_converged={off['non_converged_records']} capped={off['records_with_capped_keys']}", flush=True)

    delta = {"class_emission": round(on["class_emission_failure_as_miss"]
                                     - off["class_emission_failure_as_miss"], 4),
             "patch_file_success_at_1": round(on["patch_file_success_at_1"]
                                              - off["patch_file_success_at_1"], 4),
             "coverage": round(on["coverage"] - off["coverage"], 4)}
    paired = _paired_completed(on["details"], off["details"])
    out = {"schema_version": "sani-ablation-v3", "provenance": prov,
           "on_default": {k: v for k, v in on.items() if k != "details"},
           "off_ablation": {k: v for k, v in off.items() if k != "details"},
           "delta_on_minus_off_per_arm_CONFOUNDED": delta,
           "paired_completed_PRIMARY": paired,
           "on_details": on["details"], "off_details": off["details"]}
    os.makedirs(OUT, exist_ok=True)
    dst = os.path.join(OUT, "SANI_ABLATION_V3.json")
    json.dump(out, open(dst, "w"), indent=1)
    print(f"\nper-arm delta ON-OFF (timeout-CONFOUNDED): class_emission {delta['class_emission']:+.4f} "
          f"pf@1 {delta['patch_file_success_at_1']:+.4f}")
    print(f"PAIRED-COMPLETED (primary, timeouts dropped, {paired['n_paired']} records): "
          f"class_emission {paired['class_emission_delta_on_minus_off']:+.4f} "
          f"pf@1 {paired['patch_file_success_at_1_delta_on_minus_off']:+.4f}  "
          f"(ON-only emits: {len(paired['records_on_emits_off_does_not'])}, "
          f"OFF-only: {len(paired['records_off_emits_on_does_not'])})")
    print(f"non-converged records: ON {on['non_converged_records']}, OFF {off['non_converged_records']} "
          f"(of {on['completed']}/{off['completed']} completed)")
    print(f"wrote {os.path.relpath(dst, SYS_ROOT)}")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
