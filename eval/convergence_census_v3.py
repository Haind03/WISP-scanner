#!/usr/bin/env python3
"""Full-corpus non-convergence census, with timeout separated from non-convergence.

Contract v1 s4 says a record is a miss when the analysis did not converge, and requires
a per-dataset census of how many records did not converge and how many hit a per-key or
global cap. The shipped census (CORPUS_CONVERGENCE_CENSUS_V3.json) was produced under a
120 s per-plugin budget and recorded `wisp_converged: false` for every record, including
the 120 the harness killed at the budget. Those 120 have no analysis status at all: the
run never finished, so whether they would converge is unknown, not known-false. Rolling
them into one 294 figure overstates cap-bound non-convergence by 120 records, and it
contradicts the manuscript's own description of the corpus run as uncapped.

This script re-runs a record set with an explicit budget (0 = uncapped, matching the
corpus run the manuscript describes) and reports three distinct outcomes:

    converged            the summary table reached a fixpoint
    non_converged        the analysis finished and reported complete == false
                         (per-key cap and/or global cap fired) - this is the number
                         the contract's failure policy acts on
    unknown_timeout      killed at the budget, no status returned

    python3 -m eval.convergence_census_v3 --records <keys.txt> --budget 0 --out <json>
    python3 -m eval.convergence_census_v3 --merge <base.json> <patch.json> --out <json>

`--merge` folds an uncapped re-run of a subset into an earlier census, so the corrected
corpus census is derivable without re-running all 1108 records.
"""
from __future__ import annotations
import os, sys, json, time, signal, argparse, subprocess
from collections import Counter
from multiprocessing import Pool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.datasets.patchstack import load_rows
from eval import wisp_contract as WC

OUT_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")


def _run_one(task):
    """One record in its own process group, killed at `budget` seconds (0 = uncapped)."""
    row, budget, engine_env = task
    res = {"slug": row["slug"], "cve": row["cve"], "cls": row.get("cls", ""),
           "wisp_err": "", "wisp_converged": None, "wisp_n_findings": 0,
           "capped_keys": None, "hit_global_cap": None, "updates": None,
           "rounds": None, "elapsed_s": None}
    t = time.time()
    try:
        # Engine flags travel in the config, not in the ambient environment, so the census output
        # can name the configuration it measured. A run whose flags were exported by whichever
        # shell happened to launch it is not comparable to a baseline after the fact.
        cfg = {"env": dict(engine_env)} if engine_env else {}
        p = subprocess.Popen(
            [sys.executable, "-m", "eval._wisp_worker", row["vuln_zip"], json.dumps(cfg)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True)
        try:
            out, _ = p.communicate(timeout=budget if budget else None)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:
                pass
            p.communicate()
            res["wisp_err"] = "timeout"
            res["elapsed_s"] = round(time.time() - t, 1)
            return res
        d = json.loads(out) if out and out.strip() else {}
    except Exception as exc:
        res["wisp_err"] = f"harness:{type(exc).__name__}"
        res["elapsed_s"] = round(time.time() - t, 1)
        return res

    res["elapsed_s"] = round(time.time() - t, 1)
    if not d.get("ok"):
        res["wisp_err"] = d.get("error") or "no_output"
        return res
    st = d.get("analysis_status") or {}
    res["wisp_converged"] = bool(st.get("complete"))
    res["wisp_n_findings"] = len(d.get("ranked") or [])
    # Keep the findings, not only their count. The baseline census this run is compared against
    # carries them, and the question the comparison has to answer is how many findings the contract
    # credits, which is a scoring question over the findings and cannot be recovered from a count.
    res["findings"] = d.get("ranked") or []
    ck = st.get("capped_keys")
    res["capped_keys"] = len(ck) if isinstance(ck, (list, set, tuple)) else ck
    res["hit_global_cap"] = st.get("hit_global_cap")
    res["updates"] = st.get("updates")
    res["rounds"] = st.get("rounds")
    return res


def outcome(r: dict) -> str:
    if r.get("wisp_err"):
        return "unknown_timeout" if r["wisp_err"] == "timeout" else "error"
    return "converged" if r.get("wisp_converged") else "non_converged"


def summarize(records: list[dict]) -> dict:
    c = Counter(outcome(r) for r in records)
    n = len(records)
    nc = c["non_converged"]
    known = n - c["unknown_timeout"] - c["error"]
    return {
        "n_records": n,
        "converged": c["converged"],
        "non_converged": nc,
        "unknown_timeout": c["unknown_timeout"],
        "error": c["error"],
        "n_with_known_status": known,
        "non_convergence_rate_over_all_records": round(nc / n, 4) if n else None,
        "non_convergence_rate_over_known_status": round(nc / known, 4) if known else None,
        "capped_keys_only": sum(1 for r in records if outcome(r) == "non_converged"
                                and r.get("capped_keys") and not r.get("hit_global_cap")),
        "global_cap_only": sum(1 for r in records if outcome(r) == "non_converged"
                               and r.get("hit_global_cap") and not r.get("capped_keys")),
        "both_caps": sum(1 for r in records if outcome(r) == "non_converged"
                         and r.get("hit_global_cap") and r.get("capped_keys")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", help="file of slug|cve keys, one per line; default all 1108")
    ap.add_argument("--budget", type=int, default=0,
                    help="per-plugin wall-clock seconds; 0 = uncapped (the corpus run)")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--engine-env", action="append", default=[], metavar="KEY=VALUE",
                    help="engine flag passed to every worker and stamped into the output; "
                         "repeatable, e.g. --engine-env WISP_MONOTONE_PROPS=1")
    ap.add_argument("--merge", nargs=2, metavar=("BASE", "PATCH"),
                    help="fold PATCH's per-record outcomes into BASE and re-summarize")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    if a.merge:
        base = json.load(open(a.merge[0]))
        patch = json.load(open(a.merge[1]))
        brecs = base if isinstance(base, list) else base["records"]
        precs = patch if isinstance(patch, list) else patch["records"]
        pm = {r["slug"] + "|" + r["cve"]: r for r in precs}
        merged, replaced = [], 0
        for r in brecs:
            k = r["slug"] + "|" + r["cve"]
            if k in pm:
                merged.append(pm[k]); replaced += 1
            else:
                merged.append(r)
        res = {
            "schema_version": "convergence-census-v3",
            "note": "merged census: records re-run uncapped replace their capped outcome",
            "base": os.path.relpath(a.merge[0], SYS_ROOT),
            "patch": os.path.relpath(a.merge[1], SYS_ROOT),
            "records_replaced": replaced,
            "summary_before": summarize(brecs),
            "summary_after": summarize(merged),
            "records": merged,
        }
        json.dump(res, open(a.out, "w"), indent=1)
        print(f"replaced {replaced} records")
        print("before:", json.dumps(res["summary_before"]))
        print("after :", json.dumps(res["summary_after"]))
        print("wrote", a.out)
        return

    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    if a.records:
        keys = [l.strip() for l in open(a.records) if l.strip()]
        sel = [rows[k] for k in keys if k in rows]
        if len(sel) != len(keys):
            print(f"WARNING: {len(keys) - len(sel)} requested keys not in the corpus")
    else:
        sel = list(rows.values())

    engine_env = {}
    for item in a.engine_env:
        if "=" not in item:
            sys.exit(f"--engine-env wants KEY=VALUE, got {item!r}")
        k, v = item.split("=", 1)
        engine_env[k] = v

    env = WC.CANONICAL_ENV if hasattr(WC, "CANONICAL_ENV") else {}
    print(f"census over {len(sel)} records, budget={a.budget or 'uncapped'}, "
          f"workers={a.workers}, engine_env={engine_env or 'canonical only'}", flush=True)
    t0 = time.time()
    with Pool(a.workers) as pool:
        recs = pool.map(_run_one, [(r, a.budget, engine_env) for r in sel], chunksize=1)

    res = {
        "schema_version": "convergence-census-v3",
        "contract": "EVALUATION-CONTRACT.md v1 s4 (failure policy + non-convergence census)",
        "budget_s": a.budget,
        "budget_note": ("uncapped: the corpus run the manuscript describes"
                        if not a.budget else f"per-plugin wall-clock cap {a.budget}s"),
        "canonical_env": dict(env),
        "engine_env_overrides": dict(engine_env),
        "workers": a.workers,
        "elapsed_s": round(time.time() - t0, 1),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summarize(recs),
        "records": recs,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps(res["summary"], indent=1))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
