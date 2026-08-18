#!/usr/bin/env python3
"""Summary-fixpoint convergence measurement (Reviewer Report 2026-07-11, item 2.1).

The engine caps summary iteration at 3 passes with an early break when nothing
changes. The reviewer correctly notes the paper claimed convergence without
measuring it. This script replays the same pass-1 / pass-1b construction with a
raised cap (default 10) on the matched-100 vulnerable trees and records, per
plugin, the first pass after which no summary changed. If every plugin
stabilizes at pass <= 3, the production cap is a measured fixpoint on this
corpus; otherwise the paper must describe the analysis as depth-bounded.

Usage: python3 measure_convergence.py [--cap 10] [--sample sample_100.txt]
"""
import os, sys, json, argparse

R = os.environ.get("WISP_SYS_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WISP = os.path.join(R, "WISP_Scan")
sys.path.insert(0, WISP)

from wisp.engine.taint_engine import (_parser, _build_summary,
                                     _summary_key)                   # noqa: E402
from wisp.engine.taint_ast import _collect_functions, _fn_name        # noqa: E402
from eval.datasets.patchstack import load_rows                       # noqa: E402
from eval.localize import _unzip                                     # noqa: E402


def summaries_converge(root_dir, cap):
    """Replicate pass 1 + pass 1b of taint_engine with iteration cap `cap`.
    Returns dict: first stable pass (or cap if still changing), per-pass change
    counts, and unqualified-name collision statistics (reviewer item 2.2)."""
    from collections import Counter
    cache = {}
    summaries = {}
    names = Counter()
    for dirpath, _dirs, files in os.walk(root_dir):
        for f in files:
            if not f.endswith(".php"):
                continue
            p = os.path.join(dirpath, f)
            try:
                src = open(p, "rb").read()
            except OSError:
                continue
            if b"<?" not in src:
                continue
            try:
                rootn = _parser().parse(src).root_node
                funcs = _collect_functions(rootn, src)
            except Exception:
                continue
            cache[p] = (src, funcs)
            for fn in funcs:
                try:
                    names[_fn_name(fn, src)] += 1
                    s = _build_summary(fn, src, summaries)
                    summaries[_summary_key(fn, src)] = s
                except Exception:
                    continue
    dup_names = {n for n, c in names.items() if c > 1}
    stable_at = None
    pass_changes = []
    changed_dup, changed_uniq = 0, 0
    for it in range(1, cap + 1):
        changed = 0
        for _p, (src, funcs) in cache.items():
            for fn in funcs:
                try:
                    name = _summary_key(fn, src)
                    old = summaries.get(name)
                    new_s = _build_summary(fn, src, summaries)
                except Exception:
                    continue
                if (old is None
                        or new_s.tainted_params_to_sink != old.tainted_params_to_sink
                        or new_s.returns_tainted_from != old.returns_tainted_from
                        or new_s.returns_source_tainted != old.returns_source_tainted
                        or new_s.return_safe_for != old.return_safe_for
                        or new_s.source_return_safe_for != old.source_return_safe_for
                        or new_s.source_return_scoped_for != old.source_return_scoped_for
                        or new_s.return_invalidates_for != old.return_invalidates_for
                        or new_s.tainted_params_to_props != old.tainted_params_to_props):
                    summaries[name] = new_s
                    changed += 1
                    if it == cap:
                        if name in dup_names:
                            changed_dup += 1
                        else:
                            changed_uniq += 1
        pass_changes.append(changed)
        if not changed:
            stable_at = it
            break
    return {"stable_at_pass": stable_at, "pass_changes": pass_changes,
            "n_definitions": sum(names.values()), "n_names": len(names),
            "n_collision_names": len(dup_names),
            "defs_sharing_name": sum(c for c in names.values() if c > 1),
            "last_pass_changed_dup": changed_dup,
            "last_pass_changed_uniq": changed_uniq}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", type=int, default=10)
    ap.add_argument("--sample", default=os.path.join(R, "baselines", "sample_100.txt"))
    ap.add_argument("--out", default=os.path.join(R, "2026-07-08", "experiments",
                                                  "out", "convergence.json"))
    a = ap.parse_args()
    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]
    results = []
    seen_zip = set()
    for r in rows:
        zp = r.get("vuln_zip") or r.get("zip")
        if not zp or zp in seen_zip:
            continue
        seen_zip.add(zp)
        root = _unzip(zp)
        if not root:
            print("SKIP", r["slug"], "unzip failed", flush=True)
            continue
        try:
            m = summaries_converge(root, a.cap)
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)
        m["slug"] = r["slug"]
        results.append(m)
        print(f"{r['slug']:44s} stable_at={m['stable_at_pass']} "
              f"changes={m['pass_changes']} dup_names={m['n_collision_names']}"
              f"/{m['n_names']}", flush=True)
    conv = [x for x in results if x["stable_at_pass"] is not None]
    dist = {}
    for x in conv:
        dist[x["stable_at_pass"]] = dist.get(x["stable_at_pass"], 0) + 1
    tot_defs = sum(x["n_definitions"] for x in results)
    tot_shared = sum(x["defs_sharing_name"] for x in results)
    rep = {"cap": a.cap, "n_plugins": len(results),
           "n_converged_within_cap": len(conv),
           "stable_at_distribution": dict(sorted(dist.items())),
           "pct_definitions_sharing_unqualified_name":
               round(tot_shared / tot_defs, 4) if tot_defs else 0,
           "details": results}
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print(json.dumps({k: rep[k] for k in list(rep)[:5]}, indent=1))


if __name__ == "__main__":
    main()
