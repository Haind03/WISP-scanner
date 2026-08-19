#!/usr/bin/env python3
"""The geometric ladder on all 1108 corpus records, not the matched 100.

The paper's primary endpoint was measured on a 100-record diagnostic sample, 9 percent of the
corpus, and a reviewer asked the obvious question: the ground truth is diff-derived and automatic,
so why not run it on everything. The honest answer was that the full-corpus scan output stored only
per-record counts, with no file or line for individual findings, so the exact-changed-line rung
could not be derived from it. This scores the ladder on the full corpus from scans that do store
per-finding detail.

Method is the matched-sample method, unchanged: the pooled rank<=3 slice per tool, each finding
scored against a patch map built from that record's own vulnerable and patched archives, rates
bootstrapped with the plugin slug as the cluster so the 1108 records from 854 plugins are not
treated as independent. Reusing eval.analyze_v3's estimator rather than writing a second one is
deliberate, because two implementations of one statistic is how two numbers for one quantity start.

Both failure-policy arms come out of one scoring pass. The population file stores the raw geometry
of every finding together with the flag saying whether the contract withholds credit for it, so the
contract arm and the kept arm are two aggregations of one measurement rather than two measurements.
That also makes the run verifiable offline: --verify recomputes both arms from the shipped
population and compares them to the shipped result files, which takes seconds instead of the half
hour a rebuild of 1108 patch maps costs.

Each arm also carries a primary_effect block: the corpus-scale drop from the patched-file rung to
the exact-changed-line rung, per tool, with a plugin-clustered bootstrap interval on the difference
itself. The two rungs are nested on the same findings, so the difference cannot be intervalled by
subtracting the endpoints of the two marginal intervals, and it is resampled directly with the same
estimator, cluster and seed the matched-sample ladder uses.

    python3 -m eval.corpus_ladder_v3
    python3 -m eval.corpus_ladder_v3 --verify
    python3 -m eval.corpus_ladder_v3 --from-pop
"""
from __future__ import annotations
import os, sys, json, time, platform, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval import patch_geometry as pg
from eval import analyze_v3 as A

MAN = os.path.join(SYS_ROOT, "rerun_70e04ee", "full_1108_manifest.json")
OUTD = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
SCANS = {t: os.path.join(OUTD, f"CORPUS1108_{t.upper()}_CONTRACT_V3.json")
         for t in ("wisp", "semgrep", "progpilot", "wpt")}
OUT = os.path.join(OUTD, "CORPUS_LADDER_V3.json")
KEPT = os.path.join(OUTD, "CORPUS_LADDER_KEPT_V3.json")
POP = os.path.join(OUTD, "CORPUS_FINDING_POPULATION_V3.jsonl")
TOPK = 3
RUNGS = ("in_patched_file", "same_callable_as_change", "on_exact_changed_line",
         "within_5_changed_lines", "same_diff_hunk")

CLASSES = {"xss", "sqli", "rce", "lfi", "ssrf", "auth", "csrf", "deserial", "upload", "other"}


def map_class(c):
    c = (c or "").strip().lower()
    return c if c in CLASSES else "other"


def failed_record(tool, rec):
    """Contract v1 s4 rule 3, applied where it is symmetric: at the record level."""
    blk = rec.get(tool) or {}
    if blk.get("err"):
        return True
    if tool == "wisp":
        st = blk.get("analysis_status") or {"complete": True}
        return not st.get("complete", True)
    return False


POLICY_NOTE = {
    "contract": ("contract v1 s4 rule 3 at the record level, a record a tool failed on or whose "
                 "WISP analysis did not converge is credited at no rung"),
    "kept": ("rule 3 ignored, the arm the matched-sample ladder uses, so the two are comparable"),
}


def aggregate(units, tools, policy, n_ok, n_err):
    """One arm of the ladder, read off the raw-geometry population."""
    def credited(u, rung):
        if policy == "contract" and u.get("credit_withheld_non_convergence"):
            return False
        return bool(u[rung])

    per_tool = {}
    primary_effect = {}
    for tool in tools:
        sub = [u for u in units if u["tool"] == tool]
        per_tool[tool] = {"n_findings": len(sub)}
        for rung in RUNGS + ("class_match",):
            per_tool[tool][rung] = A.boot_rate(sub, lambda u, r=rung: credited(u, r), 10000)
        # The corpus-scale version of the matched sample's primary endpoint: how much of the
        # patched-file rate survives the move to the exact changed line. It has to be resampled
        # directly. The two rungs are nested on the same findings and positively correlated, so
        # differencing the endpoints of their two marginal intervals gives a width that is wrong by
        # an unknown amount and always in the conservative direction. Same estimator, same cluster
        # and same seed as analyze_v3.geometric_ladder's primary_effect on the matched 100, so the
        # two rows of the same quantity are produced by one implementation rather than two.
        primary_effect[tool] = {
            "drop_to_exact_changed_line": A.boot_diff(
                sub,
                lambda u: credited(u, "in_patched_file"),
                lambda u: credited(u, "on_exact_changed_line"), 10000)}
    return {
        "schema_version": "corpus-ladder-v3",
        "script": "eval/corpus_ladder_v3.py",
        "scope": ("the full 1108-record corpus, pooled rank<=%d per tool, scored against patch "
                  "maps built from each record's own archives" % TOPK),
        "failure_policy": policy + ": " + POLICY_NOTE[policy],
        "bootstrap_unit": "plugin_slug",
        "bootstrap_replicates": 10000,
        "seed": A.SEED,
        "records_scored": n_ok,
        "records_unresolved": n_err,
        "topk": TOPK,
        "per_tool": per_tool,
        "primary_effect": primary_effect,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": platform.python_version(),
    }


def _comparable(d):
    """Everything in a result file except the two fields that move on every run by design."""
    return {k: v for k, v in d.items() if k not in ("timestamp_utc", "python_version")}


def _load_population(pop_path):
    """The shipped per-finding population, or None with a reason printed."""
    if not os.path.isfile(pop_path):
        print("no population file at " + pop_path)
        return None
    units = [json.loads(l) for l in open(pop_path, encoding="utf-8") if l.strip()]
    if not units:
        print("population file is empty")
        return None
    if not all(u.get("raw_geometry") for u in units):
        print("population predates the raw-geometry schema, regenerate it first")
        return None
    return units


def rewrite_from_population(pop_path, paths):
    """Re-aggregate both arms from the shipped population and rewrite the result files.

    This is the same code path --verify runs, so it recomputes rather than edits: nothing is copied
    out of the old file except the two record counts, which are outputs of the scoring pass this
    mode does not redo and which the population cannot supply (21 of the 1108 records contributed no
    rank<=3 finding, so counting the population's records would silently report 1087 scored).

    It exists so a new derived block can be added to files that already ship, without paying the
    half hour a rescore of 1108 patch maps costs and without the rescore's exposure to an archive
    that moved. It refuses to write if any field that was already in the file moves, which is the
    property that makes the addition auditable: the only admissible difference is the new block.
    """
    units = _load_population(pop_path)
    if units is None:
        return 2
    tools = sorted({u["tool"] for u in units})
    fresh_by_path, bad = {}, 0
    for path, policy in paths:
        if not os.path.isfile(path):
            print("rewrite: missing %s, run the full scoring pass instead" % os.path.basename(path))
            return 2
        shipped = json.load(open(path, encoding="utf-8"))
        for k in ("records_scored", "records_unresolved"):
            if k not in shipped:
                print("rewrite: %s has no %s, run the full scoring pass instead"
                      % (os.path.basename(path), k))
                return 2
        fresh = aggregate(units, tools, policy, shipped["records_scored"],
                          shipped["records_unresolved"])
        drift = {k: (shipped[k], fresh.get(k)) for k in _comparable(shipped)
                 if fresh.get(k) != shipped[k]}
        if drift:
            print("rewrite: REFUSED on %s, a field that already shipped would change:"
                  % os.path.basename(path))
            for k, (was, now) in drift.items():
                print("    %s: shipped %r, recomputed %r" % (k, was, now))
            bad += 1
            continue
        added = sorted(set(_comparable(fresh)) - set(_comparable(shipped)))
        print("rewrite: %-28s unchanged fields %d, added %s"
              % (os.path.basename(path), len(_comparable(shipped)), added or "nothing"))
        fresh_by_path[path] = fresh
    if bad:
        return 2
    for path, fresh in fresh_by_path.items():
        json.dump(fresh, open(path, "w"), indent=1, sort_keys=True)
        print("wrote " + path)
    return 0


def verify(pop_path):
    """Recompute both arms from the shipped population and compare to the shipped result files.

    A population written before the raw-geometry change stored each rung already masked by the
    contract, which would make the kept arm silently reproduce the contract arm. Refuse it rather
    than report a match that means nothing.
    """
    if not os.path.isfile(pop_path):
        print("verify: no population file at " + pop_path)
        return 2
    units = [json.loads(l) for l in open(pop_path, encoding="utf-8") if l.strip()]
    if not units:
        print("verify: population file is empty")
        return 2
    if not all(u.get("raw_geometry") for u in units):
        print("verify: population predates the raw-geometry schema, regenerate it first")
        return 2
    tools = sorted({u["tool"] for u in units})
    n_ok = len({(u["slug"], u["cve"]) for u in units})
    bad = 0
    for path, policy in ((OUT, "contract"), (KEPT, "kept")):
        if not os.path.isfile(path):
            print("verify: missing %s" % os.path.basename(path))
            bad += 1
            continue
        shipped = json.load(open(path, encoding="utf-8"))
        fresh = aggregate(units, tools, policy, shipped.get("records_scored", n_ok),
                          shipped.get("records_unresolved", 0))
        ok = _comparable(fresh) == _comparable(shipped)
        print("verify: %-28s %s" % (os.path.basename(path), "MATCH" if ok else "MISMATCH"))
        if not ok:
            bad += 1
            if "primary_effect" not in shipped:
                print("    no primary_effect block in the shipped file, regenerate it")
            for tool in tools:
                for rung in RUNGS + ("class_match",):
                    a_ = fresh["per_tool"].get(tool, {}).get(rung)
                    b_ = shipped.get("per_tool", {}).get(tool, {}).get(rung)
                    if a_ != b_:
                        print("    %s %s: recomputed %s, shipped %s" % (tool, rung, a_, b_))
                for eff in ("drop_to_exact_changed_line",):
                    a_ = fresh["primary_effect"].get(tool, {}).get(eff)
                    b_ = (shipped.get("primary_effect") or {}).get(tool, {}).get(eff)
                    if a_ != b_:
                        print("    %s %s: recomputed %s, shipped %s" % (tool, eff, a_, b_))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=0, help="score only the first N records")
    ap.add_argument("--tools", default="", help="comma list, default every tool with a scan")
    ap.add_argument("--scan-dir", default="", help="read the scans from here instead")
    ap.add_argument("--out", default="", help="contract-arm output path override")
    ap.add_argument("--kept-out", default="", help="kept-arm output path override")
    ap.add_argument("--pop", default="", help="population path override")
    ap.add_argument("--verify", action="store_true",
                    help="recompute both arms from the shipped population and compare, no rescan")
    ap.add_argument("--from-pop", action="store_true",
                    help="re-aggregate both arms from the shipped population and rewrite the "
                         "result files, refusing if any field already in them would change")
    a = ap.parse_args()

    if a.verify:
        return verify(a.pop or POP)
    if a.from_pop:
        return rewrite_from_population(a.pop or POP,
                                       ((a.out or OUT, "contract"), (a.kept_out or KEPT, "kept")))

    scans_in = dict(SCANS)
    if a.scan_dir:
        scans_in = {t: os.path.join(a.scan_dir, os.path.basename(p))
                    for t, p in scans_in.items()}
    if a.tools:
        want = [x.strip() for x in a.tools.split(",") if x.strip()]
        scans_in = {t: p for t, p in scans_in.items() if t in want}
    missing = [t for t, p in scans_in.items() if not os.path.isfile(p)]
    if missing:
        sys.exit("missing full-corpus scan(s) for: " + ", ".join(missing))
    out_path = a.out or OUT
    kept_path = a.kept_out or KEPT
    pop_path = a.pop or POP
    man = {r["slug"] + "|" + r["cve"]: r for r in json.load(open(MAN, encoding="utf-8"))}
    scans = {t: {r["slug"] + "|" + r["cve"]: r
                 for r in json.load(open(p, encoding="utf-8"))["details"]}
             for t, p in scans_in.items()}

    keys = sorted(set().union(*(set(s) for s in scans.values())))
    if a.limit:
        keys = keys[:a.limit]
    units, n_ok, n_err = [], 0, 0
    t0 = time.time()
    for i, key in enumerate(keys, 1):
        m = man.get(key)
        if not m:
            n_err += 1
            continue
        try:
            pm = pg.build_patchmap_from_archives(
                {"slug": m["slug"], "cve": m["cve"],
                 "vuln_zip": m["vuln_zip"], "patched_zip": m["patched_zip"]})
        except Exception:
            n_err += 1
            continue
        n_ok += 1
        adv = None
        for t in scans:
            r = scans[t].get(key)
            if r:
                adv = map_class(r.get("cls", ""))
                break
        for tool, bykey in scans.items():
            rec = bykey.get(key)
            if not rec:
                continue
            blk = rec.get(tool) or {}
            withheld = failed_record(tool, rec)
            for f in (blk.get("findings_sample") or [])[:50]:
                rank = int(f.get("rank") or 0)
                if not rank or rank > TOPK:
                    continue
                cls = [map_class(c) for c in (f.get("classes") or [])] or [map_class(f.get("cls"))]
                g = pg.finding_geometry(pm, {"file": f.get("file", ""),
                                             "line": int(f.get("line") or 0),
                                             "reported_classes": cls}, adv)
                # geometry as measured, unmasked. The arm is applied in aggregate(), so one
                # population serves both and neither can drift from the other.
                u = {"slug": m["slug"], "cve": m["cve"], "tool": tool, "rank": rank,
                     "advisory_class": adv, "credit_withheld_non_convergence": withheld,
                     "raw_geometry": True}
                for rung in RUNGS:
                    u[rung] = bool(g.get(rung))
                u["class_match"] = adv in cls
                units.append(u)
        if i % 100 == 0:
            print(f"  {i}/{len(keys)} records, {len(units)} findings, "
                  f"{time.time() - t0:.0f}s", flush=True)

    with open(pop_path, "w", encoding="utf-8") as fh:
        for u in units:
            fh.write(json.dumps(u, sort_keys=True) + "\n")

    tools = sorted(scans_in)
    for path, policy in ((out_path, "contract"), (kept_path, "kept")):
        res = aggregate(units, tools, policy, n_ok, n_err)
        json.dump(res, open(path, "w"), indent=1, sort_keys=True)
        print(f"wrote {path}")
        for tool, v in res["per_tool"].items():
            de = res["primary_effect"][tool]["drop_to_exact_changed_line"]
            print(f"  {policy:8} {tool:10} n={v['n_findings']:6} "
                  f"file={v['in_patched_file']['rate']} "
                  f"exact={v['on_exact_changed_line']['rate']} "
                  f"drop={de['diff']} ci95={de['ci95']}")
    print(f"wrote {pop_path}")
    print(f"  {n_ok} records scored, {n_err} unresolved, {len(units)} findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
