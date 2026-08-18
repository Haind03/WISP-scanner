#!/usr/bin/env python3
"""Reviewer-response statistics: plugin-clustered uncertainty, common-subset and
failure-as-miss accounting, macro averages, and dataset accounting - all from the
EXISTING per-record result files (no rescans).

Motivation (Reviewer Report 2026-07-11, sections 3.6 / 3.10 / 3.8):
  * 1108 records span only 854 plugins, so record-level bootstrap / McNemar
    treats non-independent observations as independent. Everything here
    resamples PLUGIN SLUGS (clusters), not records.
  * precision@K conditioned on each tool's own answered subset is not
    comparable across tools; we add the common completed subset and
    failure-as-miss readings.
  * matched-100 representativeness: duplicate slugs, class mix.

Inputs (all pre-existing):
  WISP  s100 class hits : baselines/out_wisp_s100.json
  SG   s100 class hits : baselines/out_semgrep_s100.json
  PP   s100 class hits : baselines/out_progpilot_s100.json
  WPT  s100 class+@K   : baselines/out_wpt_s100.json
  SG   s100 @K         : baselines/out_sg_cf100.json
  PP   s100 @K         : baselines/out_pp_cf100.json
  WISP  s100 @K         : WISP_Scan re-run via eval.localize (per-record
                         patchfile_at_k / classfile_at_k), path via --wisp-atk
  WISP  full-1108 class : WISP_Scan/out/recall_full.json
  WPT  full-1108 class : baselines/wp_taint_scan_1108_t60.json
  WISP  s100 file prec  : WISP_Scan/out/localize_s100.json
  SG   s100 file prec  : baselines/out_sgprec_s100.json
  PP   s100 file prec  : baselines/out_ppprec_s100.json

Usage:  python3 cluster_stats.py [--wisp-atk PATH] [--out PATH]
"""
import json, os, argparse, random
from collections import defaultdict
from math import comb

# Inputs are the per-record result JSONs produced by reproduce_paper.sh plus the
# baseline runs; point BL/WISP at the directories holding them.
WISP = os.environ.get("WISP_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BL = os.environ.get("BASELINES_DIR", os.path.join(os.path.dirname(WISP), "baselines"))
R = os.path.dirname(WISP)
SEED, B = 42, 10000
KS = ("1", "3", "5", "10")


def load(p):
    return json.load(open(p))


def key(d):
    return d["slug"] + "|" + d["cve"]


# ---------------- clustered bootstrap ----------------

def cluster_boot_ci(records, stat, B=B, seed=SEED):
    """records: list of dicts each carrying 'slug'. Resample slugs with
    replacement; each draw keeps every record of the drawn slug."""
    by_slug = defaultdict(list)
    for r in records:
        by_slug[r["slug"]].append(r)
    slugs = sorted(by_slug)
    rng = random.Random(seed)
    n = len(slugs)
    xs = []
    for _ in range(B):
        s = []
        for _ in range(n):
            s.extend(by_slug[slugs[rng.randrange(n)]])
        xs.append(stat(s))
    xs.sort()
    return xs[int(0.025 * B)], xs[int(0.975 * B)]


def prop(field):
    return lambda recs: sum(r[field] for r in recs) / len(recs) if recs else 0.0


def macro_by_plugin(records, field):
    by_slug = defaultdict(list)
    for r in records:
        by_slug[r["slug"]].append(r[field])
    return sum(sum(v) / len(v) for v in by_slug.values()) / len(by_slug)


def mcnemar_exact(pairs):
    b = sum(1 for x, y in pairs if x and not y)
    c = sum(1 for x, y in pairs if y and not x)
    n = b + c
    if n == 0:
        return b, c, 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / 2 ** n
    return b, c, min(1.0, 2 * tail)


def _rkey(r):
    return r["key"] if "key" in r else key(r)


def cluster_delta_ci(recA, recB, field, B=B, seed=SEED):
    """Paired clustered bootstrap CI of mean(A)-mean(B); recA/recB keyed lists
    aligned on the same records."""
    by_slug = defaultdict(list)
    bmap = {_rkey(r): r for r in recB}
    for a in recA:
        by_slug[a["slug"]].append((a[field], bmap[_rkey(a)][field]))
    slugs = sorted(by_slug)
    rng = random.Random(seed)
    n = len(slugs)
    xs = []
    for _ in range(B):
        pairs = []
        for _ in range(n):
            pairs.extend(by_slug[slugs[rng.randrange(n)]])
        xs.append(sum(p[0] for p in pairs) / len(pairs)
                  - sum(p[1] for p in pairs) / len(pairs))
    xs.sort()
    return xs[int(0.025 * B)], xs[int(0.975 * B)]


def rget(d, *names, default=0):
    for n in names:
        if n in d:
            return d[n]
    return default


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wisp-atk", default="", help="eval.localize output with "
                    "per-record patchfile_at_k/classfile_at_k for WISP on s100")
    ap.add_argument("--out", default=os.path.join(WISP, "out", "cluster_stats.json"))
    a = ap.parse_args()
    res = {"seed": SEED, "resamples": B,
           "note": "all CIs are plugin-slug-clustered percentile bootstrap"}

    # ---------------- dataset accounting ----------------
    full = load(os.path.join(WISP, "out/recall_full.json"))["details"]
    slugs_full = defaultdict(int)
    for d in full:
        slugs_full[d["slug"]] += 1
    dist = defaultdict(int)
    for c in slugs_full.values():
        dist[c] += 1
    sample = [s.strip() for s in open(os.path.join(BL, "sample_100.txt")) if s.strip()]
    s_slugs = [k.split("|")[0] for k in sample]
    res["accounting"] = {
        "records_full": len(full),
        "unique_plugins_full": len(slugs_full),
        "records_per_plugin_dist": dict(sorted(dist.items())),
        "max_records_one_plugin": max(slugs_full.values()),
        "matched100_records": len(sample),
        "matched100_unique_slugs": len(set(s_slugs)),
        "matched100_dup_slugs": sorted({s for s in s_slugs if s_slugs.count(s) > 1}),
    }

    # ---------------- full-1108 class recall, clustered ----------------
    wisp_full = [{"slug": d["slug"], "cve": d["cve"], "hit": int(d["hit"])} for d in full]
    lo, hi = cluster_boot_ci(wisp_full, prop("hit"))
    res["full1108_class_recall"] = {
        "WISP": {"micro": round(prop("hit")(wisp_full), 4),
                "ci95_clustered": [round(lo, 4), round(hi, 4)],
                "macro_by_plugin": round(macro_by_plugin(wisp_full, "hit"), 4)}}
    wpt_full = [{"slug": d["slug"], "cve": d["cve"], "hit": int(bool(d.get("hit")))}
                for d in load(os.path.join(BL, "wp_taint_scan_1108_t60.json"))["details"]]
    lo, hi = cluster_boot_ci(wpt_full, prop("hit"))
    res["full1108_class_recall"]["wp-taint-scan"] = {
        "micro": round(prop("hit")(wpt_full), 4),
        "ci95_clustered": [round(lo, 4), round(hi, 4)],
        "macro_by_plugin": round(macro_by_plugin(wpt_full, "hit"), 4)}
    # paired WISP vs WPT on full corpus
    common_fk = set(map(key, wisp_full)) & set(map(key, wpt_full))
    nA = [r for r in wisp_full if key(r) in common_fk]
    nB = [r for r in wpt_full if key(r) in common_fk]
    b, c, p = mcnemar_exact([( {key(r): r for r in nA}[k]["hit"],
                               {key(r): r for r in nB}[k]["hit"]) for k in sorted(common_fk)])
    lo, hi = cluster_delta_ci(nA, nB, "hit")
    res["full1108_class_recall"]["WISP_vs_WPT_paired"] = {
        "mcnemar_b_c_p_recordlevel": [b, c, round(p, 8)],
        "delta_ci95_clustered": [round(lo, 4), round(hi, 4)]}

    # ---------------- matched-100 per-record tables ----------------
    wisp100 = {key(d): d for d in load(os.path.join(BL, "out_wisp_s100.json"))["details"]}
    sg100 = {key(d): d for d in load(os.path.join(BL, "out_semgrep_s100.json"))["details"]}
    pp100 = {key(d): d for d in load(os.path.join(BL, "out_progpilot_s100.json"))["details"]}
    wpt100 = {key(d): d for d in load(os.path.join(BL, "out_wpt_s100.json"))["details"]}
    sgcf = {key(d): d for d in load(os.path.join(BL, "out_sg_cf100.json"))["details"]}
    ppcf = {key(d): d for d in load(os.path.join(BL, "out_pp_cf100.json"))["details"]}
    nesatk = {}
    if a.wisp_atk and os.path.exists(a.wisp_atk):
        nesatk = {key(d): d for d in load(a.wisp_atk)["details"]}

    ks_all = sorted(set(wisp100) & set(sg100) & set(pp100) & set(wpt100))

    def build(tool):
        """unified per-record rows: hit, ok, pf@K, cf@K (failure-as-miss: a
        record a tool errored on keeps pf=cf=0 and hit as recorded)."""
        rows = []
        for k in ks_all:
            slug = k.split("|")[0]
            r = {"slug": slug, "key": k}
            if tool == "WISP":
                r["hit"] = int(wisp100[k]["hit"]); r["ok"] = 1
                src = nesatk.get(k, {})
                pf, cf = src.get("patchfile_at_k", {}), src.get("classfile_at_k", {})
            elif tool == "Semgrep":
                d = sg100[k]
                r["hit"] = int(d["hit"]); r["ok"] = int(not d.get("err"))
                pf, cf = sgcf[k].get("pf", {}), sgcf[k].get("cf", {})
            elif tool == "Progpilot":
                d = pp100[k]
                r["hit"] = int(d["hit"]); r["ok"] = int(not d.get("err"))
                pf, cf = ppcf[k].get("pf", {}), ppcf[k].get("cf", {})
            else:  # wp-taint-scan
                d = wpt100[k]
                r["hit"] = int(rget(d, "class_hit", "hit"))
                r["ok"] = int(not d.get("err"))
                pf, cf = d.get("patchfile_at_k", {}), d.get("classfile_at_k", {})
            for K in KS:
                r["pf" + K] = int(rget(pf, K, int(K), default=0) or 0)
                r["cf" + K] = int(rget(cf, K, int(K), default=0) or 0)
            rows.append(r)
        return rows

    tools = {t: build(t) for t in ("WISP", "Semgrep", "Progpilot", "wp-taint-scan")}

    def summarize(rows, fields):
        out = {}
        for f in fields:
            lo, hi = cluster_boot_ci(rows, prop(f))
            out[f] = {"value": round(prop(f)(rows), 4),
                      "ci95_clustered": [round(lo, 4), round(hi, 4)]}
        return out

    fields = ["hit"] + ["pf" + K for K in KS] + ["cf" + K for K in KS]
    res["matched100_failure_as_miss"] = {
        "note": "denominator = all 100 records for every tool; a record the tool "
                "errored/timed out on scores 0 on every @K metric",
        "per_tool": {t: dict(summarize(rows, fields),
                             completed=sum(r["ok"] for r in rows))
                     for t, rows in tools.items()}}

    # paired tests on the primary endpoint (cf@K) and class hit
    paired = {}
    for other in ("Semgrep", "Progpilot", "wp-taint-scan"):
        entry = {}
        for f in ("hit", "cf1", "cf10", "pf1"):
            A, Br = tools["WISP"], tools[other]
            bmap = {r["key"]: r for r in Br}
            b, c, p = mcnemar_exact([(r[f], bmap[r["key"]][f]) for r in A])
            lo, hi = cluster_delta_ci(A, Br, f)
            entry[f] = {"mcnemar_b_c_p": [b, c, round(p, 8)],
                        "delta_ci95_clustered": [round(lo, 4), round(hi, 4)]}
        paired["WISP_vs_" + other] = entry
    res["matched100_paired"] = paired

    # ---------------- common completed subsets ----------------
    def subset(rows_by_tool, need):
        okk = set(ks_all)
        for t in need:
            okk &= {r["key"] for r in rows_by_tool[t] if r["ok"]}
        return okk

    for name, need in (("all4", ("WISP", "Semgrep", "Progpilot", "wp-taint-scan")),
                       ("no_progpilot", ("WISP", "Semgrep", "wp-taint-scan"))):
        okk = subset(tools, need)
        res.setdefault("matched100_common_subset", {})[name] = {
            "n": len(okk),
            "per_tool": {t: summarize([r for r in tools[t] if r["key"] in okk], fields)
                         for t in tools}}

    # ---------------- matched-100 file precision (findings-weighted) ------
    locf = os.path.join(WISP, "out/localize_s100.json")
    prec_src = {"WISP": {key(d): d for d in load(locf)["details"]},
                "Semgrep": {key(d): d for d in load(os.path.join(BL, "out_sgprec_s100.json"))["details"]},
                "Progpilot": {key(d): d for d in load(os.path.join(BL, "out_ppprec_s100.json"))["details"]}}
    wtp = {}
    for k, d in wpt100.items():
        tp = rget(d, "file_tp", default=0)
        wtp[k] = {"slug": k.split("|")[0], "file_tp": tp,
                  "file_fp": max(0, rget(d, "findings", default=0) - tp)}
    prec_src["wp-taint-scan"] = wtp

    def fprec(recs):
        tp = sum(r.get("file_tp", 0) for r in recs)
        fp = sum(r.get("file_fp", 0) for r in recs)
        return tp / (tp + fp) if tp + fp else 0.0

    res["matched100_file_precision_clustered"] = {}
    for t, m in prec_src.items():
        recs = [dict(m[k], slug=k.split("|")[0]) for k in ks_all if k in m]
        lo, hi = cluster_boot_ci(recs, fprec)
        res["matched100_file_precision_clustered"][t] = {
            "value": round(fprec(recs), 4),
            "ci95_clustered": [round(lo, 4), round(hi, 4)]}

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
