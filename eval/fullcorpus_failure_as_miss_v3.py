#!/usr/bin/env python3
"""Full-corpus tables under the contract's failure policy, with the robustness arm.

Contract v1 s4 rule 3 makes a non-converged WISP analysis a miss over the full record
denominator, and s4's robustness clause asks for the same metrics with non-converged
records kept. The equal-budget matrix applies rule 3. The full-corpus tables
(tab:fullcorpus, tab:common) never did: they were built before the engine reported a
stabilization status, so every non-converged record was scored as a clean success.

Two of the endpoints are record-level (class emission) and two are finding-level
(whole-pool precision, ranked precision@K), and "miss" does not mean the same thing for
both, so this script is explicit rather than clever:

  kept        rule 3 ignored entirely. The published arm, and the robustness arm s4 also asks for.
  contract    THE HEADLINE. Rule 3 on the record-level endpoint (class emission) only, because
              that is where a failed record is a 0 for every tool alike and the comparison stays
              symmetric. The finding-level precisions are unchanged.
  miss        rule 3 pushed onto the finding-level precisions as well. Reported so the effect is
              visible, but it is not symmetric: a baseline that fails emits nothing, so its
              failures never enter a per-finding denominator while WISP's do.
  dropped     non-converged records removed from both sides. Reported for context only;
              it conditions on the records WISP happened to finish, which is the exact
              survivor bias this table criticises Progpilot for.

Only the WISP column can move: the baselines have no convergence notion.

    python3 -m eval.fullcorpus_failure_as_miss_v3 --census <corrected census json>
"""
from __future__ import annotations
import os, sys, json, glob, argparse
from decimal import Decimal, ROUND_HALF_UP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

WISP_GLOBS = ["out/paired_20260717/loc_full/loc_*.json",
              "out/fill_20260714/loc_full/loc_*.json"]
BASE = {"semgrep": "out/fill_20260714/atk_sg_1108.json",
        "progpilot": "out/fill_20260714/atk_pp_1108.json",
        "wpt": "out/fill_20260714/atk_wpt_1108.json"}
COMMON = "out/fill_20260714/common_subset_keys.json"
KS = ("1", "3", "5", "10")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "FULLCORPUS_FAILURE_AS_MISS_V3.json")


def rnd(v, dec=4):
    return float(Decimal(str(v)).quantize(Decimal("1." + "0" * dec), rounding=ROUND_HALF_UP))


def wisp_records(globs=None):
    for g in (globs or WISP_GLOBS):
        files = sorted(glob.glob(os.path.join(ROOT, g)))
        if not files:
            continue
        det = {}
        for f in files:
            for d in json.load(open(f))["details"]:
                det[d["slug"] + "|" + d["cve"]] = d
        if det and "topk_tp" in next(iter(det.values())):
            return det, g
    sys.exit("no WISP localization shards with per-record @K counters found")


def base_records(rel):
    return {d["slug"] + "|" + d["cve"]: d
            for d in json.load(open(os.path.join(ROOT, rel)))["details"]}


def stats(det, keys, nonconv=frozenset(), arm="kept", tool="wisp"):
    """Non-convergence is a WISP failure mode, so only WISP loses credit under `miss`.

    The `dropped` arm removes the same records for every tool, which is what makes it a
    coverage-conditioned view rather than a per-tool penalty. Charging a baseline for WISP's
    non-convergence would be nonsense; an earlier draft of this function did exactly that.
    """
    # Which metrics rule 3 acts on. It is a RECORD-level rule ("a miss over the full record
    # denominator"), and only WISP has the failure mode, so:
    #   emission      record-level  -> rule 3 applies in the contract arm
    #   pf@K, pool    finding-level -> it does not; a baseline that fails emits nothing and is
    #                                  never charged in a per-finding denominator, so charging
    #                                  WISP alone there would penalise the only tool whose
    #                                  failure mode is visible. Same argument as the ladder.
    withhold_record = (arm in ("miss", "contract") and tool == "wisp")
    withhold_finding = (arm == "miss" and tool == "wisp")
    sel = []
    for k in keys:
        d = det.get(k)
        if d is None:
            continue
        if k in nonconv and arm == "dropped":
            continue
        sel.append((k, d))
    if not sel:
        return None
    out = {}
    for K in KS:
        tp = sum(0 if (withhold_finding and k in nonconv) else d["topk_tp"][K] for k, d in sel)
        n = sum(d["topk_n"][K] for k, d in sel)
        out[f"pf@{K}"] = tp / n if n else 0.0
    ft = sum(0 if (withhold_finding and k in nonconv) else d["file_tp"] for k, d in sel)
    nf = sum(d["findings"] for k, d in sel)
    out["pool"] = ft / nf if nf else 0.0
    out["emission"] = sum(1 for k, d in sel
                          if d.get("hit") and not (withhold_record and k in nonconv)) / len(sel)
    out["f_per_rec"] = nf / len(sel)
    out["n"] = len(sel)
    out["n_nonconverged_in_view"] = sum(1 for k, _ in sel if k in nonconv)
    return out


def load_nonconverged(path):
    """Records whose analysis is KNOWN not to have converged. A record whose status is
    unknown because the run was killed at a budget is not counted: unknown is not false."""
    d = json.load(open(path))
    recs = d["records"] if isinstance(d, dict) else d
    nc, unknown = set(), set()
    for r in recs:
        key = r["slug"] + "|" + r["cve"]
        err = r.get("wisp_err") or ""
        if err == "timeout":
            unknown.add(key)
        elif err:
            continue
        elif r.get("wisp_converged") is False:
            nc.add(key)
    return nc, unknown




# --------------------------------------------------------------------------- paired intervals
def _metrics(det, keys, nonconv, tool):
    """Same metric set as eval/paired_ci.py, with the contract failure policy applied."""
    withhold_record = tool == "wisp"
    sel = [(k, det[k]) for k in keys if k in det]
    if not sel:
        return None
    out = {}
    for K in KS:
        tp = sum(d["topk_tp"][K] for _, d in sel)
        n = sum(d["topk_n"][K] for _, d in sel)
        out[f"pf@{K}"] = tp / n if n else None
    ft = sum(d["file_tp"] for _, d in sel)
    nf = sum(d["findings"] for _, d in sel)
    out["pool"] = ft / nf if nf else None
    out["emission"] = sum(1 for k, d in sel
                          if d.get("hit") and not (withhold_record and k in nonconv)) / len(sel)
    return out


def paired(tools, keys, nonconv, B=10000, seed=20260717):
    """Plugin-clustered paired bootstrap of WISP minus each baseline.

    Same unit, same resampling and the same undefined-replicate handling as
    eval/paired_ci.py, so the only difference from the published intervals is the failure
    policy: rule 3 withholds WISP's class-emission credit on non-converged records. The
    finding-level ratios are untouched (see stats()).
    """
    import random
    rnd = random.Random(seed)
    by_slug = {}
    for k in keys:
        by_slug.setdefault(k.split("|")[0], []).append(k)
    slugs = sorted(by_slug)
    names = [t for t in tools if t != "wisp"]
    fields = [f"pf@{K}" for K in KS] + ["pool", "emission"]
    draws = {t: {f: [] for f in fields} for t in names}
    for _ in range(B):
        rk = [k for _ in range(len(slugs)) for k in by_slug[rnd.choice(slugs)]]
        mn = _metrics(tools["wisp"], rk, nonconv, "wisp")
        for t in names:
            mt = _metrics(tools[t], rk, nonconv, t)
            for f in fields:
                a, b = (mn or {}).get(f), (mt or {}).get(f)
                if a is None or b is None:
                    continue
                draws[t][f].append(a - b)
    out = {}
    for t in names:
        out[t] = {}
        for f in fields:
            v = sorted(draws[t][f])
            if len(v) < B * 0.9:
                out[t][f] = {"note": f"undefined in {B - len(v)}/{B} replicates"}
                continue
            lo, hi = v[int(0.025 * len(v))], v[int(0.975 * len(v))]
            out[t][f] = {"lo": round(lo, 4), "hi": round(hi, 4),
                         "excludes_zero": bool(lo > 0 or hi < 0)}
    return out


ORDER = ["wisp", "semgrep", "progpilot", "wpt"]


def table_body(res, view, tools, keys, nonconv, path, counts):
    """The LaTeX body for tab:fullcorpus / tab:common, generated so the table cannot
    disagree with the prose the way the published one did (0.771 printed against 0.5478
    stated three lines above it)."""
    arm = res["arms"][view]["contract"]
    ci = res["paired"][view]
    def f3(x):
        return f"{x:.3f}"
    def cell(t, key, bold=False):
        v = f3(arm[t][key])
        return "\\textbf{%s}" % v if bold else v
    def ci_cell(t, key):
        c = ci[t][key]
        if "lo" not in c:
            return "n.d."
        return "[$%+0.3f$, $%+0.3f$]" % (c["lo"], c["hi"])
    L = ["% Auto-generated by eval/fullcorpus_failure_as_miss_v3.py. Do not edit by hand.",
         "% Contract failure policy: rule 3 applies to the record-level endpoint (class",
         "% emission); the finding-level ratios are conditional on emitting and are unchanged."]
    for K in KS:
        best = max(ORDER, key=lambda t: arm[t][f"pf@{K}"])
        L.append("%-2s & %s & %s & %s & %s & %s & %s & %s \\\\" % (
            K, cell("wisp", f"pf@{K}", best == "wisp"), cell("semgrep", f"pf@{K}", best == "semgrep"),
            cell("progpilot", f"pf@{K}", best == "progpilot"), cell("wpt", f"pf@{K}", best == "wpt"),
            ci_cell("semgrep", f"pf@{K}"), ci_cell("progpilot", f"pf@{K}"), ci_cell("wpt", f"pf@{K}")))
    L.append(r"\midrule")
    for label, key in (("all findings", "pool"), ("class emission", "emission")):
        best = max(ORDER, key=lambda t: arm[t][key])
        L.append("%s & %s & %s & %s & %s & %s & %s & %s \\\\" % (
            label, cell("wisp", key, best == "wisp"), cell("semgrep", key, best == "semgrep"),
            cell("progpilot", key, best == "progpilot"), cell("wpt", key, best == "wpt"),
            ci_cell("semgrep", key), ci_cell("progpilot", key), ci_cell("wpt", key)))
    # Accounting rows. WISP's "errors / timeouts" was 0 and stayed 0; what the contract adds
    # is a non-convergence row, which is the failure mode the published table had no column for.
    L.append(r"\midrule")
    n = arm["wisp"]["n"]
    def acct(label, vals, pct=False):
        cells = []
        for t in ORDER:
            v = vals[t]
            cells.append(("\\textbf{%d}" % v) if t == "wisp" else str(v))
            if pct:
                cells[-1] += " (%d\\%%)" % round(100 * v / n)
        return "%s & %s & & & \\\\" % (label, " & ".join(cells))
    L.append(acct("records with $\\geq$1 finding", counts["with_findings"], pct=True))
    L.append(acct("completed, no findings", counts["no_findings"]))
    L.append(acct("errors / timeouts", counts["errors"]))
    L.append("non-converged (WISP only) & \\textbf{%d} & -- & -- & -- & & & \\\\"
             % counts["nonconv"]["wisp"])
    if counts.get("findings_per_record"):
        fpr = counts["findings_per_record"]
        L.append("findings/record & %s & & & \\\\" % " & ".join(
            ("\\textbf{%.2f}" % fpr[t]) if t == "wisp" else ("%.2f" % fpr[t]) for t in ORDER))
    L.append(r"\bottomrule")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", required=True,
                    help="corrected census json (eval.convergence_census_v3 output or merge)")
    ap.add_argument("--out", default=OUT)
    # The WISP source is normally the first glob that exists, which is the live corpus cache. Naming
    # it explicitly lets the same analysis run against the v1.2 shard backup, which is how the
    # ablation gets a with-learning arm frozen to the run its without-learning arm came from,
    # instead of borrowing a headline macro that moves when the engine does.
    ap.add_argument("--wisp-glob", action="append", default=None,
                    help="repo-relative glob for the WISP localization shards, repeatable")
    a = ap.parse_args()

    wisp, src = wisp_records(a.wisp_glob)
    tools = {"wisp": wisp}
    tools.update({t: base_records(p) for t, p in BASE.items()})
    order = ["wisp", "semgrep", "progpilot", "wpt"]
    full = sorted(wisp)
    common = sorted(set(json.load(open(os.path.join(ROOT, COMMON)))))

    nc, unknown = load_nonconverged(a.census)
    nc_full = nc & set(full)
    print(f"WISP source: {src} ({len(full)} records); common subset {len(common)}")
    print(f"census: {len(nc)} known non-converged, {len(unknown)} unknown (timed out at the "
          f"census budget); {len(nc_full)} of the non-converged are in the corpus view")
    if unknown:
        print("NOTE: records with an UNKNOWN status are treated as converged here, which is "
              "the conservative direction for a failure-as-miss claim.")

    res = {
        "schema_version": "fullcorpus-failure-as-miss-v3",
        "contract": "EVALUATION-CONTRACT.md v1 s4 (rule 3 + robustness arm)",
        "census": os.path.relpath(a.census, SYS_ROOT),
        "wisp_source": src,
        "n_known_non_converged": len(nc),
        "n_unknown_status": len(unknown),
        "unknown_status_treated_as": "converged (conservative for a failure-as-miss claim)",
        "arms": {},
    }
    for view, keys in (("full_1108", full), ("common_520", common)):
        res["arms"][view] = {}
        for arm in ("kept", "contract", "miss", "dropped"):
            res["arms"][view][arm] = {
                t: {k: (rnd(v) if isinstance(v, float) else v)
                    for k, v in (stats(tools[t], keys, nc_full, arm, tool=t) or {}).items()}
                for t in order}

    res["paired"] = {}
    for view, keys in (("full_1108", full), ("common_520", common)):
        print(f"paired bootstrap ({view}) ...", flush=True)
        res["paired"][view] = paired(tools, keys, nc_full)

    latex = os.path.join(SYS_ROOT, "2026-07-07", "latex")
    for view, name in (("full_1108", "FULLCORPUS_TABLE.tex"),
                       ("common_520", "COMMON_TABLE.tex")):
        ks = full if view == "full_1108" else common
        counts = {"with_findings": {}, "no_findings": {}, "errors": {}, "nonconv": {}}
        for t in ORDER:
            det = tools[t]
            sel = [det[k] for k in ks if k in det]
            # The three rows must partition the record set. A record that errored has zero
            # findings too, so "completed, no findings" has to exclude it or the column
            # over-counts: 829 + 279 + 25 is 1133, not 1108.
            err = [d for d in sel if d.get("err")]
            ok = [d for d in sel if not d.get("err")]
            counts["with_findings"][t] = sum(1 for d in ok if d["findings"] > 0)
            counts["no_findings"][t] = sum(1 for d in ok if d["findings"] == 0)
            counts["errors"][t] = len(err) + (len(ks) - len(sel))
            counts["nonconv"][t] = (sum(1 for k in ks if k in nc_full) if t == "wisp" else 0)
            if view == "common_520":
                counts.setdefault("findings_per_record", {})[t] = (
                    sum(d["findings"] for d in sel) / len(sel) if sel else 0.0)
        res.setdefault("accounting", {})[view] = counts
        p = table_body(res, view, tools, None, nc_full, os.path.join(latex, name), counts)
        print("wrote", p)

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1, sort_keys=True)

    for view in ("full_1108", "common_520"):
        print(f"\n=== {view} ===")
        print(f"{'arm':8} {'tool':10} " + " ".join(f"{k:>9}" for k in
              ("pf@1", "pf@3", "pf@5", "pf@10", "pool", "emission")))
        for arm in ("kept", "contract", "miss", "dropped"):
            for t in order:
                s = res["arms"][view][arm][t]
                if not s:
                    continue
                print(f"{arm:8} {t:10} " + " ".join(
                    f"{s[k]:>9.4f}" for k in ("pf@1", "pf@3", "pf@5", "pf@10",
                                              "pool", "emission")) + f"  n={s['n']}")
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
