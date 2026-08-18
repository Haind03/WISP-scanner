#!/usr/bin/env python3
"""Design-weighted same-defect rate for BOTH adjudicated tools, from one estimand.

The paper reported a design-weighted rate for WISP (0.026) beside a raw rate for
wp-taint-scan (0.032) and called them indistinguishable. Those are different
estimands and cannot be compared. Worse, the stored weighted figure was computed
over 101 WISP findings while the raw rate is 3/107: the sheet has 200 rows but
only 191 unique finding_id values, because the id is sha1(slug|tool|file|line)
and omits the reported class, so two findings on one line collide. An earlier fix
taught the kappa script to merge by row position but never reached the weighting,
which silently dropped the 6 colliding WISP rows and 3 wp-taint-scan rows.

This recomputes both tools the same way, from the row-position merge, and reports
raw and weighted side by side so the comparison is between like and like.

Design. The sample is a quota per (advisory_class x rank) cell over each tool's
top-3 findings on matched-100, not a probability sample, so a raw mean is biased
toward whichever cells the quota over-fills. Each cell is therefore weighted by
its share of that tool's own top-3 population. Cells present in the population but
absent from the sample cannot be imputed and are reported, not hidden.

SD is credited only when BOTH reviewers marked it, matching the paper's claim that
"both reviewers marked the same defect on ...".

    python3 -m eval.adjudication_weighted --out out/paired_20260717/ADJ_WEIGHTED.json
"""
from __future__ import annotations
import os, sys, json, csv, random, argparse, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
RES = os.path.join(os.environ.get("WISP_SYS_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "final", "results")
WISP_CAP = "out/fill_20260714/train_cap.json"
WPT_RUN = "out/corrected_20260713/matched_100_baselines_final.json"
TOPK = 3


def load_sample():
    """The 200 adjudicated rows, merged by POSITION. filled_A and filled_B are the
    same sheet in the same order, so position is the only safe join: finding_id is
    not unique."""
    A = list(csv.DictReader(open(os.path.join(RES, "filled_A.csv"), encoding="utf-8")))
    B = list(csv.DictReader(open(os.path.join(RES, "filled_B.csv"), encoding="utf-8")))
    if len(A) != len(B):
        sys.exit(f"sheets differ in length: {len(A)} vs {len(B)}")
    key = json.load(open(os.path.join(RES, "adjudication_v2_key.json")))
    rows = []
    for a, b in zip(A, B):
        if a["finding_id"] != b["finding_id"] or a["line"] != b["line"]:
            sys.exit("sheets are not row-aligned; the position join is invalid")
        k = key.get(a["finding_id"])
        if k is None:
            sys.exit(f"no key entry for {a['finding_id']}")
        la = (a.get("reviewer_A") or "").strip().upper()
        lb = (b.get("reviewer_B") or "").strip().upper()
        rows.append({"tool": k["tool"], "rank": int(k["rank"]),
                     "cls": k["advisory_class"], "slug": k["slug"],
                     "sd": la == "SD" and lb == "SD", "a": la, "b": lb})
    return rows


def population():
    """Each tool's top-3 findings on matched-100, counted per (class x rank).

    The class MUST come from the canonical dataset. The wp-taint run's own 'cls'
    field is "other" on all 100 records (its manifest carried no vuln_type), so
    reading it here collapses the whole population into three cells and the
    weighted estimate silently excludes every cell the sample actually covers.
    """
    from eval.datasets.patchstack import load_rows
    cls_of = {r["slug"] + "|" + r["cve"]: r["cls"] for r in load_rows()}
    pop = {"wisp": collections.Counter(), "wpt": collections.Counter()}
    for r in json.load(open(WISP_CAP)):
        c = cls_of.get(r["slug"] + "|" + r["cve"], r["cls"])
        for i, _f in enumerate(r["findings"][:TOPK], 1):
            pop["wisp"][(c, i)] += 1
    for d in json.load(open(WPT_RUN))["details"]:
        key = d["slug"] + "|" + d["cve"]
        c = cls_of.get(key)
        if c is None:
            continue
        fs = (d.get("wpt") or {}).get("findings") or []
        for f in sorted(fs, key=lambda x: x.get("rank") or 0)[:TOPK]:
            pop["wpt"][(c, int(f.get("rank") or 0))] += 1
    return pop


def weighted(rows, pop, tool):
    smp = [r for r in rows if r["tool"] == tool]
    cells = collections.defaultdict(lambda: [0, 0])          # cell -> [sd, n]
    for r in smp:
        c = cells[(r["cls"], r["rank"])]
        c[1] += 1
        c[0] += 1 if r["sd"] else 0
    N = pop[tool]
    covered = {c: v for c, v in N.items() if c in cells}
    num = sum(N[c] * (cells[c][0] / cells[c][1]) for c in covered)
    den = sum(N[c] for c in covered)
    raw_sd = sum(1 for r in smp if r["sd"])
    return {"raw_sd": raw_sd, "raw_n": len(smp),
            "raw_rate": round(raw_sd / len(smp), 4) if smp else None,
            "weighted_rate": round(num / den, 4) if den else None,
            "population_top3": sum(N.values()),
            "population_covered": den,
            "cells_in_population": len(N), "cells_sampled": len(cells),
            "cells_unsampled": sorted(str(c) for c in N if c not in cells)}


def boot(rows, pop, tool, B, seed):
    """Stratified bootstrap: resample within each sampled cell, reweight, repeat."""
    rnd = random.Random(seed)
    smp = [r for r in rows if r["tool"] == tool]
    cells = collections.defaultdict(list)
    for r in smp:
        cells[(r["cls"], r["rank"])].append(1 if r["sd"] else 0)
    N = pop[tool]
    covered = [c for c in N if c in cells]
    den = sum(N[c] for c in covered)
    if not den:
        return None
    out = []
    for _ in range(B):
        num = 0.0
        for c in covered:
            v = cells[c]
            draw = [rnd.choice(v) for _ in v]
            num += N[c] * (sum(draw) / len(draw))
        out.append(num / den)
    out.sort()
    return [round(out[int(0.025 * B)], 4), round(out[int(0.975 * B)], 4)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260717)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    rows = load_sample()
    pop = population()
    n_by_tool = collections.Counter(r["tool"] for r in rows)
    print(f"merged {len(rows)} rows by position: " +
          ", ".join(f"{k}={v}" for k, v in sorted(n_by_tool.items())))
    dis = [r for r in rows if r["a"] != r["b"]]
    print(f"reviewer disagreements: {len(dis)}")

    rep = {"n_rows": len(rows), "join": "row position (finding_id is not unique)",
           "sd_rule": "both reviewers marked SD", "B": a.B, "seed": a.seed,
           "topk": TOPK, "tools": {}}
    for tool in ("wisp", "wpt"):
        d = weighted(rows, pop, tool)
        d["ci95_weighted"] = boot(rows, pop, tool, a.B, a.seed)
        rep["tools"][tool] = d
        print(f"\n  {tool}: raw {d['raw_sd']}/{d['raw_n']} = {d['raw_rate']}   "
              f"weighted {d['weighted_rate']}  CI {d['ci95_weighted']}")
        print(f"      population top-{TOPK} = {d['population_top3']}, "
              f"covered by sample = {d['population_covered']}, "
              f"cells {d['cells_sampled']}/{d['cells_in_population']}")
        if d["cells_unsampled"]:
            print(f"      UNSAMPLED cells (excluded from the weighted estimate): "
                  f"{', '.join(d['cells_unsampled'][:6])}")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
