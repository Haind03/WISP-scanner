#!/usr/bin/env python3
"""Design-weighted same-defect rate with a repaired row key and two sensitivities.

Why this supersedes eval/adjudication_weighted.py
-------------------------------------------------
The sheet builder minted its row id as sha1(slug|tool|file|line)[:8] and stored
the per-row metadata in a dict under that id. The id omits rank and reported
class, so two findings that a tool reports on the same line under different
classes collide, and `key[fid] = ...` keeps only the last one. The sheet has 200
rows but 191 distinct ids.

The previous scorer already joined the two reviewer sheets by row position, so
no row was dropped, but it still read tool/rank/class from the collapsed key.
This version rebuilds the per-row metadata instead:

  tool   recovered exactly, because the tool string is inside the sha1 preimage,
         so testing both candidates identifies it without ambiguity (107 wisp,
         93 wpt, matching the previous split exactly).
  class  taken from the sheet row itself, which is what the reviewers saw.
  rank   matched back against the tool's own top-3 population on this record.

Measured damage from the collapsed key: tool wrong on 0 rows, rank wrong on 3,
advisory class wrong on 1. No row labelled same-defect by both reviewers was
among the colliding ids, so the headline counts (3/107 and 3/93) are unchanged.

Two sensitivities are reported beside the primary estimate:

  dedup      Five findings enter the sheet twice, because their plugin carries
             two advisories and the quota treats (advisory, finding) as the unit.
             The dedup arm collapses them to 195 distinct findings.
  clustered  The primary bootstrap resamples within (class x rank) cells, which
             mirrors the sampling design. The clustered arm resamples plugin
             slugs instead, which is conservative if findings within a plugin are
             correlated.

    python3 -m eval.adjudication_weighted_v3 --out out/ADJ_WEIGHTED_V3.json
"""
from __future__ import annotations
import os, sys, json, csv, random, hashlib, argparse, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# Standalone reproduction (reviewer 7): when WISP_REPRO_DATA is set the re-analysis
# reads every input from that one directory, so it runs from the shipped bundle with
# no repository checkout and no hardcoded machine path.
_RD = os.environ.get("WISP_REPRO_DATA")


def _rp(path):
    return os.path.join(_RD, os.path.basename(path)) if _RD else path


RES = _RD or os.path.join(os.environ.get("WISP_SYS_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "final", "results")
WISP_CAP = _rp("out/fill_20260714/train_cap.json")
WPT_RUN = _rp("out/corrected_20260713/matched_100_baselines_final.json")
TOPK = 3


def _fid(slug, tool, path, line):
    return "E" + hashlib.sha1(f"{slug}|{tool}|{path}|{line}".encode()).hexdigest()[:8]


def _norm(p):
    return (p or "").replace("\\", "/")


def population_index():
    """Each tool's top-3 findings on matched-100, as a population counter and as a
    lookup from (tool, slug, file, line, reported class) to the ranks it occupies."""
    from eval.datasets.patchstack import load_rows
    cls_of = {r["slug"] + "|" + r["cve"]: r["cls"] for r in load_rows()}
    pop = {"wisp": collections.Counter(), "wpt": collections.Counter()}
    lut = collections.defaultdict(set)
    for r in json.load(open(WISP_CAP)):
        c = cls_of.get(r["slug"] + "|" + r["cve"], r["cls"])
        for i, f in enumerate(r["findings"][:TOPK], 1):
            pop["wisp"][(c, i)] += 1
            lut[("wisp", r["slug"], _norm(f["file"]), int(f["line"] or 0),
                 f["cls"] or "")].add(i)
    for d in json.load(open(WPT_RUN))["details"]:
        c = cls_of.get(d["slug"] + "|" + d["cve"])
        if c is None:
            continue
        fs = (d.get("wpt") or {}).get("findings") or []
        for f in sorted(fs, key=lambda x: x.get("rank") or 0)[:TOPK]:
            rk = int(f.get("rank") or 0)
            pop["wpt"][(c, rk)] += 1
            lut[("wpt", d["slug"], _norm(f.get("file")), int(f.get("line") or 0),
                 (f.get("classes") or [""])[0] or "")].add(rk)
    return pop, lut


def load_sample(lut):
    """The 200 rows, joined by position, with metadata rebuilt per row."""
    A = list(csv.DictReader(open(os.path.join(RES, "filled_A.csv"), encoding="utf-8")))
    B = list(csv.DictReader(open(os.path.join(RES, "filled_B.csv"), encoding="utf-8")))
    if len(A) != len(B):
        sys.exit(f"sheets differ in length: {len(A)} vs {len(B)}")
    old = json.load(open(os.path.join(RES, "adjudication_v2_key.json")))
    rows, damage = [], collections.Counter()
    for i, (a, b) in enumerate(zip(A, B)):
        if a["finding_id"] != b["finding_id"] or a["line"] != b["line"]:
            sys.exit("sheets are not row-aligned; the position join is invalid")
        slug, path, line = a["slug"], _norm(a["file"]), int(a["line"] or 0)
        cand = [t for t in ("wisp", "wpt") if _fid(slug, t, path, line) == a["finding_id"]]
        if len(cand) != 1:
            sys.exit(f"row {i}: tool not recoverable from id {a['finding_id']}")
        tool = cand[0]
        o = old.get(a["finding_id"], {})
        ranks = lut.get((tool, slug, path, line, a["reported_class"]), set())
        if o.get("rank") in ranks:
            rank = o["rank"]                      # population agrees with the key
        elif ranks:
            rank = min(ranks)
            damage["rank_repaired"] += 1
        else:
            rank = o.get("rank")                  # not in population, keep the key
            damage["rank_unverifiable"] += 1
        if o.get("tool") != tool:
            damage["tool_repaired"] += 1
        if o.get("advisory_class") != a["advisory_class"]:
            damage["class_repaired"] += 1
        la = (a.get("reviewer_A") or "").strip().upper()
        lb = (b.get("reviewer_B") or "").strip().upper()
        rows.append({"row_uid": f"{a['finding_id']}#{i:03d}", "tool": tool, "rank": rank,
                     "cls": a["advisory_class"], "slug": slug, "file": path, "line": line,
                     "reported_class": a["reported_class"],
                     "sd": la == "SD" and lb == "SD", "a": la, "b": lb})
    return rows, damage


def dedup(rows):
    """Collapse findings that entered the sheet more than once. Identity is the
    finding itself, not the advisory it was drawn against."""
    seen, out = {}, []
    for r in rows:
        k = (r["tool"], r["slug"], r["file"], r["line"], r["reported_class"])
        if k in seen:
            if seen[k]["sd"] != r["sd"]:
                seen[k]["sd"] = seen[k]["sd"] or r["sd"]
            continue
        seen[k] = dict(r)
        out.append(seen[k])
    return out


def weighted(rows, pop, tool):
    smp = [r for r in rows if r["tool"] == tool]
    cells = collections.defaultdict(lambda: [0, 0])
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
            "population_top3": sum(N.values()), "population_covered": den,
            "cells_in_population": len(N), "cells_sampled": len(cells),
            "cells_unsampled": sorted(str(c) for c in N if c not in cells)}


def boot_cell(rows, pop, tool, B, seed):
    """Resample within each sampled (class x rank) cell: mirrors the quota design."""
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
            num += N[c] * (sum(rnd.choice(v) for _ in v) / len(v))
        out.append(num / den)
    out.sort()
    return [round(out[int(0.025 * B)], 4), round(out[int(0.975 * B)], 4)]


def boot_cluster(rows, pop, tool, B, seed):
    """Resample plugin slugs with replacement, then reweight the cells the
    resampled slugs happen to cover. Conservative under within-plugin correlation."""
    rnd = random.Random(seed)
    smp = [r for r in rows if r["tool"] == tool]
    by_slug = collections.defaultdict(list)
    for r in smp:
        by_slug[r["slug"]].append(r)
    slugs = sorted(by_slug)
    N = pop[tool]
    out = []
    for _ in range(B):
        draw = [rnd.choice(slugs) for _ in slugs]
        cells = collections.defaultdict(lambda: [0, 0])
        for s in draw:
            for r in by_slug[s]:
                c = cells[(r["cls"], r["rank"])]
                c[1] += 1
                c[0] += 1 if r["sd"] else 0
        covered = [c for c in N if c in cells]
        den = sum(N[c] for c in covered)
        if not den:
            continue
        out.append(sum(N[c] * (cells[c][0] / cells[c][1]) for c in covered) / den)
    if not out:
        return None
    out.sort()
    n = len(out)
    return [round(out[int(0.025 * n)], 4), round(out[int(0.975 * n)], 4)]


def kappa(rows):
    """Cohen's kappa over the three-way label, on the repaired row set."""
    labs = sorted({r["a"] for r in rows} | {r["b"] for r in rows})
    n = len(rows)
    obs = sum(1 for r in rows if r["a"] == r["b"]) / n
    ca = collections.Counter(r["a"] for r in rows)
    cb = collections.Counter(r["b"] for r in rows)
    exp = sum((ca[l] / n) * (cb[l] / n) for l in labs)
    return {"n": n, "agreement": round(obs, 4),
            "kappa": round((obs - exp) / (1 - exp), 4) if exp < 1 else None}


def arm(rows, pop, B, seed, clustered=False):
    out = {}
    for tool in ("wisp", "wpt"):
        d = weighted(rows, pop, tool)
        d["ci95_cell"] = boot_cell(rows, pop, tool, B, seed)
        if clustered:
            d["ci95_slug_clustered"] = boot_cluster(rows, pop, tool, B, seed)
        out[tool] = d
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260717)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    pop, lut = population_index()
    rows, damage = load_sample(lut)
    ded = dedup(rows)
    print(f"rows {len(rows)} (distinct findings {len(ded)}), "
          f"tools " + ", ".join(f"{k}={v}" for k, v in
                                sorted(collections.Counter(r['tool'] for r in rows).items())))
    print(f"key repairs: {dict(damage) or 'none'}")
    print(f"unique slugs: {len({r['slug'] for r in rows})}")

    rep = {"n_rows": len(rows), "n_distinct_findings": len(ded),
           "n_slugs": len({r["slug"] for r in rows}),
           "join": "row position; tool recovered from the sha1 preimage",
           "key_repairs": dict(damage), "sd_rule": "both reviewers marked SD",
           "B": a.B, "seed": a.seed, "topk": TOPK,
           "kappa_primary": kappa(rows), "kappa_dedup": kappa(ded),
           "primary": arm(rows, pop, a.B, a.seed, clustered=True),
           "dedup": arm(ded, pop, a.B, a.seed, clustered=True)}

    for name in ("primary", "dedup"):
        print(f"\n[{name}]")
        for tool in ("wisp", "wpt"):
            d = rep[name][tool]
            print(f"  {tool}: raw {d['raw_sd']}/{d['raw_n']} = {d['raw_rate']}   "
                  f"weighted {d['weighted_rate']}  cell-CI {d['ci95_cell']}  "
                  f"slug-CI {d['ci95_slug_clustered']}")
            if d["cells_unsampled"]:
                print(f"      unsampled cells: {', '.join(d['cells_unsampled'][:6])}")
    print(f"\nkappa primary {rep['kappa_primary']}  dedup {rep['kappa_dedup']}")
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("wrote", a.out)


if __name__ == "__main__":
    main()
