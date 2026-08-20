#!/usr/bin/env python3
"""Score the calibration study on three or more fully blind annotators.

The v3 scorer reports annotator B alone and puts A beside it, because only B declared no knowledge
of the study's objective. That is the honest reading of a two-annotator study with one blind arm,
and the paper reports the resulting number as directional rather than calibrated for exactly that
reason. The reviewer's P0-4 asks for the study to be re-run with at least three annotators, all
blind, so that the number rests on a panel rather than on one reader.

This file is the scorer that panel needs. It is separate from v3 rather than an edit of it, because
v3 is what produced the shipped numbers and rewriting it would silently restate them. v3 keeps
scoring the study that was run. v4 scores the study that P0-4 asks for, and until three sheets come
back it has nothing to score and says so.

What it computes, and what each is for:

  per-annotator rate     the share of findings each annotator calls SAME_DEFECT. Reported for every
                         annotator, never averaged into a single arm, because the spread between
                         them is the thing a single-judge study could not show.
  majority rate          the share where a strict majority of the panel says SAME_DEFECT. This is
                         the headline the panel supports.
  unanimous rate         the share where every annotator agrees on SAME_DEFECT, reported beside the
                         majority as the conservative reading.
  Fleiss kappa           agreement over the whole panel on the root-cause axis, with a
                         record-cluster bootstrap, because packets drawn from one advisory are not
                         independent.
  overstatement factor   the geometric patch-file rate over the panel's majority rate, on the same
                         findings, with the paired slug-cluster bootstrap v3 uses, so the interval
                         is comparable to the one already in the paper.

The eligibility gate is not advisory. A panel member who declares knowledge of the study's
objective, or authorship of the paper, is refused rather than footnoted, because "all blind" is the
condition P0-4 sets and a study that quietly relaxes it answers a different question.

    python3 -m eval.defect_study_result_v4 --returned <dir> --reviewers A,B,C
"""
from __future__ import annotations
import argparse, json, os, sys, platform, time
from collections import Counter, defaultdict

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C
from eval.analyze_v3 import boot_rate, _slug_index
from eval.defect_study_result_v3 import boot_ratio
from eval.defect_study_reconciliation_lock_v4 import _read_sheet

SYS_ROOT = C.SYS_ROOT
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "DEFECT_STUDY_SAMPLE_V3.json")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "DEFECT_STUDY_RESULT_V4.json")
AXIS = "root_cause_relation"
HIT = "SAME_DEFECT"
MIN_PANEL = 3
REPS = 10000
SEED = 20260820


def fleiss_kappa(rows) -> float | None:
    """Fleiss' kappa over `rows`, each a list of one item's categorical ratings.

    Cohen's kappa is a two-rater statistic and does not extend to a panel, so the panel number is
    Fleiss'. Items must all carry the same number of ratings, which is what a complete panel means;
    an item any annotator skipped is dropped upstream rather than being given a smaller n here,
    because a varying n changes the expected agreement and would quietly move the statistic.
    """
    if not rows:
        return None
    n = len(rows[0])
    if n < 2 or any(len(r) != n for r in rows):
        return None
    cats = sorted({c for r in rows for c in r})
    N = len(rows)
    counts = np.array([[Counter(r)[c] for c in cats] for r in rows], dtype=float)
    p_i = (counts * (counts - 1)).sum(1) / (n * (n - 1))
    p_bar = p_i.mean()
    p_e = ((counts.sum(0) / (N * n)) ** 2).sum()
    return None if p_e >= 1 else float((p_bar - p_e) / (1 - p_e))


def _boot_fleiss(units, reps=REPS, seed=SEED):
    """Record-cluster bootstrap of Fleiss' kappa, matching v3's clustering choice."""
    recs = sorted({u["record_uid"] for u in units})
    by = defaultdict(list)
    for u in units:
        by[u["record_uid"]].append(u)
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(reps):
        pick = rng.integers(0, len(recs), size=len(recs))
        us = [u for i in pick for u in by[recs[i]]]
        k = fleiss_kappa([[u["labels"][t] for t in u["panel"]] for u in us])
        if k is not None:
            out.append(k)
    if not out:
        return [None, None]
    lo, hi = np.percentile(out, [2.5, 97.5])
    return [round(float(lo), 4), round(float(hi), 4)]


def _geometry():
    g = {}
    with open(POP, encoding="utf-8") as fh:
        for ln in fh:
            if ln.strip():
                d = json.loads(ln)
                g[d["finding_uid"]] = d
    return g


def _metadata(path):
    if not os.path.isfile(path):
        return {}
    d = json.load(open(path, encoding="utf-8"))
    return d.get("payload", d)


def _eligibility(meta, panel):
    """Every reason this panel does not meet what P0-4 asks for. Empty list means it does."""
    bad = []
    for t in panel:
        m = meta.get(f"reviewer_{t}") or meta.get(t) or {}
        if not m:
            bad.append(f"annotator {t}: no declaration recorded")
            continue
        if str(m.get("knows_research_objective", "")).strip().lower() in ("yes", "true", "1"):
            bad.append(f"annotator {t}: declares knowledge of the study's objective, so the panel "
                       f"is not blind")
        if str(m.get("is_paper_author", "")).strip().lower() in ("yes", "true", "1"):
            bad.append(f"annotator {t}: declares authorship of the paper")
        try:
            yrs = float(str(m.get("years_experience", "")).strip() or "nan")
        except ValueError:
            yrs = float("nan")
        if yrs != yrs:
            bad.append(f"annotator {t}: years_experience is not a number")
    return bad


def _selftest() -> int:
    """Prove the arithmetic and prove the gate bites, on a synthetic panel with known answers.

    Synthetic, and deliberately so. No label here comes from a person and none is written anywhere
    a scorer of the real study could read. What is being tested is this file: that a majority of
    three is counted as a majority and not as a mean, that unanimity is stricter than majority,
    that Fleiss returns 1 on perfect agreement and about 0 on independent noise, and that an
    annotator declaring knowledge of the objective is refused rather than footnoted. Every one of
    those has a plausible wrong implementation that would still produce a number.
    """
    import tempfile
    from openpyxl import Workbook
    fails = []

    def want(cond, msg):
        if not cond:
            fails.append(msg)

    # ---- Fleiss on the two ends, where the right answer is known without a reference
    want(abs(fleiss_kappa([[HIT, HIT, HIT]] * 10 + [["UNRELATED"] * 3] * 10) - 1.0) < 1e-9,
         "Fleiss is not 1 on perfect agreement")
    rng = np.random.default_rng(3)
    noise = [[str(x) for x in rng.integers(0, 4, size=3)] for _ in range(4000)]
    k_noise = fleiss_kappa(noise)
    want(abs(k_noise) < 0.05, f"Fleiss is {k_noise:.3f} on independent noise, expected about 0")
    want(fleiss_kappa([[HIT, HIT], [HIT]]) is None, "Fleiss accepted a ragged panel")

    # ---- majority and unanimity, on a pattern whose counts are known by construction
    panel = ["A", "B", "C"]
    pat = ([[HIT, HIT, HIT]] * 5 +            # 5 unanimous hits
           [[HIT, HIT, "UNRELATED"]] * 3 +    # 3 majority hits, not unanimous
           [[HIT, "UNRELATED", "UNRELATED"]] * 4 +   # 4 minority, not a hit
           [["UNRELATED"] * 3] * 8)           # 8 unanimous misses
    units = [{"labels": dict(zip(panel, p)), "panel": panel} for p in pat]
    maj = lambda u: sum(1 for t in panel if u["labels"][t] == HIT) * 2 > len(panel)
    una = lambda u: all(u["labels"][t] == HIT for t in panel)
    want(sum(1 for u in units if maj(u)) == 8, "majority of three counted wrongly")
    want(sum(1 for u in units if una(u)) == 5, "unanimity counted wrongly")
    want(sum(1 for u in units if u["labels"]["A"] == HIT) == 12, "per-annotator count is wrong")
    # the trap: a mean of the three per-annotator rates is 0.40 here and the majority is 0.40 too
    # only by accident on this pattern, so use one where they differ
    pat2 = [[HIT, "UNRELATED", "UNRELATED"]] * 9 + [[HIT, HIT, HIT]] * 1
    u2 = [{"labels": dict(zip(panel, p)), "panel": panel} for p in pat2]
    mean_rate = sum(sum(1 for u in u2 if u["labels"][t] == HIT) for t in panel) / (3 * len(u2))
    want(abs(mean_rate - 0.40) < 1e-9, "the mean-of-annotators trap changed shape")
    want(sum(1 for u in u2 if maj(u)) == 1,
         "majority collapsed to the mean of the annotators, which is the wrong statistic")

    # ---- the eligibility gate must refuse, not footnote
    blind = {f"reviewer_{t}": {"knows_research_objective": "no", "is_paper_author": "no",
                               "years_experience": "6"} for t in panel}
    want(_eligibility(blind, panel) == [], f"a blind panel was refused: {_eligibility(blind, panel)}")
    aware = json.loads(json.dumps(blind))
    aware["reviewer_C"]["knows_research_objective"] = "yes"
    want(any("objective" in b for b in _eligibility(aware, panel)),
         "an annotator who knows the study's objective was accepted, which is the v3 defect")
    author = json.loads(json.dumps(blind))
    author["reviewer_B"]["is_paper_author"] = "yes"
    want(any("authorship" in b for b in _eligibility(author, panel)), "a paper author was accepted")
    nan = json.loads(json.dumps(blind))
    nan["reviewer_A"]["years_experience"] = ""
    want(any("years_experience" in b for b in _eligibility(nan, panel)),
         "a blank experience field was accepted")
    want(any("no declaration" in b for b in _eligibility({}, panel)),
         "a panel with no declarations at all was accepted")

    # ---- the sheet reader round-trips a workbook of the shape the annotators return
    d = tempfile.mkdtemp(prefix="v4-selftest-")
    p = os.path.join(d, "reviewer_A.xlsx")
    wb = Workbook()
    ws = wb.active
    ws.append(["finding_uid"] + C.TIER2_LABEL_AXES)
    ws.append(["uid-1", "MATCH", HIT, "SUFFICIENT", "HIGH", "SAME_SOURCE_SINK"])
    ws.append(["uid-2", "MISMATCH", "UNRELATED", "PARTIAL", "LOW", "OTHER"])
    wb.save(p)
    got = _read_sheet(p)
    want(set(got) == {"uid-1", "uid-2"}, f"the sheet reader lost rows: {sorted(got)}")
    want(got["uid-1"][AXIS] == HIT, f"the sheet reader misread the axis: {got['uid-1']}")

    if fails:
        print("SELFTEST FAILED, the scorer does not do what it claims:")
        for f in fails:
            print("  - " + f)
        return 1
    print("SELFTEST OK: majority is a majority and not a mean, unanimity is stricter, Fleiss is 1 "
          "on agreement and ~0 on noise, and the gate refuses an aware annotator, a paper author, "
          "a blank experience field and a missing declaration")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true",
                    help="prove the arithmetic and the eligibility gate, then exit")
    ap.add_argument("--returned", default=os.path.join(C.ADJ_DIR, "RETURNED-V4"))
    ap.add_argument("--reviewers", default="A,B,C",
                    type=lambda x: tuple(t.strip() for t in x.split(",") if t.strip()))
    ap.add_argument("--metadata", default=os.path.join(C.ADJ_DIR, "study-v4",
                                                       "ANNOTATOR_METADATA_V4.json"))
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--allow-small-panel", action="store_true",
                    help="score a panel of fewer than three. The result then records that it does "
                         "not meet P0-4 and the paper must keep saying directional.")
    a = ap.parse_args()

    if a.selftest:
        return _selftest()

    panel = list(a.reviewers)
    if len(panel) < MIN_PANEL and not a.allow_small_panel:
        sys.exit(f"P0-4 asks for at least {MIN_PANEL} annotators and this panel has {len(panel)}. "
                 f"Nothing is scored. Pass --allow-small-panel only to measure a partial panel, "
                 f"and expect the result to say it is not the study P0-4 asks for.")

    sheets = {}
    for t in panel:
        p = os.path.join(a.returned, f"reviewer_{t}.xlsx")
        if not os.path.isfile(p):
            sys.exit(f"annotator {t}: no returned workbook at {p}. The panel is not complete, so "
                     f"there is nothing to score. This is the people-side step P0-4 needs.")
        sheets[t] = _read_sheet(p)

    meta = _metadata(a.metadata)
    ineligible = _eligibility(meta, panel)
    if ineligible:
        print("PANEL DOES NOT MEET P0-4:")
        for b in ineligible:
            print("  - " + b)
        print("Refusing to write a result that would be read as the blind panel.")
        return 1

    common = sorted(set.intersection(*(set(s) for s in sheets.values())))
    if not common:
        sys.exit("the returned sheets share no finding_uid")
    geom = _geometry()
    units = []
    for u in common:
        g = geom.get(u)
        if g is None:
            continue
        labels = {t: sheets[t][u].get(AXIS, "") for t in panel}
        if any(not v for v in labels.values()):
            continue
        units.append({"finding_uid": u, "slug": g["slug"], "record_uid": g["record_uid"],
                      "panel": panel, "labels": labels,
                      "in_patched_file": bool(g.get("in_patched_file")),
                      "on_exact_changed_line": bool(g.get("on_exact_changed_line"))})
    if not units:
        sys.exit("no finding carries a label from every annotator")

    per = {}
    for t in panel:
        hits = [u for u in units if u["labels"][t] == HIT]
        per[t] = {"rate": round(len(hits) / len(units), 4), "n_hit": len(hits),
                  "ci95": boot_rate(units, lambda u, t=t: u["labels"][t] == HIT,
                                    reps=REPS, seed=SEED)["ci95"]}

    maj = lambda u: sum(1 for t in panel if u["labels"][t] == HIT) * 2 > len(panel)
    una = lambda u: all(u["labels"][t] == HIT for t in panel)
    n_maj = sum(1 for u in units if maj(u))
    n_una = sum(1 for u in units if una(u))
    n_geo = sum(1 for u in units if u["in_patched_file"])

    res = {
        "schema_version": "defect-study-result-v4",
        "script": "eval/defect_study_result_v4.py",
        "panel": panel, "panel_size": len(panel),
        "meets_p0_4_panel_size": len(panel) >= MIN_PANEL,
        "all_declared_blind": True,
        "n_findings": len(units),
        "n_records": len({u["record_uid"] for u in units}),
        "n_slugs": len({u["slug"] for u in units}),
        "axis": AXIS, "hit_label": HIT,
        "per_annotator": per,
        "majority": {"rate": round(n_maj / len(units), 4), "n_hit": n_maj,
                     "ci95": boot_rate(units, maj, reps=REPS, seed=SEED)["ci95"],
                     "rule": f"strictly more than {len(panel)//2} of {len(panel)} say {HIT}"},
        "unanimous": {"rate": round(n_una / len(units), 4), "n_hit": n_una,
                      "ci95": boot_rate(units, una, reps=REPS, seed=SEED)["ci95"]},
        "geometry_on_same_findings": {
            "in_patched_file": {"rate": round(n_geo / len(units), 4), "n_hit": n_geo,
                                "ci95": boot_rate(units, lambda u: u["in_patched_file"],
                                                  reps=REPS, seed=SEED)["ci95"]}},
        "fleiss_kappa": {
            "point": (lambda k: round(k, 4) if k is not None else None)(
                fleiss_kappa([[u["labels"][t] for t in panel] for u in units])),
            "ci95": _boot_fleiss(units),
            "cluster_unit": "advisory record", "replicates": REPS, "seed": SEED,
            "note": ("Fleiss rather than Cohen, because the panel has more than two raters. It is "
                     "not comparable to the 0.56 the two-annotator study reported, which is "
                     "Cohen's on one pair.")},
        "overstatement_factor": boot_ratio(units, lambda u: u["in_patched_file"], maj),
        "label_distribution": {t: dict(sorted(Counter(u["labels"][t] for u in units).items()))
                               for t in panel},
        "eligibility": {"checked": sorted(meta.keys()), "problems": []},
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": platform.python_version(),
        "what_this_does_not_settle": (
            "the panel measures how often annotators agree that a finding names the vendor's "
            "defect. It does not establish that the majority is right. It also does not transfer "
            "to the corpus: the sample is the stratified 200 drawn from the matched-sample finding "
            "population, and the supplement names that frame."),
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(res, open(a.out, "w", encoding="utf-8"), indent=1, sort_keys=True)
    print(f"panel of {len(panel)} on {len(units)} findings over {res['n_records']} records")
    for t in panel:
        print(f"  {t}: {per[t]['rate']:.4f}  {per[t]['ci95']}")
    print(f"  majority  {res['majority']['rate']:.4f}  {res['majority']['ci95']}")
    print(f"  unanimous {res['unanimous']['rate']:.4f}")
    print(f"  geometry  {res['geometry_on_same_findings']['in_patched_file']['rate']:.4f}")
    print(f"  Fleiss    {res['fleiss_kappa']['point']}  {res['fleiss_kappa']['ci95']}")
    print("wrote " + os.path.relpath(a.out, SYS_ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
