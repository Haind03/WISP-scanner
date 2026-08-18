#!/usr/bin/env python3
"""Diagnose why class-and-file@1 is low: for each matched-100 record, find the
rank of the FIRST finding that is both the advisory class and in a patch-changed
file. If such a finding exists but ranks > 1, a ranking change can recover cf@1.
If it does not exist, the miss is recall/class, not ranking.

Prints a breakdown and the recoverable set.
"""
import os, sys, json, argparse
from collections import Counter

WISP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = os.path.dirname(WISP)
sys.path.insert(0, WISP)
from wisp.engine import taint_engine as te
from wisp.engine import l1_ingest
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _changed_lines


def keyof(p):
    parts = p.split("/") if "/" in p else p.split(os.sep)
    return os.sep.join(parts[1:]) if len(parts) > 1 else p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=os.path.join(R, "baselines", "sample_100.txt"))
    ap.add_argument("--out", default=os.path.join(R, "2026-07-08", "experiments",
                                                  "out", "diag_cf1.json"))
    a = ap.parse_args()
    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]

    recs = []
    for r in rows:
        zp, patched = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(zp) and os.path.isfile(patched)):
            continue
        vroot, proot = _unzip(zp), _unzip(patched)
        if not vroot or not proot:
            continue
        try:
            vmap, pmap = _php_map(vroot), _php_map(proot)
            gt = {rel for rel, vf in vmap.items()
                  if rel in pmap and _changed_lines(vf, pmap[rel])}
            plug = l1_ingest.load_plugin(zp)
            findings = te.detect(plug) if (plug and plug.php_files) else []
            if plug:
                plug.cleanup()
            cls = r["cls"]
            # rank (1-based) of first finding in-GT-and-correct-class
            rank_cf = None
            rank_pf = None            # first in-GT (any class)
            top1_cls = findings[0].vuln_class if findings else None
            top1_in_gt = bool(findings) and keyof(findings[0].file) in gt
            correct_class_in_gt_exists = False
            for i, f in enumerate(findings):
                ingt = keyof(f.file) in gt
                if ingt and rank_pf is None:
                    rank_pf = i + 1
                if ingt and f.vuln_class == cls:
                    correct_class_in_gt_exists = True
                    if rank_cf is None:
                        rank_cf = i + 1
            recs.append({
                "slug": r["slug"], "cls": cls, "n": len(findings),
                "top1_cls": top1_cls, "top1_in_gt": top1_in_gt,
                "rank_first_correct_cf": rank_cf,   # None if never
                "rank_first_pf": rank_pf,
                "cf_achievable": correct_class_in_gt_exists,
            })
            tag = "CF@1" if rank_cf == 1 else ("RECOV" if rank_cf else ("PFonly" if rank_pf else "miss"))
            print(f"{tag:7s} {r['slug'][:34]:34s} adv={cls:8s} top1={top1_cls} "
                  f"rank_cf={rank_cf} rank_pf={rank_pf} n={len(findings)}", flush=True)
        finally:
            import shutil
            shutil.rmtree(vroot, ignore_errors=True)
            shutil.rmtree(proot, ignore_errors=True)

    n = len(recs)
    cf1 = sum(1 for x in recs if x["rank_first_correct_cf"] == 1)
    achievable = sum(1 for x in recs if x["cf_achievable"])
    recoverable = sum(1 for x in recs if x["cf_achievable"] and x["rank_first_correct_cf"] != 1)
    pf1_only = sum(1 for x in recs if x["top1_in_gt"] and x["rank_first_correct_cf"] != 1)
    # among recoverable, distribution of the rank the correct-class finding sits at
    ranks = Counter(x["rank_first_correct_cf"] for x in recs
                    if x["cf_achievable"] and x["rank_first_correct_cf"] != 1)
    # what class is top1 when pf@1 hit but cf@1 miss
    wrongclass = Counter(x["top1_cls"] for x in recs
                         if x["top1_in_gt"] and x["rank_first_correct_cf"] != 1)
    rep = {
        "n": n,
        "cf_at_1": round(cf1 / n, 3),
        "cf_achievable_anywhere": round(achievable / n, 3),
        "recoverable_by_ranking": recoverable,
        "recoverable_frac_of_n": round(recoverable / n, 3),
        "cf_at_1_ceiling_if_perfect_rank": round(achievable / n, 3),
        "pf1_hit_but_cf1_miss": pf1_only,
        "rank_of_correct_cf_when_recoverable": dict(sorted(ranks.items())),
        "top1_class_when_pf1hit_cf1miss": dict(wrongclass.most_common()),
        "details": recs,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print(json.dumps({k: rep[k] for k in list(rep)[:-1]}, indent=1))


if __name__ == "__main__":
    main()
