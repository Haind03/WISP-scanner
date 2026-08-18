#!/usr/bin/env python3
"""Plugin-class recall of WISP on a gold dataset (default: Patchstack).

Dataset-agnostic: pulls rows from a dataset adapter (eval/datasets/patchstack.py)
exposing load_rows() -> [{slug, cve, type, cls, vuln_zip}]. For each row, run the
WISP taint engine on the VULNERABLE zip and check whether the CVE's class is among
the detected classes.

    python3 -m eval.recall --out out/recall.json [--only-present]
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # project root
sys.path.insert(0, ROOT)
from wisp.engine import l1_ingest, taint_engine as te
from eval.datasets.patchstack import load_rows


def _score_row(r):
    """Run one archive in an isolated worker and return its score detail."""
    zp = r["vuln_zip"]
    det = set()
    nf = 0
    if os.path.isfile(zp):
        plug = None
        try:
            plug = l1_ingest.load_plugin(zp)
            if plug and plug.php_files:
                fnds = te.detect(plug)
                det = {f.vuln_class for f in fnds}
                nf = len(fnds)
        except Exception:
            det = {"<error>"}
        finally:
            if plug is not None:
                plug.cleanup()
    expected = r["cls"]
    return {"slug": r["slug"], "cve": r["cve"], "type": r["type"],
            "expected": expected, "detected": sorted(det),
            "hit": expected in det, "n_findings": nf}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out/recall.json")
    ap.add_argument("--only-present", action="store_true",
                    help="only score CVEs whose plugin zip is present on disk")
    ap.add_argument("--sample", default="", help="file of slug|cve keys to restrict to")
    ap.add_argument("--workers", type=int, default=1,
                    help="parallel archive workers (default: 1; each worker has its own AST state)")
    args = ap.parse_args()
    rows = load_rows()
    if args.only_present:
        rows = [r for r in rows if os.path.exists(r["vuln_zip"])]
    if args.sample:
        want = {s.strip() for s in open(args.sample) if s.strip()}
        rows = [r for r in rows if r["slug"] + "|" + r["cve"] in want]

    per_class = defaultdict(lambda: [0, 0])   # cls -> [tp, total]
    details = []
    total_findings = 0
    hit = 0
    if args.workers < 1:
        ap.error("--workers must be >= 1")
    iterator = (_score_row(r) for r in rows)
    if args.workers > 1:
        from multiprocessing import Pool
        pool = Pool(args.workers)
        iterator = pool.imap(_score_row, rows, chunksize=1)
    try:
        for detail in iterator:
            expected = detail["expected"]
            det = set(detail["detected"])
            nf = detail["n_findings"]
            ok = expected in det
            per_class[expected][1] += 1
            if ok:
                per_class[expected][0] += 1
                hit += 1
            total_findings += nf
            detail["hit"] = ok
            details.append(detail)
            print(f"{'HIT ' if ok else 'MISS'} {detail['slug']:34} {expected:8} det={sorted(det)}", flush=True)
    finally:
        if args.workers > 1:
            pool.close()
            pool.join()

    rep = {
        "n_plugins": len(rows),
        "plugin_class_recall": round(hit / len(rows), 4) if rows else 0,
        "hits": hit,
        "findings_per_plugin": round(total_findings / len(rows), 2) if rows else 0,
        "per_class": {c: {"recall": round(tp / tot, 3) if tot else 0, "tp": tp, "total": tot}
                      for c, (tp, tot) in sorted(per_class.items())},
        "details": details,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    json.dump(rep, open(args.out, "w"), indent=2)
    print("\n=== WISP plugin-class recall ===")
    print(json.dumps({k: rep[k] for k in ("n_plugins", "plugin_class_recall", "hits",
          "findings_per_plugin", "per_class")}, indent=2))


if __name__ == "__main__":
    main()
