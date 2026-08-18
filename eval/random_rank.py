#!/usr/bin/env python3
"""Random-order ranking baseline (reviewer 2.11: random / discovery / reachability).

Discovery order is the no-ranking control already in the ablation. This adds the
weaker random control: the same finding pool per plugin, shuffled, averaged over
many seeds. It answers whether the exploitability ranking beats chance, not just
emission order. Scores WISP on the matched-100 with the frozen engine, reusing the
diff ground truth, so it is consistent with the exact-defect table.

  python3 -m eval.random_rank --sample sample_100.txt --seeds 200 --out out/random_rank.json
"""
from __future__ import annotations
import os, sys, json, argparse, random, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wisp.engine import l1_ingest, taint_engine as te
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _changed_lines
from eval.exact_defect import _keyof, _build_gt
from eval.localize import _enclosing_fn

KS = (1, 3, 5, 10)


def _cf_at_k(order, advisory, gt, window):
    """(class-and-file, class-and-hunk, class-and-fn) success dict K->0/1 for one ordering."""
    res = {m: {k: 0 for k in KS} for m in ("cf", "ch", "cfn")}
    for k in KS:
        for fk, line, cls in order[:k]:
            if fk not in gt or cls != advisory:
                continue
            cl, ranges = gt[fk]
            res["cf"][k] = 1
            if any(abs(line - g) <= window for g in cl):
                res["ch"][k] = 1
            encl = _enclosing_fn(line, ranges)
            if encl is not None and any(encl[0] <= g <= encl[1] for g in cl):
                res["cfn"][k] = 1
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--seeds", type=int, default=200)
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--out", default="out/random_rank.json")
    a = ap.parse_args()
    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]

    n = 0
    native = {m: {k: 0 for k in KS} for m in ("cf", "ch", "cfn")}     # exploitability order
    pf_native = {k: 0 for k in KS}                                    # class-agnostic patch-file
    rnd = {m: {k: 0.0 for k in KS} for m in ("cf", "ch", "cfn")}      # random, averaged
    pf_rnd = {k: 0.0 for k in KS}
    rng = random.Random(42)
    for r in rows:
        zp, patched = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(zp) and os.path.isfile(patched)):
            continue
        vroot, proot = _unzip(zp), _unzip(patched)
        if not (vroot and proot):
            shutil.rmtree(vroot, ignore_errors=True); shutil.rmtree(proot, ignore_errors=True); continue
        try:
            gt = _build_gt(vroot, proot)
            plug = l1_ingest.load_plugin(zp)
            order = []
            if plug and plug.php_files:
                try:
                    order = [(_keyof(f.file), f.line, f.vuln_class) for f in te.detect(plug)]
                except Exception:
                    order = []
                plug.cleanup()
            n += 1
            # native (exploitability) order
            sc = _cf_at_k(order, r["cls"], gt, a.window)
            for m in ("cf", "ch", "cfn"):
                for k in KS:
                    native[m][k] += sc[m][k]
            for k in KS:
                pf_native[k] += int(any(fk in gt for fk, _l, _c in order[:k]))
            # random orderings averaged over seeds
            if order:
                acc = {m: {k: 0 for k in KS} for m in ("cf", "ch", "cfn")}
                pfacc = {k: 0 for k in KS}
                for _ in range(a.seeds):
                    sh = order[:]
                    rng.shuffle(sh)
                    s = _cf_at_k(sh, r["cls"], gt, a.window)
                    for m in ("cf", "ch", "cfn"):
                        for k in KS:
                            acc[m][k] += s[m][k]
                    for k in KS:
                        pfacc[k] += int(any(fk in gt for fk, _l, _c in sh[:k]))
                for m in ("cf", "ch", "cfn"):
                    for k in KS:
                        rnd[m][k] += acc[m][k] / a.seeds
                for k in KS:
                    pf_rnd[k] += pfacc[k] / a.seeds
        finally:
            shutil.rmtree(vroot, ignore_errors=True); shutil.rmtree(proot, ignore_errors=True)
        print(f"scored {n}", flush=True)

    rep = {"n": n, "seeds": a.seeds, "window": a.window,
           "exploitability": {"patch_file": {str(k): round(pf_native[k] / n, 4) for k in KS},
                              **{m: {str(k): round(native[m][k] / n, 4) for k in KS} for m in ("cf", "ch", "cfn")}},
           "random": {"patch_file": {str(k): round(pf_rnd[k] / n, 4) for k in KS},
                      **{m: {str(k): round(rnd[m][k] / n, 4) for k in KS} for m in ("cf", "ch", "cfn")}}}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=2)
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
