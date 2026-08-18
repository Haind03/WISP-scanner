#!/usr/bin/env python3
"""Exact-defect success@K: a stricter localization endpoint than class-and-file.

class-and-file@K   a top-K finding carries the advisory class AND its file is patch-changed
class-and-hunk@K   ... AND its line is within +/-window of a patch-changed line
class-and-fn@K     ... AND its enclosing function contains a patch-changed line

The hunk/function variants are the reviewer's exact-defect proxy: they require
the finding to point at the changed code, not merely the changed file, and they
are computed from the diff alone (no human adjudication). Failure-as-miss over
all records: a timeout, empty output, or wrong class scores zero.

Scores WISP (this frozen engine) and wp-taint-scan (from its scan cache) on the
matched-100 sample so the two WordPress-aware tools can be compared on the
same-class same-defect endpoint (reviewer Incisive Q5).

  python3 -m eval.exact_defect --sample <sample_100.txt> --wpt-cache <dir> --out out/exact_defect.json
"""
from __future__ import annotations
import os, sys, json, argparse, hashlib, shutil
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wisp.engine import l1_ingest, taint_engine as te
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _changed_lines, _fn_ranges, _enclosing_fn

KS = (1, 3, 5, 10)


def _wpt_key(zip_path):
    st = os.stat(zip_path)
    raw = f"{zip_path}|{st.st_size}|{int(st.st_mtime)}".encode()
    return hashlib.sha1(raw).hexdigest()[:16]


def _strip_top(path):
    path = (path or "").replace("\\", "/")
    parts = [p for p in path.split("/") if p and p != "."]
    if not parts:
        return ""
    return "/".join(parts[1:]) if len(parts) > 1 else parts[0]


def _build_gt(vroot, proot):
    """relpath -> (changed_line_set, [(fn_start, fn_end), ...]) for patched files."""
    vmap, pmap = _php_map(vroot), _php_map(proot)
    gt = {}
    for rel, vf in vmap.items():
        if rel in pmap:
            cl = _changed_lines(vf, pmap[rel])
            if cl:
                gt[rel] = (cl, _fn_ranges(vf))
    return gt


def _keyof(p):
    parts = p.split("/") if "/" in p else p.split(os.sep)
    return os.sep.join(parts[1:]) if len(parts) > 1 else p


def _wisp_findings(zp):
    """Exploitability-ranked (file_key, line, {class}) for WISP."""
    plug = l1_ingest.load_plugin(zp)
    out = []
    if plug and plug.php_files:
        try:
            for f in te.detect(plug):
                out.append((_keyof(f.file), f.line, {f.vuln_class}))
        except Exception:
            pass
        plug.cleanup()
    return out


def _wpt_findings(zp, cache_dir):
    cpath = Path(cache_dir) / f"{_wpt_key(zp)}.json"
    if not cpath.exists():
        return None                      # no cache = treat as miss
    rec = json.loads(cpath.read_text(encoding="utf-8"))
    if not rec.get("ok"):
        return None                      # timeout / scan error = miss
    # wp-taint-scan emits findings in its own access-tier ranked order and the
    # cache preserves that order; its paths are already stripped of the top
    # plugin dir. Use them as-is to match the paper's wpt scorer exactly.
    fs = rec.get("findings") or []
    return [((f.get("path") or "").replace("\\", "/"), f.get("line") or 0,
             set(f.get("classes") or [])) for f in fs]


def _score_record(findings, advisory_cls, gt, window):
    """Return dict metric->{K->0/1} for one record's ranked findings."""
    res = {m: {k: 0 for k in KS} for m in ("cf", "ch", "cfn")}
    if not findings:
        return res
    rng_cache = {}
    for k in KS:
        for fk, line, classes in findings[:k]:
            if fk not in gt:
                continue
            cl, ranges = gt[fk]
            cls_ok = advisory_cls in classes
            if not cls_ok:
                continue
            res["cf"][k] = 1                              # class-and-file
            if any(abs(line - g) <= window for g in cl):
                res["ch"][k] = 1                          # class-and-hunk
            encl = _enclosing_fn(line, ranges)
            if encl is not None and any(encl[0] <= g <= encl[1] for g in cl):
                res["cfn"][k] = 1                         # class-and-function
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--wpt-cache", default="")
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--out", default="out/exact_defect.json")
    args = ap.parse_args()

    want = {s.strip() for s in open(args.sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]

    tools = ["wisp"] + (["wpt"] if args.wpt_cache else [])
    agg = {t: {m: {k: 0 for k in KS} for m in ("cf", "ch", "cfn")} for t in tools}
    n = 0
    for r in rows:
        zp, patched = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(zp) and os.path.isfile(patched)):
            continue
        vroot, proot = _unzip(zp), _unzip(patched)
        if not (vroot and proot):
            shutil.rmtree(vroot, ignore_errors=True)
            shutil.rmtree(proot, ignore_errors=True)
            continue
        try:
            gt = _build_gt(vroot, proot)
            n += 1
            per = {"wisp": _wisp_findings(zp)}
            if args.wpt_cache:
                per["wpt"] = _wpt_findings(zp, args.wpt_cache) or []
            for t in tools:
                sc = _score_record(per[t], r["cls"], gt, args.window)
                for m in ("cf", "ch", "cfn"):
                    for k in KS:
                        agg[t][m][k] += sc[m][k]
        finally:
            shutil.rmtree(vroot, ignore_errors=True)
            shutil.rmtree(proot, ignore_errors=True)
        print(f"scored {n}: {r['slug']}", flush=True)

    rep = {"n": n, "window": args.window,
           "metrics": {t: {m: {str(k): round(agg[t][m][k] / n, 4) for k in KS}
                           for m in ("cf", "ch", "cfn")} for t in tools},
           "raw": {t: {m: {str(k): agg[t][m][k] for k in KS}
                       for m in ("cf", "ch", "cfn")} for t in tools}}
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    json.dump(rep, open(args.out, "w"), indent=2)
    labels = {"cf": "class-and-file@K", "ch": "class-and-hunk@K", "cfn": "class-and-function@K"}
    print(f"\n=== exact-defect endpoints (n={n}, window={args.window}) ===")
    for m in ("cf", "ch", "cfn"):
        print(f"\n{labels[m]}")
        print(f"{'tool':<6}" + "".join(f"K={k:<6}" for k in KS))
        for t in tools:
            print(f"{t:<6}" + "".join(f"{rep['metrics'][t][m][str(k)]:<8}" for k in KS))


if __name__ == "__main__":
    main()
