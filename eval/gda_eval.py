#!/usr/bin/env python3
"""Fast class-and-file@K harness for tuning the GDA ranking, with an offline cache.

Running the taint engine over the corpus is the expensive step. This harness runs
`te.detect` ONCE per plugin, records each finding's ranking FEATURES (class, entry
point, interprocedural flag, confidence, guard deficit) plus the diff-based ground
truth, and caches that to JSON. A `--score` pass then recomputes class-and-file@K
under any ranking weighting from the cached features in milliseconds, so the GDA
weights can be tuned without re-running the engine.

  python3 -m eval.gda_eval --dump out/gda_dump.json --limit 200     # slow, once
  python3 -m eval.gda_eval --score out/gda_dump.json --wguard 2.0    # instant

The class-and-file@K definition matches eval/localize.py exactly: for each plugin,
is there a top-K finding whose file is a patched file AND whose class equals the
advisory class.
"""
from __future__ import annotations
import os, sys, json, zipfile, tempfile, shutil, difflib, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wisp.engine import l1_ingest, taint_engine as te
from eval.datasets.patchstack import load_rows

KS = (1, 3, 5, 10)


def _unzip(path):
    d = tempfile.mkdtemp()
    try:
        zipfile.ZipFile(path).extractall(d)
    except Exception:
        return None
    return d


def _php_map(root):
    out = {}
    for r, _, files in os.walk(root):
        for fn in files:
            if fn.endswith(".php"):
                ap = os.path.join(r, fn)
                rel = os.path.relpath(ap, root)
                parts = rel.split(os.sep)
                key = os.sep.join(parts[1:]) if len(parts) > 1 else rel
                out[key] = ap
    return out


def _changed_lines(vuln_file, patched_file):
    try:
        a = open(vuln_file, encoding="utf-8", errors="ignore").read().splitlines()
        b = open(patched_file, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return set()
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    lines = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            lines.update(range(i1 + 1, i2 + 1))
        elif tag == "insert":
            lines.add(i1 + 1)
    return lines


def _keyof(p):
    parts = p.split("/") if "/" in p else p.split(os.sep)
    return os.sep.join(parts[1:]) if len(parts) > 1 else p


def _old_slugs():
    """(slug, cve) keys in the original 252-plugin xlsx = the TRAIN split (the set
    the REST/auth lever was tuned on). Everything else is the disjoint TEST split."""
    import openpyxl
    old = os.path.join(os.path.dirname(ROOT), "patchstack_bugbounty",
                       "patchstack_vulnerable_plugins.xlsx")
    keys = set()
    try:
        wb = openpyxl.load_workbook(old, read_only=True)
        ws = wb.active
        it = ws.iter_rows(values_only=True)
        hdr = list(next(it))
        si, ci = hdr.index("Slug"), hdr.index("CVE")
        for r in it:
            if r[si] and r[ci]:
                keys.add((str(r[si]).strip(), str(r[ci]).strip()))
    except Exception:
        pass
    return keys


def _dump_one(r):
    """Process one Patchstack row -> dump entry (or None). Top-level so it is
    picklable by multiprocessing workers."""
    zp, patched = r["vuln_zip"], r["patched_zip"]
    if not (os.path.isfile(zp) and os.path.isfile(patched)):
        return None
    vroot, proot = _unzip(zp), _unzip(patched)
    if not vroot or not proot:
        return None
    try:
        vmap, pmap = _php_map(vroot), _php_map(proot)
        gt = {}
        for rel, vf in vmap.items():
            if rel in pmap:
                cl = _changed_lines(vf, pmap[rel])
                if cl:
                    gt[rel] = sorted(cl)
        if not gt:
            return None
        plug = l1_ingest.load_plugin(zp)
        findings = []
        if plug and plug.php_files:
            try:
                findings = te.detect(plug)
            except Exception:
                findings = []
            plug.cleanup()
        feats = [{
            "file": _keyof(f.file), "line": f.line, "cls": f.vuln_class,
            "ep": getattr(f, "entry_point", "unknown"),
            "inter": bool(getattr(f, "interprocedural", False)),
            "conf": float(getattr(f, "confidence", 0.6)),
            "deficit": float(getattr(f, "guard_deficit", -1.0)),
            "sink": getattr(f, "sink", ""), "src": getattr(f, "source", ""),
        } for f in findings]
        return {"slug": r["slug"], "cve": r["cve"], "cls": r["cls"],
                "gt_files": list(gt), "findings": feats}
    finally:
        shutil.rmtree(vroot, ignore_errors=True)
        shutil.rmtree(proot, ignore_errors=True)


def build_dump(limit, out_path, split="all", jobs=1, sample=""):
    import multiprocessing as mp
    rows = load_rows()
    if sample:
        want = {s.strip() for s in open(sample) if s.strip()}
        rows = [r for r in rows if f"{r['slug']}|{r['cve']}" in want]
    if split in ("train", "test"):
        old = _old_slugs()
        rows = [r for r in rows
                if ((str(r["slug"]).strip(), str(r["cve"]).strip()) in old)
                == (split == "train")]
    if limit:
        rows = rows[:limit]
    dump = []
    if jobs <= 1:
        for i, r in enumerate(rows):
            e = _dump_one(r)
            if e:
                dump.append(e)
                print(f"[{len(dump)}] {r['slug']:30} {r['cls']:8} find={len(e['findings'])}",
                      flush=True)
    else:
        done = 0
        with mp.Pool(jobs) as pool:
            for e in pool.imap_unordered(_dump_one, rows, chunksize=1):
                done += 1
                if e:
                    dump.append(e)
                if done % 20 == 0:
                    print(f"  ...{done}/{len(rows)} processed, {len(dump)} kept", flush=True)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    json.dump(dump, open(out_path, "w"))
    print(f"\nwrote {len(dump)} plugins -> {out_path}")


_ENTRY_WEIGHT = {"ajax_nopriv": 5.0, "rest_api": 4.0, "shortcode": 3.0,
                 "ajax_auth": 2.5, "admin": 1.0, "unknown": 0.5}


def _score(feat, wflow, wguard):
    deficit = feat["deficit"]
    guard_term = wguard * deficit if deficit >= 0.0 else 0.0
    return (_ENTRY_WEIGHT.get(feat["ep"], 0.5)
            + (1.0 if feat["inter"] else 0.0)
            + wflow * feat["conf"]
            + guard_term)


def score_dump(dump_path, wflow, wguard, per_class=False):
    dump = json.load(open(dump_path))
    agg = {k: 0 for k in KS}
    pf = {k: 0 for k in KS}          # patch-file@K (any class)
    per = {}                          # cls -> {k: hits, "n": count, "ceil": cov@10-any-order}
    n = 0
    for d in dump:
        gt = set(d["gt_files"])
        cls = d["cls"]
        feats = sorted(d["findings"], key=lambda f: _score(f, wflow, wguard),
                       reverse=True)
        pc = per.setdefault(cls, {**{k: 0 for k in KS}, "n": 0, "ceil": 0})
        pc["n"] += 1
        # coverage ceiling: is the right class+file emitted at all (any rank)?
        if any(f["file"] in gt and f["cls"] == cls for f in feats):
            pc["ceil"] += 1
        for k in KS:
            topk = feats[:k]
            hit = any(f["file"] in gt and f["cls"] == cls for f in topk)
            if hit:
                agg[k] += 1
                pc[k] += 1
            if any(f["file"] in gt for f in topk):
                pf[k] += 1
        n += 1
    res = {"n": n,
           "cf_at_k": {k: round(agg[k] / n, 4) for k in KS} if n else {},
           "pf_at_k": {k: round(pf[k] / n, 4) for k in KS} if n else {}}
    if per_class:
        res["per_class"] = {c: {"n": v["n"],
                                "cf@1": round(v[1] / v["n"], 3),
                                "cf@10": round(v[10] / v["n"], 3),
                                "ceil@any": round(v["ceil"] / v["n"], 3)}
                            for c, v in sorted(per.items())}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", help="build a feature dump to this path")
    ap.add_argument("--score", help="score an existing dump")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--wflow", type=float, default=1.0)
    ap.add_argument("--wguard", type=float, default=1.0)
    ap.add_argument("--per-class", action="store_true")
    ap.add_argument("--split", choices=["all", "train", "test"], default="all")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--sample", default="", help="file of slug|cve keys to restrict to")
    args = ap.parse_args()
    if args.dump:
        build_dump(args.limit, args.dump, args.split, args.jobs, args.sample)
    if args.score:
        res = score_dump(args.score, args.wflow, args.wguard, args.per_class)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
