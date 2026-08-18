#!/usr/bin/env python3
"""Blinded two-reviewer same-defect sheet, stratified by advisory class and rank.

Findings are read from the captures both tools already produced on the matched-100
sample (WISP from capture_findings, wp-taint-scan from the matched baseline run), so
no plugin is re-scanned. An earlier version re-ran the engine and stalled for an
hour inside one pathological plugin; the captures hold the same findings from the
same engine revision, so the scan was pure waste.

The archives are still opened, but only to read the code slice around each finding
and the vendor's patch hunk, and only for the records actually sampled. Each record
is capped by SIGALRM so one large archive cannot stall the build.

Rows are drawn on a fixed quota per (advisory class x rank) cell rather than
"top-3 of everything", so the same-defect rate can be read per class and per rank.
Tool identity is hidden: rows are shuffled and the tool lives only in a key file.

    python3 -m eval.build_adjudication_v3 --target 200 --out out/adjudication.csv
"""
from __future__ import annotations
import os, sys, csv, json, random, hashlib, shutil, argparse, signal, difflib
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map

WISP_CAP = os.path.join(ROOT, "out/fill_20260714/train_cap.json")
WPT_RUN = os.path.join(ROOT, "out/corrected_20260713/matched_100_baselines_final.json")
SLICE_BEFORE, SLICE_AFTER, HUNK_LINES = 4, 4, 28
PER_RECORD_BUDGET = 90


class _Alarm(Exception):
    pass


def _slice(path, line):
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return ""
    a, b = max(0, line - 1 - SLICE_BEFORE), min(len(lines), line + SLICE_AFTER)
    return "\n".join(f"{i+1:5}: {lines[i]}" for i in range(a, b))


def _patch_hunk(vf, pf):
    try:
        v = open(vf, encoding="utf-8", errors="replace").read().split("\n")
        p = open(pf, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return ""
    out = [l for l in difflib.unified_diff(v, p, lineterm="", n=2)
           if not l.startswith(("---", "+++"))]
    return "\n".join(out[:HUNK_LINES]) if out else "(file unchanged by the patch)"


def candidates(topk):
    """Every (tool, rank, class) finding available, before any archive is opened."""
    wisp = json.load(open(WISP_CAP))
    wpt = {d["slug"] + "|" + d["cve"]: (d.get("wpt") or {})
           for d in json.load(open(WPT_RUN))["details"]}
    out = []
    for rec in wisp:
        k = rec["slug"] + "|" + rec["cve"]
        for i, f in enumerate(rec["findings"][:topk], 1):
            out.append({"tool": "wisp", "rank": i, "slug": rec["slug"], "cve": rec["cve"],
                        "advisory_class": rec["cls"], "reported_class": f.get("cls", ""),
                        "file": f.get("file", ""), "line": int(f.get("line") or 0)})
        for f in (wpt.get(k, {}).get("findings") or [])[:topk]:
            out.append({"tool": "wpt", "rank": int(f.get("rank") or 0), "slug": rec["slug"],
                        "cve": rec["cve"], "advisory_class": rec["cls"],
                        "reported_class": (f.get("classes") or [""])[0],
                        "file": (f.get("file") or "").replace("\\", "/"),
                        "line": int(f.get("line") or 0)})
    return [c for c in out if c["file"] and c["rank"]]


def stratify(items, target, seed):
    rng = random.Random(seed)
    cells = defaultdict(list)
    for it in items:
        cells[(it["advisory_class"], min(it["rank"], 3), it["tool"])].append(it)
    for v in cells.values():
        rng.shuffle(v)
    picked, quota = [], 1
    while len(picked) < target:
        added = 0
        for k in sorted(cells):
            taken = sum(1 for p in picked
                        if (p["advisory_class"], min(p["rank"], 3), p["tool"]) == k)
            if taken < quota and len(cells[k]) > taken:
                picked.append(cells[k][taken]); added += 1
                if len(picked) >= target:
                    break
        if added == 0:
            break
        quota += 1
    return picked


def enrich(picked):
    """Open each sampled record once and attach the code slice and patch hunk."""
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    by_rec = defaultdict(list)
    for it in picked:
        by_rec[it["slug"] + "|" + it["cve"]].append(it)

    def _fire(signum, frame):
        raise _Alarm()
    signal.signal(signal.SIGALRM, _fire)

    done = 0
    for k, group in by_rec.items():
        r = rows.get(k)
        if not r:
            continue
        vroot = proot = None
        signal.alarm(PER_RECORD_BUDGET)
        try:
            vroot, proot = _unzip(r["vuln_zip"]), _unzip(r["patched_zip"])
            if not (vroot and proot):
                continue
            vmap, pmap = _php_map(vroot), _php_map(proot)
            for it in group:
                vf, pf = vmap.get(it["file"]), pmap.get(it["file"])
                it["finding_slice"] = _slice(vf, it["line"]) if vf else "(file not found in archive)"
                it["vendor_patch_hunk"] = (_patch_hunk(vf, pf) if (vf and pf)
                                           else "(file not in patch)")
        except _Alarm:
            for it in group:
                it.setdefault("finding_slice", "(archive read timed out)")
                it.setdefault("vendor_patch_hunk", "(archive read timed out)")
        finally:
            signal.alarm(0)
            for d in (vroot, proot):
                if d:
                    shutil.rmtree(d, ignore_errors=True)
        done += 1
        print(f"  archives {done}/{len(by_rec)}", flush=True)
    return picked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topk", type=int, default=3)
    ap.add_argument("--target", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="out/adjudication.csv")
    a = ap.parse_args()

    cands = candidates(a.topk)
    print(f"candidates: {len(cands)} "
          f"(wisp={sum(1 for c in cands if c['tool']=='wisp')}, "
          f"wpt={sum(1 for c in cands if c['tool']=='wpt')})")
    picked = stratify(cands, a.target, a.seed)
    print(f"sampled: {len(picked)} over "
          f"{len({(p['advisory_class'], min(p['rank'],3)) for p in picked})} (class x rank) cells")
    picked = enrich(picked)
    random.Random(a.seed).shuffle(picked)

    key = {}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["finding_id", "slug", "advisory_class", "reported_class", "file",
                    "line", "finding_slice", "vendor_patch_hunk",
                    "reviewer_A", "reviewer_B", "notes"])
        for it in picked:
            fid = "E" + hashlib.sha1(
                f"{it['slug']}|{it['tool']}|{it['file']}|{it['line']}".encode()).hexdigest()[:8]
            key[fid] = {"tool": it["tool"], "rank": it["rank"], "slug": it["slug"],
                        "cve": it["cve"], "advisory_class": it["advisory_class"]}
            w.writerow([fid, it["slug"], it["advisory_class"], it["reported_class"],
                        it["file"], it["line"], it.get("finding_slice", ""),
                        it.get("vendor_patch_hunk", ""), "", "", ""])
    kp = a.out.replace(".csv", "_key.json")
    json.dump(key, open(kp, "w"), indent=1)

    dist = defaultdict(int)
    for it in picked:
        dist[(it["advisory_class"], min(it["rank"], 3))] += 1
    print(f"\nsheet: {len(picked)} findings -> {a.out}")
    print(f"key  : {kp} (reviewers must not open this)")
    print(f"tools: wisp={sum(1 for i in picked if i['tool']=='wisp')}, "
          f"wpt={sum(1 for i in picked if i['tool']=='wpt')}")
    print("\nper (class x rank):")
    for k in sorted(dist):
        print(f"  {k[0]:9} rank{k[1]}  {dist[k]}")


if __name__ == "__main__":
    main()
