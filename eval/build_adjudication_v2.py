#!/usr/bin/env python3
"""Blinded two-reviewer same-defect sheet, stratified by advisory class and rank.

The earlier round sampled the top-3 findings of every matched-100 record and took
whatever fell out: 119 findings, unstratified, so the rarer classes carried a
handful of rows and rank-3 was thin. This builder draws a fixed quota per
(advisory class x rank) cell instead, so the resulting same-defect rate can be
read per class and per rank rather than only in aggregate.

WISP findings are produced by the current engine. wp-taint-scan findings are read
from the matched-100 baseline run, which already stores rank/file/line/classes,
so the two tools stay comparable without re-scanning.

Tool identity is hidden: rows are shuffled under a fixed seed and the tool is
recorded only in a separate key file the reviewers never see.

    python3 -m eval.build_adjudication_v2 --target 200 --out out/adjudication_v2.csv
"""
from __future__ import annotations
import os, sys, csv, json, random, hashlib, shutil, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _changed_lines
from wisp.engine import l1_ingest, taint_engine as te

SLICE_BEFORE, SLICE_AFTER = 4, 4


def _keyof(p):
    parts = p.replace("\\", "/").split("/")
    return "/".join(parts[1:]) if len(parts) > 1 else p


def _slice(path, line, before=SLICE_BEFORE, after=SLICE_AFTER):
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return ""
    a, b = max(0, line - 1 - before), min(len(lines), line + after)
    return "\n".join(f"{i+1:5}: {lines[i]}" for i in range(a, b))


def _patch_hunk(vf, pf, limit=28):
    """The vendor's actual change for this file, as a unified diff."""
    import difflib
    try:
        v = open(vf, encoding="utf-8", errors="replace").read().split("\n")
        p = open(pf, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        return ""
    out = [l for l in difflib.unified_diff(v, p, lineterm="", n=2)
           if not l.startswith(("---", "+++"))]
    return "\n".join(out[:limit])


def collect(sample, topk):
    """All candidate findings from both tools, with their code slice and patch hunk."""
    want = {s.strip() for s in open(sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]
    base = json.load(open(os.path.join(
        ROOT, "out/corrected_20260713/matched_100_baselines_final.json")))
    wpt = {d["slug"] + "|" + d["cve"]: (d.get("wpt") or {}) for d in base["details"]}

    items = []
    for r in rows:
        vzip, pzip = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(vzip) and os.path.isfile(pzip)):
            continue
        vroot, proot = _unzip(vzip), _unzip(pzip)
        if not (vroot and proot):
            for d in (vroot, proot):
                if d:
                    shutil.rmtree(d, ignore_errors=True)
            continue
        try:
            vmap, pmap = _php_map(vroot), _php_map(proot)
            per = {"wisp": [], "wpt": []}
            plug = l1_ingest.load_plugin(vzip)
            if plug and plug.php_files:
                try:
                    for i, f in enumerate(te.detect(plug)[:topk], 1):
                        per["wisp"].append((i, _keyof(f.file), int(getattr(f, "line", 0) or 0),
                                           f.vuln_class))
                except Exception:
                    pass
                plug.cleanup()
            for f in (wpt.get(r["slug"] + "|" + r["cve"], {}).get("findings") or [])[:topk]:
                per["wpt"].append((f.get("rank", 0), (f.get("file") or "").replace("\\", "/"),
                                   f.get("line") or 0, (f.get("classes") or [""])[0]))
            for tool, fs in per.items():
                for rank, fk, line, cls in fs:
                    vf, pf = vmap.get(fk), pmap.get(fk)
                    if not vf:
                        continue
                    items.append({
                        "tool": tool, "rank": rank, "slug": r["slug"], "cve": r["cve"],
                        "advisory_class": r["cls"], "reported_class": cls or "",
                        "file": fk, "line": line,
                        "finding_slice": _slice(vf, line),
                        "vendor_patch_hunk": _patch_hunk(vf, pf) if pf else "(file not in patch)",
                    })
        finally:
            for d in (vroot, proot):
                shutil.rmtree(d, ignore_errors=True)
    return items


def stratify(items, target, seed):
    """Fixed quota per (advisory class x rank), balanced across the two tools."""
    rng = random.Random(seed)
    cells = defaultdict(list)
    for it in items:
        cells[(it["advisory_class"], min(it["rank"], 3), it["tool"])].append(it)
    for v in cells.values():
        rng.shuffle(v)
    picked, quota = [], 1
    # grow the per-cell quota until the target is met or every cell is drained
    while len(picked) < target:
        added = 0
        for k in sorted(cells):
            pool = cells[k]
            have = sum(1 for p in picked if (p["advisory_class"], min(p["rank"], 3), p["tool"]) == k)
            if have < quota and len(pool) > have:
                picked.append(pool[have]); added += 1
                if len(picked) >= target:
                    break
        if added == 0:
            break
        quota += 1
    return picked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=os.path.join(
        os.environ.get("WISP_SYS_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "baselines", "sample_100.txt"))
    ap.add_argument("--topk", type=int, default=3)
    ap.add_argument("--target", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="out/adjudication_v2.csv")
    a = ap.parse_args()

    items = collect(a.sample, a.topk)
    print(f"candidates: {len(items)}")
    picked = stratify(items, a.target, a.seed)
    random.Random(a.seed).shuffle(picked)          # hide tool identity in row order

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
                        it["file"], it["line"], it["finding_slice"],
                        it["vendor_patch_hunk"], "", "", ""])
    kp = a.out.replace(".csv", "_key.json")
    json.dump(key, open(kp, "w"), indent=1)

    dist = defaultdict(int)
    for it in picked:
        dist[(it["advisory_class"], min(it["rank"], 3))] += 1
    print(f"\nsheet: {len(picked)} findings -> {a.out}\nkey  : {kp} (reviewers must not see this)")
    print(f"tools: wisp={sum(1 for i in picked if i['tool']=='wisp')}, "
          f"wpt={sum(1 for i in picked if i['tool']=='wpt')}")
    print("\nper (class x rank):")
    for k in sorted(dist):
        print(f"  {k[0]:9} rank{k[1]}  {dist[k]}")


if __name__ == "__main__":
    main()
