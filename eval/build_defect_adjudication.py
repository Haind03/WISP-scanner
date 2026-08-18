#!/usr/bin/env python3
"""Build a blinded two-reviewer sheet for the same-defect endpoint (reviewer P0.2).

Unlike the vulnerability-reality audit (eval/testset, TP/LP/FP/UN), this sheet asks
whether each top-K finding corresponds to the SAME defect the advisory describes.
For every matched-100 record it samples the top-K ranked findings of each
WordPress-aware tool (WISP, wp-taint-scan), hides the tool identity behind an
opaque id, and shows the reviewer both the finding's code slice AND the vendor
patch hunk (what actually changed) so a same-defect judgment is possible.

Two reviewers independently fill reviewer_A / reviewer_B with one of:
  SD  same defect        (finding points at the code the vendor patch changed for THIS advisory)
  SC  same class, related (correct class in the patched file but a different spot / not the fixed line)
  UR  unrelated          (wrong class or clearly not the advisory's defect)
  UN  uncertain

Build:  python3 -m eval.build_defect_adjudication --sample sample_100.txt \
            --wpt-cache <dir> --topk 3 --out out/defect_adjudication.csv
Score:  python3 -m eval.build_defect_adjudication --kappa filled_A.csv filled_B.csv
"""
from __future__ import annotations
import os, sys, csv, json, argparse, hashlib, shutil, random
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wisp.engine import l1_ingest, taint_engine as te
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _changed_lines
from eval.exact_defect import _wpt_key, _keyof

LABELS = ("SD", "SC", "UR", "UN")


def _slice(abs_file, line, ctx=4):
    try:
        lines = open(abs_file, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return ""
    lo, hi = max(0, line - 1 - ctx), min(len(lines), line + ctx)
    return "\n".join(f"{i+1:5}: {lines[i]}" for i in range(lo, hi))


def _hunk_preview(vf, pf, maxlines=6):
    """A short preview of the vuln-side lines the patch changed, for context."""
    cl = sorted(_changed_lines(vf, pf))
    if not cl:
        return ""
    try:
        lines = open(vf, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return ""
    out = [f"{n:5}: {lines[n-1]}" for n in cl[:maxlines] if 1 <= n <= len(lines)]
    return "\n".join(out)


def build(sample, wpt_cache, topk, seed, out):
    want = {s.strip() for s in open(sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]
    items, key = [], {}
    for r in rows:
        zp, patched = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(zp) and os.path.isfile(patched)):
            continue
        vroot, proot = _unzip(zp), _unzip(patched)
        if not (vroot and proot):
            shutil.rmtree(vroot, ignore_errors=True); shutil.rmtree(proot, ignore_errors=True); continue
        try:
            vmap, pmap = _php_map(vroot), _php_map(proot)
            # WISP findings (this engine, ranked)
            per = {"wisp": [], "wpt": []}
            plug = l1_ingest.load_plugin(zp)
            if plug and plug.php_files:
                try:
                    for f in te.detect(plug)[:topk]:
                        per["wisp"].append((_keyof(f.file), f.line, f.vuln_class))
                except Exception:
                    pass
                plug.cleanup()
            cpath = Path(wpt_cache) / f"{_wpt_key(zp)}.json"
            if cpath.exists():
                rec = json.loads(cpath.read_text(encoding="utf-8"))
                if rec.get("ok"):
                    for f in (rec.get("findings") or [])[:topk]:
                        cls = (f.get("classes") or [None])[0]
                        per["wpt"].append(((f.get("path") or "").replace("\\", "/"),
                                           f.get("line") or 0, cls))
            for tool in ("wisp", "wpt"):
                for fk, line, cls in per[tool]:
                    vf = vmap.get(fk)
                    pf = pmap.get(fk)
                    fid = "D" + hashlib.sha1(f"{r['slug']}|{tool}|{fk}|{line}".encode()).hexdigest()[:8]
                    items.append({
                        "finding_id": fid, "slug": r["slug"], "advisory_class": r["cls"],
                        "reported_class": cls or "", "file": fk, "line": line,
                        "finding_slice": _slice(vf, line) if vf else "",
                        "vendor_patch_hunk": _hunk_preview(vf, pf) if (vf and pf) else "",
                        "reviewer_A": "", "reviewer_B": "", "notes": "",
                    })
                    key[fid] = {"tool": tool, "slug": r["slug"], "cve": r["cve"],
                                "advisory_class": r["cls"], "reported_class": cls}
        finally:
            shutil.rmtree(vroot, ignore_errors=True); shutil.rmtree(proot, ignore_errors=True)
    rng = random.Random(seed)
    rng.shuffle(items)                       # tool/class order not guessable
    cols = ["finding_id", "slug", "advisory_class", "reported_class", "file", "line",
            "finding_slice", "vendor_patch_hunk", "reviewer_A", "reviewer_B", "notes"]
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols); w.writeheader()
        for it in items:
            w.writerow(it)
    json.dump(key, open(out.replace(".csv", "_key.json"), "w"), indent=1)
    print(f"wrote {len(items)} rows -> {out}")
    print(f"tool key (hidden from reviewers) -> {out.replace('.csv', '_key.json')}")
    print("Reviewers fill reviewer_A (Duy) and reviewer_B (Hieu) with one of: SD / SC / UR / UN")


def kappa(fa, fb, key_path=""):
    def load(p, col):
        return {r["finding_id"]: (r.get(col) or "").strip().upper()
                for r in csv.DictReader(open(p, encoding="utf-8"))}
    A = load(fa, "reviewer_A"); B = load(fb, "reviewer_B")
    ids = [i for i in A if i in B and A[i] in LABELS and B[i] in LABELS]
    n = len(ids)
    agree = sum(1 for i in ids if A[i] == B[i])
    po = agree / n if n else 0
    from collections import Counter
    ca, cb = Counter(A[i] for i in ids), Counter(B[i] for i in ids)
    pe = sum((ca[l] / n) * (cb[l] / n) for l in LABELS) if n else 0
    kap = (po - pe) / (1 - pe) if (1 - pe) else 0
    # same-defect success rate: both label SD
    both_sd = sum(1 for i in ids if A[i] == "SD" and B[i] == "SD")
    res = {"n": n, "agreement": round(po, 4), "kappa": round(kap, 4),
           "both_same_defect": both_sd, "both_sd_rate": round(both_sd / n, 4) if n else 0,
           "A_counts": dict(ca), "B_counts": dict(cb)}
    if key_path and os.path.exists(key_path):
        k = json.load(open(key_path))
        per_tool = {}
        for i in ids:
            t = k.get(i, {}).get("tool", "?")
            d = per_tool.setdefault(t, {"n": 0, "both_sd": 0})
            d["n"] += 1; d["both_sd"] += int(A[i] == "SD" and B[i] == "SD")
        res["per_tool_both_sd"] = per_tool
    print(json.dumps(res, indent=2))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample"); ap.add_argument("--wpt-cache", default="")
    ap.add_argument("--topk", type=int, default=3); ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="out/defect_adjudication.csv")
    ap.add_argument("--kappa", nargs=2, metavar=("A.csv", "B.csv"))
    ap.add_argument("--key", default="")
    a = ap.parse_args()
    if a.kappa:
        kappa(a.kappa[0], a.kappa[1], a.key)
    else:
        build(a.sample, a.wpt_cache, a.topk, a.seed, a.out)


if __name__ == "__main__":
    main()
