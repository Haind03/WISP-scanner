#!/usr/bin/env python3
"""Build a blinded review sheet from normalized test-set findings.

This utility produces a protocol and blank labels; running it is not evidence
that a review was completed.  Completed labels must be released separately and
must match the generated key.  It writes:
  * adjudication_sheet.csv  : one row per sampled finding, with a code slice,
                              tool identity HIDDEN behind an opaque id; two blank
                              label columns (reviewer_A, reviewer_B).
  * adjudication_key.json   : the hidden mapping finding_id -> (tool, slug, class)
                              kept OUT of the reviewers' sheet.

Rubric for each finding (reviewers fill reviewer_A / reviewer_B with one of):
  TP  = confirmed true positive (a real, reachable vulnerability)
  LP  = likely true positive (plausible flow, reachability not established)
  FP  = clear false positive
  UN  = uncertain

After both reviewers return the sheet, run:
  python3 build_adjudication_sheet.py --kappa filled_A.csv filled_B.csv

Usage (build): python3 build_adjudication_sheet.py --per-class 10
"""
import os, json, csv, argparse, random, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("WISP_TESTSET_DIR", os.path.join(HERE, "data"))


def _fid(tool, slug, i):
    return "F" + hashlib.sha1(f"{tool}|{slug}|{i}".encode()).hexdigest()[:8]


def _slice(manifest_rec, relfile, line, ctx=8):
    """Extract +/- ctx lines around `line` from the vulnerable zip, so reviewers
    read the code without the tool identity. Returns a compact one-cell string."""
    import zipfile
    if not manifest_rec or not line:
        return ""
    try:
        zf = zipfile.ZipFile(manifest_rec["vuln_zip"])
    except Exception:
        return ""
    # zip entries are <topdir>/<relfile>; match by suffix
    target = None
    for nm in zf.namelist():
        if nm.endswith("/" + relfile) or nm.endswith(relfile):
            target = nm
            break
    if not target:
        return ""
    try:
        text = zf.read(target).decode("utf-8", "ignore").splitlines()
    except Exception:
        return ""
    lo, hi = max(0, line - ctx - 1), min(len(text), line + ctx)
    out = []
    for i in range(lo, hi):
        mark = ">>" if i + 1 == line else "  "
        out.append(f"{mark}{i+1}: {text[i]}")
    return "\n".join(out)


def build(per_class, seed, scored_path, manifest_path, sheet_path, key_path):
    """Sample findings across tools and classes, blinded. Requires the scan to
    have stored per-finding file/line/class (extended scan output)."""
    with open(scored_path, encoding="utf-8") as handle:
        data = json.load(handle)
    det = data["details"]
    # collect candidate findings: (tool, slug, cls, file, line) if present
    pool = []
    for rec in det:
        slug = rec["slug"]
        for tool in ("wisp", "semgrep", "progpilot", "wpt"):
            tv = rec.get(tool, {})
            for i, f in enumerate(tv.get("findings", tv.get("findings_sample", []))):
                classes = f.get("classes") or ([f.get("cls")] if f.get("cls") else [])
                pool.append({"tool": tool, "slug": slug, "cls": "/".join(classes),
                             "file": f.get("file"), "line": f.get("line"),
                             "advisory_cls": rec["cls"], "cve": rec.get("cve")})
    rng = random.Random(seed)
    rng.shuffle(pool)
    by_cls = {}
    for p in pool:
        by_cls.setdefault(p["cls"], []).append(p)
    sample = []
    for cls, items in by_cls.items():
        sample.extend(items[:per_class])
    rng.shuffle(sample)   # so tool/class order is not guessable
    # map slug -> vulnerable zip (kept under plugins/)
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = {m["slug"]: m for m in json.load(handle)}
    rows, key = [], {}
    for j, p in enumerate(sample):
        fid = _fid(p["tool"], p["slug"], j)
        key[fid] = p
        rows.append({"finding_id": fid, "slug": p["slug"], "reported_class": p["cls"],
                     "file": p["file"], "line": p["line"],
                     "code_slice": _slice(manifest.get(p["slug"]), p["file"], p["line"]),
                     "reviewer_A": "", "reviewer_B": "", "notes": ""})
    os.makedirs(os.path.dirname(sheet_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    with open(sheet_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["finding_id", "slug", "reported_class", "file",
                                           "line", "code_slice", "reviewer_A", "reviewer_B",
                                           "notes"])
        w.writeheader()
        w.writerows(rows)
    with open(key_path, "w", encoding="utf-8") as handle:
        json.dump(key, handle, indent=1)
    print(f"wrote {len(rows)} blinded findings to {sheet_path}")
    print(f"hidden key (tool identities) in {key_path} -- keep OUT of reviewers' copy")


def kappa(fa, fb):
    """Cohen's kappa between two filled sheets (columns finding_id, label)."""
    def load(path, col):
        out = {}
        for r in csv.DictReader(open(path)):
            lab = (r.get(col) or r.get("label") or "").strip().upper()
            if lab:
                out[r["finding_id"]] = lab
        return out
    A = load(fa, "reviewer_A")
    B = load(fb, "reviewer_B")
    ids = sorted(set(A) & set(B))
    if not ids:
        print("no common labeled findings"); return
    labels = sorted({A[i] for i in ids} | {B[i] for i in ids})
    n = len(ids)
    agree = sum(1 for i in ids if A[i] == B[i])
    po = agree / n
    pe = sum((sum(A[i] == l for i in ids) / n) * (sum(B[i] == l for i in ids) / n)
             for l in labels)
    k = (po - pe) / (1 - pe) if pe != 1 else 1.0
    print(f"n={n} common findings, observed agreement={po:.3f}, "
          f"expected={pe:.3f}, Cohen's kappa={k:.3f}")
    # collapse TP+LP -> positive for a coarser agreement too
    def pos(x):
        return "POS" if x in ("TP", "LP") else ("NEG" if x == "FP" else "UN")
    agree2 = sum(1 for i in ids if pos(A[i]) == pos(B[i]))
    print(f"collapsed (TP/LP=POS, FP=NEG, UN): agreement={agree2/n:.3f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--kappa", nargs=2, metavar=("A.csv", "B.csv"))
    ap.add_argument("--scored", default=os.path.join(HERE, "out", "testset_scored.json"))
    ap.add_argument("--manifest", default=os.path.join(DATA_DIR, "testset_manifest.json"))
    ap.add_argument("--sheet", default=os.path.join(HERE, "out", "adjudication_sheet.csv"))
    ap.add_argument("--key", default=os.path.join(HERE, "out", "adjudication_key.json"))
    a = ap.parse_args()
    if a.kappa:
        kappa(*a.kappa)
    else:
        build(a.per_class, a.seed, a.scored, a.manifest, a.sheet, a.key)


if __name__ == "__main__":
    main()
