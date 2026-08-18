#!/usr/bin/env python3
"""Build the matched-100 manifest that eval.testset.scan_testset consumes.

The matched-100 four-tool run used a manifest under /tmp that no longer exists, and the
shipped result file it produced carries `cls: "other"` on all 100 records - the 2026-07-17
broken-class bug, where a manifest without `vuln_type` made every class-dependent metric
ask "did the tool report other?". scan_testset now refuses such a manifest outright, so
the manifest has to be rebuilt from the corpus itself.

One wrinkle the guard cannot distinguish: 206 of the 1108 corpus rows have an EMPTY type
in the Patchstack source, and the dataset legitimately classifies those as `other`. They
are not a dropped field, they are an absent label. They are written here as the explicit
token `unspecified`, which classify_type maps to `other` - the same class the corpus
assigns - so no label is invented and the round-trip is exact.

The script refuses to write unless classify_type(manifest) reproduces load_rows()'s class
for all 100 records.

    python3 -m eval.build_matched100_manifest
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.datasets.patchstack import load_rows
from eval.testset.scan_testset import classify_type

SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100_manifest.json")
NO_LABEL = "unspecified"          # classify_type() -> "other", matching the corpus


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", default=SAMPLE)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = [l.strip() for l in open(a.sample) if l.strip()]
    missing = [k for k in keys if k not in rows]
    if missing:
        sys.exit(f"{len(missing)} sample keys not in the corpus: {missing[:5]}")

    man, unlabelled = [], 0
    for k in keys:
        r = rows[k]
        t = r.get("type") or ""
        if not t.strip():
            t = NO_LABEL
            unlabelled += 1
        man.append({"slug": r["slug"], "cve": r["cve"], "vuln_type": t,
                    "vuln_zip": r["vuln_zip"], "patched_zip": r["patched_zip"]})

    got = Counter(classify_type(m["vuln_type"]) for m in man)
    want = Counter(rows[k]["cls"] for k in keys)
    if got != want:
        sys.exit(f"class round-trip FAILED\n  manifest: {dict(got)}\n  corpus  : {dict(want)}")

    missing_zip = [m["slug"] for m in man
                   if not (os.path.isfile(m["vuln_zip"]) and os.path.isfile(m["patched_zip"]))]
    if missing_zip:
        print(f"WARNING: {len(missing_zip)} records have a missing archive: {missing_zip[:5]}")

    json.dump(man, open(a.out, "w"), indent=1)
    print(f"wrote {a.out}: {len(man)} records, {unlabelled} with no source label "
          f"(written as '{NO_LABEL}' -> other)")
    print("class round-trip exact:", dict(sorted(got.items())))


if __name__ == "__main__":
    main()
