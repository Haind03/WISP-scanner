#!/usr/bin/env python3
"""Census of the bibliography: how many references are peer-reviewed and how many are preprints.

The related-work paragraph tells the reader that much of the 2026 literature it cites is not yet
peer-reviewed. That sentence used to say "most", which is a claim about the bibliography that
nothing checked and that quietly went stale every time an entry was added or a preprint was
replaced by its published version. This counts the entries instead, so the sentence is a number
with a source like every other number in the paper.

An entry counts as a preprint when its note field says so, which is the same signal the rendered
bibliography shows the reader. Entry types are recorded too, so a reviewer can see the split
without opening the .bib.

    python3 -m eval.reference_census_v3
"""
from __future__ import annotations
import os, re, sys, json, time, platform, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
BIB = os.path.join(SYS_ROOT, "2026-07-07", "latex", "references.bib")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "REFERENCE_CENSUS_V3.json")

ENTRY = re.compile(r"@(\w+)\s*\{\s*([^,\s]+)\s*,(.*?)\n\}", re.S)
PREPRINT = re.compile(r"\bpreprint\b|\barxiv\b", re.I)


def main() -> int:
    if not os.path.isfile(BIB):
        # A tree without the .bib cannot recount, so the shipped census stands as the reference
        # rather than the target failing on a missing input it never had.
        if os.path.isfile(OUT):
            prev = json.load(open(OUT, encoding="utf-8"))
            print("no bibliography at %s, keeping the shipped census" % BIB)
            print("  %d references, %d preprints, %d peer-reviewed"
                  % (prev["n_references"], prev["n_preprints"], prev["n_peer_reviewed"]))
            return 0
        sys.exit("no bibliography at " + BIB)
    src = open(BIB, encoding="utf-8").read()
    entries, preprints, by_type = [], [], collections.Counter()
    for etype, key, body in ENTRY.findall(src):
        note = ""
        # the note is often the entry's last field, so the closing brace is not always followed by
        # a newline. Anchoring on one is how this silently counted zero preprints the first time.
        m = re.search(r"\bnote\s*=\s*\{(.*?)\}\s*,?\s*(?:\n|$)", body, re.S)
        if m:
            note = m.group(1)
        is_pre = bool(PREPRINT.search(note))
        entries.append(key)
        by_type[etype.lower()] += 1
        if is_pre:
            preprints.append(key)
    res = {
        "schema_version": "reference-census-v3",
        "script": "eval/reference_census_v3.py",
        "bibliography": "2026-07-07/latex/references.bib",
        "rule": ("an entry counts as a preprint when its note field says preprint or names arXiv, "
                 "which is the same signal the rendered bibliography shows"),
        "n_references": len(entries),
        "n_preprints": len(preprints),
        "n_peer_reviewed": len(entries) - len(preprints),
        "preprint_keys": sorted(preprints),
        "entry_types": dict(sorted(by_type.items())),
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": platform.python_version(),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(res, open(OUT, "w"), indent=1, sort_keys=True)
    print("wrote " + OUT)
    print("  %d references, %d preprints, %d peer-reviewed"
          % (res["n_references"], res["n_preprints"], res["n_peer_reviewed"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
