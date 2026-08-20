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

Since 2026-08-19 the census file is no longer this script's to write. The reference audit that
answered the reviewer's preprint count added a per-entry array and the counts that derive from it,
before and after the pass, which arXiv id each entry was verified from, and which one gained a
published DOI. This script cannot recover any of that from the .bib, and it used to overwrite the
file with the older shape anyway, on every reproduce run, leaving a document that
build_paper_macros_v3 reads two now-absent keys out of. The same staleness reached the other
branch: with no .bib on disk it printed prev["n_preprints"], a key the current schema does not
have, and the KeyError read as a missing bibliography that was never missing.

So when the census on disk carries an entries array, this recounts the .bib and checks it against
that array rather than replacing it, and writes nothing. It still writes the full document for a
tree that has no census at all.

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


def _preprints_now(prev):
    """The count the current schema calls n_preprints_after, under whichever name it carries."""
    for k in ("n_preprints_after", "n_preprints"):
        if k in prev:
            return prev[k]
    return None


def main() -> int:
    prev = json.load(open(OUT, encoding="utf-8")) if os.path.isfile(OUT) else None
    if not os.path.isfile(BIB):
        # A tree without the .bib cannot recount, so the shipped census stands as the reference
        # rather than the target failing on a missing input it never had.
        if prev is not None:
            print("no bibliography at %s, keeping the shipped census" % BIB)
            print("  %s references, %s preprints, %s peer-reviewed"
                  % (prev.get("n_references"), _preprints_now(prev), prev.get("n_peer_reviewed")))
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
    # The audited census owns the file. Check against it and leave it alone.
    if prev is not None and prev.get("entries"):
        audited = prev["entries"]
        bad = []
        in_bib, in_census = set(entries), {e["key"] for e in audited}
        if in_bib - in_census:
            bad.append("in the bibliography and not in the census: %s"
                       % ", ".join(sorted(in_bib - in_census)))
        if in_census - in_bib:
            bad.append("in the census and not in the bibliography: %s"
                       % ", ".join(sorted(in_census - in_bib)))
        if prev.get("n_references") != len(entries):
            bad.append("census n_references is %s, the bibliography has %d"
                       % (prev.get("n_references"), len(entries)))
        still = {e["key"] for e in audited if e.get("was_preprint") and not e.get("now_published")}
        if still != set(preprints):
            only_note = sorted(set(preprints) - still)
            only_audit = sorted(still - set(preprints))
            bad.append("the preprint note in the .bib and the audited entries disagree"
                       + (", note only: %s" % ", ".join(only_note) if only_note else "")
                       + (", audit only: %s" % ", ".join(only_audit) if only_audit else ""))
        if _preprints_now(prev) != len(preprints):
            bad.append("census preprint count is %s, the bibliography's notes give %d"
                       % (_preprints_now(prev), len(preprints)))
        if bad:
            print("REFERENCE CENSUS FAIL: the bibliography and the audited census disagree.")
            for b in bad:
                print("  " + b)
            return 1
        print("reference census agrees with the bibliography, nothing rewritten")
        print("  %d references, %d preprints, %d peer-reviewed"
              % (len(entries), len(preprints), prev.get("n_peer_reviewed")))
        return 0

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
