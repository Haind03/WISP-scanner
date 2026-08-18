#!/usr/bin/env python3
"""Generate CLAIM-MAP.csv from the macro manifest instead of maintaining it by hand.

The shipped CLAIM-MAP was a hand-written file that promised a reviewer that every headline number
traces to a JSON. Nothing checked it, so it drifted: of its 19 rows, four carried values the macros
had moved past and nine named macros that no longer exist. A provenance document with no provenance
of its own is worse than none, because it is read first and trusted.

Every row here is emitted from PAPER_MACROS_V3.manifest.json, so a row cannot name a macro that
does not exist and cannot carry a value the macro does not have. The claim wording is the only
authored part, and a claim whose macro disappears fails this script rather than shipping stale.

    python3 -m eval.build_claim_map
"""
from __future__ import annotations
import os, sys, csv, json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
MANIFEST = os.path.join(LATEX, "PAPER_MACROS_V3.manifest.json")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "bundle-src", "CLAIM-MAP.csv")

# (claim wording, macro name). Order is the order a reader meets them in the paper.
CLAIMS = [
    ("Corpus size", "NAdvisories"),
    ("Plugin count", "NPlugins"),
    ("Matched records", "NRecordsMatched"),
    ("Finding population", "NFindingsPooled"),
    ("WISP patched-file rate", "WispInPatchedFileRate"),
    ("WISP exact-changed-line rate", "WispExactChangedLineRate"),
    ("wp-taint-scan patched-file rate", "WptInPatchedFileRate"),
    ("wp-taint-scan exact-changed-line rate", "WptExactChangedLineRate"),
    ("Full-corpus WISP class emission (contract)", "FcCorpusWispEmission"),
    ("Full-corpus WISP class emission (non-convergence ignored)", "FcCorpusWispEmissionKept"),
    ("Full-corpus non-convergence count", "CorpusNonConv"),
    ("Matched WISP patch-file success@1", "LocWispPfOne"),
    ("Matched WISP class-and-file success@1", "LocWispCfOne"),
    ("Matched wp-taint-scan class-and-file success@1", "LocWptCfOne"),
    ("Semgrep-WP patch-file success@1", "SwpPfOne"),
    ("Paired family size", "FamilySize"),
    ("Paired family endpoints", "FamilyEndpoints"),
    ("Comparisons surviving Holm", "FamilySurvive"),
    ("Class endpoint, WISP vs wp-taint-scan, exact p", "CmpClassWptP"),
    ("Equal-budget WISP patch-file@1 at 25 s", "WispPfOneAtTwentyFive"),
    ("Equal-budget WISP patch-file@1 at 60 s", "WispPfOneAtSixty"),
    ("Sanitizer ablation class-emission delta", "SaniClassEmissionDelta"),
    ("Corpus-scale ladder, records", "ClRecords"),
    ("Corpus-scale ladder, findings", "ClKeptFindings"),
    ("Corpus-scale WISP patch-file rate (kept)", "ClKeptWispFile"),
    ("Corpus-scale WISP exact-changed-line rate (kept)", "ClKeptWispExact"),
    ("Corpus-scale WISP patch-file rate (contract)", "ClWispFile"),
    ("References that are preprints", "RefsPreprint"),
    # The corpus-scale equal-budget matrix, added 2026-08-10. The reversal is the claim a reader is
    # most likely to want to check against its source, since it contradicts the matched sample.
    ("Corpus equal-budget, WISP patch-file@1 at 25 s", "CmxWispPfOneTwentyFive"),
    ("Corpus equal-budget, wp-taint-scan patch-file@1 at 25 s", "CmxWptPfOneTwentyFive"),
    ("Corpus equal-budget, baseline lead at 25 s", "CmxWptLeadTwentyFive"),
    ("Corpus equal-budget, paired difference lower bound at 25 s", "CmxWispLeadTwentyFiveLo"),
    ("Per-plugin memory ceiling", "MemCapMb"),
    ("Largest completing scan measured (WISP)", "MemPeakWispMaxGb"),
    ("Largest divergent scan measured (wp-taint-scan)", "MemPeakWptMaxGb"),
    ("Resident memory at the kernel out-of-memory kill", "OomWptRssGb"),
    # Rank correlation between the two rungs, added 2026-08-10. The plugin-level row is the one a
    # reader will want, and the tool-level row is listed beside it precisely because it is the
    # reading the data cannot support, which is easier to check than to take on trust.
    ("Rank correlation across plugins, WISP", "RkPlugWispRho"),
    ("Rank correlation across plugins, pooled", "RkPlugPooledRho"),
    ("Plugin share scoring zero at the exact-line rung, WISP", "RkPlugWispZero"),
    ("Rank correlation across advisory classes, WISP", "RkClsWispRho"),
    ("Rank correlation across advisory classes, Semgrep", "RkClsSemgrepRho"),
    ("Rank correlation across the four tools (contract arm)", "RkToolCorpusRho"),
    ("Rank correlation across the four tools (kept arm)", "RkToolKeptRho"),
    ("Rank-correlation tests surviving Holm", "RkFamilySurvive"),
    # Endpoint transfer across two independent ground-truth sources, added 2026-08-11. The two rows a
    # reader should check against each other are the coarse rung, which transfers, and the exact
    # changed line, which does not, because the claim is the contrast rather than either value.
    ("Endpoint transfer, patched file, Spearman rho", "EtFileRho"),
    ("Endpoint transfer, patched file, interval lower bound", "EtFileLo"),
    ("Endpoint transfer, exact changed line, Spearman rho", "EtExactRho"),
    ("Endpoint transfer, exact changed line, interval lower bound", "EtExactLo"),
    ("Endpoint transfer, leading tool on Patchstack at the exact line", "EtExactLeadPs"),
    ("Endpoint transfer, leading tool on Wordfence at the exact line", "EtExactLeadWf"),
    ("Endpoint transfer, rungs whose leader agrees", "EtNLeaderAgree"),
]


def main():
    man = json.load(open(MANIFEST, encoding="utf-8"))["macros"]
    missing = [(c, m) for c, m in CLAIMS if m not in man]
    if missing:
        for c, m in missing:
            print(f"claim {c!r} names \\{m}, which the manifest does not define", file=sys.stderr)
        return 2
    with open(OUT, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["claim", "macro", "value", "source_json", "json_pointer",
                    "generating_script"])
        for claim, mac in CLAIMS:
            e = man[mac]
            w.writerow([claim, "\\" + mac, e["value"], e["json"], e["pointer"],
                        "eval/build_paper_macros_v3.py"])
    print(f"wrote {OUT} ({len(CLAIMS)} claims, every value taken from the manifest)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
