#!/usr/bin/env python3
"""Convergence / cap-sensitivity characterization for the depth-bounded taint fixpoint.

WISP's inter-procedural taint solve is a bounded iterative approximation. Each definition key may be
updated at most WISP_PER_KEY_CAP times, and the global loop is capped at max(64, |D|*cap+64). A plugin
whose solve has not stabilized when the budget is exhausted is reported non-converged, and under the
Evaluation Contract's failure-as-miss policy it is scored as a miss over the full denominator. This
script measures how that non-convergence behaves as the per-key cap is raised, so the paper can
characterize the approximation honestly rather than assert a fixpoint it does not prove.

Two inputs, both produced by real scanner runs under the contract, no tool re-executed here:

  * CORPUS_CONVERGENCE_CENSUS_V3.json - the full 1108-advisory corpus at the contract cap (4).
  * train_cap_cap32_sensitivity.json  - the matched-100 sample re-run at cap 32 (8x the contract).

Output CONVERGENCE_SENSITIVITY_V3.json records the corpus non-convergence rate and the matched-sample
cap-4-vs-cap-32 cross-tabulation (how many plugins recover, how many regress, how many oscillate at
both caps). It also records, as a transparency-only secondary field, how many plugins' raw top-3
(file,line) tuples differ between the two caps. That tuple count is NOT a ladder-outcome delta: whether
a reordering changes a geometric rung is a separate scoring question handled by patch_geometry, and no
claim in the paper rests on the tuple count.

Corrected 2026-08-13. The two arms were paired by plugin slug, and a plugin can carry several
advisories, so 26 of the 100 sample records were compared against a different advisory of the same
plugin. The cross-tab counts are unaffected, verified by recomputing them both ways, and the tuple
count was: it read 18 and is 8. The pairing is now by slug and CVE together and the output records
how much the choice mattered, under `pairing`, so the next reader does not have to take it on trust.

    python3 -m eval.convergence_sensitivity_v3
"""
from __future__ import annotations
import os, sys, json, hashlib, datetime, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")

# Prefer the corrected census, which separates "the analysis finished and did not converge"
# from "the run was killed at a budget so the status is unknown". The original census marked
# both as wisp_converged=false, which is how the corpus figure came to fold 120 timeouts into
# a cap-bound non-convergence count.
CENSUS_CORRECTED = os.path.join(OUT, "CORPUS_CONVERGENCE_CENSUS_CORRECTED_V3.json")
CENSUS_RAW = os.path.join(OUT, "CORPUS_CONVERGENCE_CENSUS_V3.json")
CENSUS = CENSUS_CORRECTED if os.path.isfile(CENSUS_CORRECTED) else CENSUS_RAW
CAP32 = os.path.join(OUT, "train_cap_cap32_sensitivity.json")
DEST = os.path.join(OUT, "CONVERGENCE_SENSITIVITY_V3.json")

CONTRACT_CAP = 4
SENSITIVITY_CAP = 32


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def outcome(rec: dict) -> str:
    """Three outcomes, never two. A killed run has no analysis status, so whether it would
    converge is UNKNOWN; calling it non-converged manufactures evidence the run never produced."""
    err = rec.get("wisp_err") or ""
    if err == "timeout":
        return "unknown_timeout"
    if err:
        return "error"
    return "converged" if rec.get("wisp_converged") else "non_converged"


def _converged(rec: dict) -> bool:
    """Used only for the cap-4 vs cap-32 cross-tab, where both arms must be comparable."""
    return outcome(rec) == "converged"


def _top3(rec: dict) -> list:
    out = []
    for f in (rec.get("findings") or [])[:3]:
        out.append((f.get("file") or f.get("path"), f.get("line")))
    return out


def main() -> int:
    raw = json.load(open(CENSUS))
    census = raw["records"] if isinstance(raw, dict) else raw
    cap32 = json.load(open(CAP32))
    # Keyed by slug AND CVE, because a plugin can carry more than one advisory. The corpus census
    # holds 1108 records over 854 slugs, so keying by slug alone collapsed each repeated plugin to
    # whichever record came last and then compared the cap-32 arm against it. That resolved 26 of the
    # 100 sample records to a different advisory of the same plugin. The four cross-tab counts came
    # through it unchanged, which is luck and not design, and the top-3 reordering count did not: it
    # read 18 and is 8. Every other module in eval/ already keys records this way.
    by_key_cap4 = {r["slug"] + "|" + (r.get("cve") or ""): r for r in census}
    rkey = lambda r: r["slug"] + "|" + (r.get("cve") or "")

    # 1. corpus-wide non-convergence at the contract cap
    n_corpus = len(census)
    corpus_nonconv = [r["slug"] for r in census if outcome(r) == "non_converged"]
    corpus_unknown = [r["slug"] for r in census if outcome(r) == "unknown_timeout"]
    corpus_err = [r["slug"] for r in census if outcome(r) == "error"]
    n_known = n_corpus - len(corpus_unknown) - len(corpus_err)

    # 2. matched-sample cross-tabulation, contract cap (4) vs sensitivity cap (32)
    matched = [r for r in cap32 if rkey(r) in by_key_cap4]
    missing = [rkey(r) for r in cap32 if rkey(r) not in by_key_cap4]

    nc4, nc32, recovered, regressed, still_nc = [], [], [], [], []
    tuple_changed = []
    for r in matched:
        s = r["slug"]
        c4 = _converged(by_key_cap4[rkey(r)])
        c32 = _converged(r)
        if not c4:
            nc4.append(s)
        if not c32:
            nc32.append(s)
        if not c4 and c32:
            recovered.append(s)
        if c4 and not c32:
            regressed.append(s)
        if not c4 and not c32:
            still_nc.append(s)
        if _top3(by_key_cap4[rkey(r)]) != _top3(r):
            tuple_changed.append(s)

    # Diagnostic for the pairing itself, so a future reader can see whether the record key mattered
    # on this data rather than having to trust that it did.
    slug_counts = collections.Counter(r["slug"] for r in census)
    by_slug_last = {r["slug"]: r for r in census}
    n_ambiguous = sum(1 for r in cap32 if slug_counts[r["slug"]] > 1)
    n_misresolved = sum(1 for r in cap32 if by_slug_last[r["slug"]] is not by_key_cap4[rkey(r)])

    result = {
        "schema_version": "analysis-v3-convergence-sensitivity",
        "script": "eval/convergence_sensitivity_v3.py",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "contract_per_key_cap": CONTRACT_CAP,
        "sensitivity_per_key_cap": SENSITIVITY_CAP,
        "input_hashes": {
            "corpus_census": _sha256(CENSUS),
            "cap32_sensitivity": _sha256(CAP32),
        },
        "census_source": os.path.basename(CENSUS),
        "corpus_at_contract_cap": {
            "n": n_corpus,
            "non_converged": len(corpus_nonconv),
            "non_converged_rate": round(len(corpus_nonconv) / n_corpus, 4),
            "unknown_status_timeout": len(corpus_unknown),
            "errored": len(corpus_err),
            "n_with_known_status": n_known,
            "non_converged_rate_over_known_status":
                round(len(corpus_nonconv) / n_known, 4) if n_known else None,
            "note": "non_converged counts ONLY records whose analysis finished and reported "
                    "complete==false. A record killed at a budget has no status and is counted "
                    "under unknown_status_timeout, never as non-convergence.",
        },
        # How the two arms are paired, recorded because getting it wrong is invisible in the result.
        # Until 2026-08-13 the cap-4 arm was looked up by plugin slug, and the census holds 1108
        # records over 854 slugs, so a slug carrying several advisories collapsed to whichever record
        # came last. The four cross-tab counts happened to survive that, because convergence agreed
        # across advisories of the same plugin, but the top-3 reordering count did not: it read 18
        # and is 8. Nothing in the paper cited it, which is luck rather than design.
        "pairing": {
            "key": "slug|cve",
            "sample_records_with_ambiguous_slug_in_census": n_ambiguous,
            "would_misresolve_under_slug_keying": n_misresolved,
            "note": "a positive misresolve count means record keying is load-bearing here, not "
                    "defensive tidiness",
        },
        "matched_sample_cross_tab": {
            "n": len(matched),
            "not_found_in_census": missing,
            "non_converged_cap4": len(nc4),
            "non_converged_cap32": len(nc32),
            "recovered_cap4_nc_to_cap32_conv": len(recovered),
            "regressed_cap4_conv_to_cap32_nc": len(regressed),
            "oscillating_non_converged_at_both": len(still_nc),
        },
        "transparency_only": {
            "note": "raw top-3 (file,line) reordering, NOT a ladder-outcome delta; no claim rests on it",
            "top3_tuple_changed_cap4_vs_cap32": len(tuple_changed),
        },
        "oscillating_slugs": sorted(still_nc),
        "recovered_slugs": sorted(recovered),
    }
    json.dump(result, open(DEST, "w"), indent=1)
    print("wrote", DEST)
    print(json.dumps(result["corpus_at_contract_cap"], indent=1))
    print(json.dumps(result["matched_sample_cross_tab"], indent=1))
    print(json.dumps(result["transparency_only"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
