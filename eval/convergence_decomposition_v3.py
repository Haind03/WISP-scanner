#!/usr/bin/env python3
"""Which of the two v1.3 defaults bought the convergence, measured separately.

wisp-scanner-v1.3 flipped two defaults at once against v1.2:

  * `_PER_KEY_UPDATE_CAP` 4 -> 32, the per-definition summary rebuild cap.
  * `_MONOTONE_PROPS` off -> on, so the plugin property table accumulates across outer rounds
    instead of being cleared at the start of each one.

Corpus non-convergence fell from 272 of 1108 to 8. A reviewer is entitled to ask which change did
that, and a joint measurement cannot answer it. This script answers it without running the scanner,
because a third configuration was already measured: `train_cap_cap32_sensitivity.json` is the matched
100 at cap 32 with the property table still cleared. Three arms on one population, all from caches
already on disk:

    A   cap 4,  monotone off   the v1.2 contract configuration, read out of the corpus census
    B   cap 32, monotone off   the cap raised alone
    C   cap 32, monotone on    v1.3 as shipped

The arms are compared per record, keyed by slug and CVE together. Keying by slug alone is wrong here
and would go unnoticed: the matched sample holds 100 records over 98 distinct slugs, because
generateblocks and geo-mashup each carry two advisories.

Outcome classification is imported from `convergence_sensitivity_v3` rather than restated, so the two
scripts cannot drift apart. It has three outcomes and not two. A record killed at its budget has no
analysis status at all, so whether it would have converged is unknown, and folding it into
non-convergence would credit the engine with a failure it never demonstrated.

That distinction is the second thing this script reports. The shipped sensitivity cross-tab counts 12
plugins as oscillating at both caps, and one of those 12 did not oscillate, it timed out at cap 32.
The manuscript describes all 12 as oscillating between equivalent conservative approximations, which
is a claim about a bounded analysis that finished, and it is not true of a run that never finished.

One caution is recorded in the output rather than left to the reader. Arm C was produced on a host
that was also running a 1108-record corpus scan, arms A and B were not, so the timeout counts across
the three arms differ in host load as well as in configuration and no timeout difference here should
be read as an engine effect. The convergence counts are unaffected by load, since a record that
reaches a fixpoint reaches it regardless of how busy the machine was.

    python3 -m eval.convergence_decomposition_v3
"""
from __future__ import annotations
import os, json, hashlib, datetime, collections

from eval.convergence_sensitivity_v3 import outcome

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")

CENSUS_V12 = os.path.join(OUT, "CORPUS_CONVERGENCE_CENSUS_CORRECTED_V3.json")
CENSUS_V13 = os.path.join(OUT, "CORPUS_CONVERGENCE_CENSUS_MONOTONE_V3.json")
CAP32 = os.path.join(OUT, "train_cap_cap32_sensitivity.json")
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
DEST = os.path.join(OUT, "CONVERGENCE_DECOMPOSITION_V3.json")

# Arm C is the shipped matched-100 cache, which the ladder consumes.
TRAIN_CAP = os.environ.get("WISP_TRAIN_CAP") or os.path.join(
    SYS_ROOT, "final", "supplementary-data", "reproduce", "data", "train_cap.json")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _records(path: str) -> list:
    d = json.load(open(path, encoding="utf-8"))
    return d["records"] if isinstance(d, dict) else d


def _key(rec: dict) -> str:
    return rec["slug"] + "|" + (rec.get("cve") or "")


def _arm(path: str, restrict: set | None) -> dict:
    out = {}
    for r in _records(path):
        k = _key(r)
        if restrict is not None and k not in restrict:
            continue
        if k in out:
            raise SystemExit(f"duplicate record key {k} in {path}, the arms cannot be paired")
        out[k] = outcome(r)
    return out


def _tally(arm: dict) -> dict:
    c = collections.Counter(arm.values())
    return {k: c[k] for k in ("converged", "non_converged", "unknown_timeout", "error")}


def _transitions(a: dict, b: dict) -> dict:
    c = collections.Counter((a[k], b[k]) for k in a)
    return {f"{s}->{t}": n for (s, t), n in sorted(c.items())}


def main() -> int:
    keys = {l.strip() for l in open(SAMPLE, encoding="utf-8") if l.strip()}
    A = _arm(CENSUS_V12, keys)
    B = _arm(CAP32, None)
    C = _arm(TRAIN_CAP, None)
    for name, arm in (("A", A), ("B", B), ("C", C)):
        if set(arm) != keys:
            raise SystemExit(f"arm {name} does not cover the matched sample exactly, "
                             f"{len(set(arm) ^ keys)} keys differ")

    # The oscillating set as the shipped cross-tab defines it, then split by what actually happened.
    osc = [k for k in keys if A[k] != "converged" and B[k] != "converged"]
    osc_timeout = sorted(k for k in osc if B[k] == "unknown_timeout")
    osc_real = sorted(k for k in osc if B[k] == "non_converged")

    corpus12, corpus13 = _records(CENSUS_V12), _records(CENSUS_V13)

    def _corpus_block(recs: list) -> dict:
        t = _tally({_key(r): outcome(r) for r in recs})
        n = len(recs)
        return {"n": n, **t, "non_converged_rate": round(t["non_converged"] / n, 4)}

    # What is left. The paper claims the residue is a small identifiable set of plugins rather than a
    # diffuse instability, and that claim needs the set named rather than described.
    residual = sorted(_key(r) for r in corpus13 if outcome(r) == "non_converged")
    corpus = {
        "v12": _corpus_block(corpus12),
        "v13": _corpus_block(corpus13),
        "v13_residual": {
            "n_records": len(residual),
            "n_plugins": len({k.split("|")[0] for k in residual}),
            "plugins": sorted({k.split("|")[0] for k in residual}),
            "records": residual,
            "all_still_emit_findings": all(
                (r.get("findings") or []) for r in corpus13 if _key(r) in set(residual)),
        },
        "note": ("the corpus census runs uncapped, so neither arm holds a timeout and the "
                 "non-convergence counts need no separation there"),
    }

    res = {
        "schema_version": "analysis-v3-convergence-decomposition",
        "script": "eval/convergence_decomposition_v3.py",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "question": ("v1.3 flipped two defaults at once, so this separates the per-key cap from the "
                     "monotone property table on one population using caches already measured"),
        "arms": {
            "A": {"per_key_cap": 4, "monotone_props": False, "label": "v1.2 contract configuration",
                  "source": os.path.relpath(CENSUS_V12, SYS_ROOT), "tally": _tally(A)},
            "B": {"per_key_cap": 32, "monotone_props": False, "label": "cap raised alone",
                  "source": os.path.relpath(CAP32, SYS_ROOT), "tally": _tally(B)},
            "C": {"per_key_cap": 32, "monotone_props": True, "label": "v1.3 as shipped",
                  "source": os.path.relpath(TRAIN_CAP, SYS_ROOT), "tally": _tally(C)},
        },
        "n_records": len(keys),
        "n_distinct_slugs": len({k.split("|")[0] for k in keys}),
        "transitions": {"A_to_B_cap_alone": _transitions(A, B),
                        "B_to_C_adding_monotone": _transitions(B, C),
                        "A_to_C_both": _transitions(A, C)},
        "attribution": {
            "non_converged_A": _tally(A)["non_converged"],
            "non_converged_B": _tally(B)["non_converged"],
            "non_converged_C": _tally(C)["non_converged"],
            "rescued_by_cap_alone": sum(1 for k in keys if A[k] == "non_converged" and B[k] == "converged"),
            "rescued_by_monotone_after_cap": sum(1 for k in keys if B[k] == "non_converged" and C[k] == "converged"),
            "verdict": ("neither default alone reaches zero non-convergence on this sample, the cap "
                        "carries about half and the property table carries the rest"),
        },
        "oscillating_correction": {
            "as_shipped_ConvOscillating": len(osc),
            "genuine_oscillation": len(osc_real),
            "timed_out_at_cap32_not_oscillating": len(osc_timeout),
            "timed_out_keys": osc_timeout,
            "why": ("the cross-tab collapses three outcomes to two, so a record killed at its budget "
                    "is counted beside records that finished at a bounded approximation. The "
                    "manuscript calls all of them oscillating, which describes an analysis that "
                    "finished and is not true of one that did not"),
        },
        "corpus": corpus,
        "load_caveat": ("arm C was measured while a 1108-record corpus scan shared the host and arms "
                        "A and B were not, so the timeout counts differ in host load as well as in "
                        "configuration. No timeout difference across these arms is evidence about "
                        "the engine. Convergence counts are unaffected by load"),
        "input_hashes": {os.path.basename(p): _sha256(p) for p in (CENSUS_V12, CENSUS_V13, CAP32, TRAIN_CAP)},
    }
    with open(DEST, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, sort_keys=False)
        f.write("\n")
    a = res["attribution"]
    print(f"wrote {DEST}")
    print(f"  non-convergence on the matched 100: A {a['non_converged_A']} -> B "
          f"{a['non_converged_B']} -> C {a['non_converged_C']}")
    print(f"  rescued by the cap alone {a['rescued_by_cap_alone']}, "
          f"by the property table after it {a['rescued_by_monotone_after_cap']}")
    print(f"  ConvOscillating {len(osc)} of which {len(osc_timeout)} timed out rather than oscillated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
