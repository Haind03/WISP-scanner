#!/usr/bin/env python3
"""Old versus new audit for the accumulating property table (WISP_MONOTONE_PROPS).

The engine change is only defensible if it does two things at once. It has to rescue records whose
analysis never reached a fixpoint, and it has to leave alone every record that already reached one.
The second half is the real test. A change that raises convergence by also changing what the engine
reports on records it was already finishing is not a convergence fix, it is a different analysis
wearing the same name, and every number in the paper would have to be rebuilt around it.

So this compares two censuses record by record and refuses to summarise past a disagreement. The
baseline census and the new census are both produced by eval.convergence_census_v3, over the same
1108 records, with the same uncapped budget, differing only in the engine flags the new run passes.

    python3 -m eval.monotone_diff_v3 --base <baseline census> --new <new census> --out <json>

Exit status is 0 when the audit is clean, 1 when a record that converged under both configurations
reports a different number of findings. A non-zero exit is the finding, not a crash.
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

OUTD = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
BASE_DEFAULT = os.path.join(OUTD, "CORPUS_CONVERGENCE_CENSUS_CORRECTED_V3.json")
NEW_DEFAULT = os.path.join(OUTD, "CORPUS_CONVERGENCE_CENSUS_MONOTONE_V3.json")
OUT_DEFAULT = os.path.join(OUTD, "MONOTONE_PROPS_DIFF_V3.json")


def _records(path):
    d = json.load(open(path, encoding="utf-8"))
    recs = d["records"] if isinstance(d, dict) else d
    meta = {k: v for k, v in d.items() if k != "records"} if isinstance(d, dict) else {}
    return {r["slug"] + "|" + r["cve"]: r for r in recs}, meta


def _state(r):
    """Three outcomes, matching the census. A timeout is not a known non-convergence."""
    if r.get("wisp_err"):
        return "unknown_timeout" if r["wisp_err"] == "timeout" else "error"
    return "converged" if r.get("wisp_converged") else "non_converged"


def _finding_keys(r):
    """A finding identity that does not depend on rank, so a reordering is not read as a change.

    The two censuses do NOT serialise findings the same way. The baseline census carries the older
    key names cls, sink, conf, ep, and the re-run carries the scanner's own classes, rule,
    confidence, entry_point. Comparing the raw dicts would report every record as changed, which is
    the kind of false alarm that gets an audit ignored. Both are normalised here to file, line,
    class and sink, and never to position.

    The 120 records that a merge folded into the baseline carry a finding count but no findings, so
    the caller has to treat an empty side as unknown rather than as an empty result."""
    out = Counter()
    for f in r.get("findings") or []:
        cls = f.get("cls")
        if cls is None:
            got = f.get("classes") or []
            cls = ",".join(sorted(got)) if isinstance(got, (list, tuple, set)) else str(got)
        sink = f.get("sink")
        if sink is None:
            sink = f.get("rule", "")
        out[(f.get("file", ""), f.get("line", 0), cls, sink)] += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=BASE_DEFAULT)
    ap.add_argument("--new", default=NEW_DEFAULT)
    ap.add_argument("--out", default=OUT_DEFAULT)
    a = ap.parse_args()

    base, bmeta = _records(a.base)
    new, nmeta = _records(a.new)

    only_base = sorted(set(base) - set(new))
    only_new = sorted(set(new) - set(base))
    shared = sorted(set(base) & set(new))
    if only_base or only_new:
        print(f"WARNING: {len(only_base)} records only in base, {len(only_new)} only in new. "
              f"The audit runs over the {len(shared)} shared records.")

    transitions = Counter()
    rescued, lost, changed_while_converged, count_only = [], [], [], []
    for k in shared:
        b, n = base[k], new[k]
        sb, sn = _state(b), _state(n)
        transitions[f"{sb}->{sn}"] += 1
        if sb == "non_converged" and sn == "converged":
            rescued.append({"key": k, "n_base": b.get("wisp_n_findings"),
                            "n_new": n.get("wisp_n_findings")})
        if sb == "converged" and sn != "converged":
            lost.append({"key": k, "new_state": sn})
        if sb == "converged" and sn == "converged":
            nb, nn = b.get("wisp_n_findings"), n.get("wisp_n_findings")
            if nb != nn:
                changed_while_converged.append({"key": k, "n_base": nb, "n_new": nn})
            else:
                kb, kn = _finding_keys(b), _finding_keys(n)
                if kb and kn and kb != kn:
                    # Same count, different findings. Weaker than a count change but still a change
                    # on a record the flag is supposed to leave untouched, so it is reported apart
                    # rather than folded into the clean total.
                    count_only.append({"key": k,
                                       "gained": sorted(str(x) for x in (kn - kb)),
                                       "lost": sorted(str(x) for x in (kb - kn))})

    both_converged = transitions["converged->converged"]
    clean = not changed_while_converged and not lost and not count_only

    def total(recs, keys):
        return sum((recs[k].get("wisp_n_findings") or 0) for k in keys)

    stable_keys = [k for k in shared
                   if _state(base[k]) == "converged" and _state(new[k]) == "converged"]

    res = {
        "schema_version": "monotone-props-diff-v3",
        "base": os.path.relpath(a.base, SYS_ROOT),
        "new": os.path.relpath(a.new, SYS_ROOT),
        "base_engine_env": bmeta.get("engine_env_overrides", "not recorded"),
        "new_engine_env": nmeta.get("engine_env_overrides", "not recorded"),
        "n_shared_records": len(shared),
        "records_only_in_base": only_base,
        "records_only_in_new": only_new,
        "transitions": dict(sorted(transitions.items())),
        "convergence": {
            "base_converged": sum(1 for k in shared if _state(base[k]) == "converged"),
            "new_converged": sum(1 for k in shared if _state(new[k]) == "converged"),
            "base_non_converged": sum(1 for k in shared if _state(base[k]) == "non_converged"),
            "new_non_converged": sum(1 for k in shared if _state(new[k]) == "non_converged"),
            "rescued": len(rescued),
            "lost": len(lost),
        },
        "stability_check": {
            "question": ("do the records that converge under BOTH configurations report the same "
                         "findings, which is what a convergence-only change must satisfy"),
            "n_records_converged_in_both": both_converged,
            "n_with_changed_finding_count": len(changed_while_converged),
            "n_with_same_count_different_findings": len(count_only),
            "findings_base": total(base, stable_keys),
            "findings_new": total(new, stable_keys),
            "verdict": "clean" if clean else "NOT CLEAN, investigate before adopting",
        },
        "rescued_records": rescued,
        "lost_records": lost,
        "changed_while_converged": changed_while_converged,
        "same_count_different_findings": count_only,
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1)

    print(json.dumps({k: v for k, v in res.items()
                      if k in ("transitions", "convergence", "stability_check")}, indent=1))
    print("wrote", a.out)
    if not clean:
        print(f"NOT CLEAN: {len(changed_while_converged)} records changed their finding count and "
              f"{len(count_only)} changed their findings while converging under both "
              f"configurations. The flag is not a pure convergence fix on this corpus.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
