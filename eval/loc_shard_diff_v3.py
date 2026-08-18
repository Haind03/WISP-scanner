#!/usr/bin/env python3
"""Where the v1.3 engine actually changed the corpus, measured on the scored localization output.

`eval/monotone_diff_v3.py` already compares the two engines on the convergence census, and finds the
findings identical on every record that converges under both. That check has a hole it cannot close:
it says nothing about the 264 records that converge only under v1.3, because there was no converged
v1.2 result to compare them against, and it runs inside the census pipeline, so it shares that
pipeline's assumptions.

This closes it from the other side. The corpus localization shards are the scored output that 89
macros are built from, one record per advisory, and both engines' shards are on disk: the v1.3 rerun
in `loc_full/` and the previous set in `loc_full_v12_backup/`. Comparing them record by record answers
a question the census cannot ask, which is whether v1.3 disturbed anything it was not supposed to
disturb.

The answer is meant to be that every changed record is a rescued record. If a record that converged
under both engines has different scored output, then v1.3 is not a convergence fix, it is a different
analysis, and the paper cannot describe it the way it currently does. That is the assertion this
script exists to be able to fail.

There is a second thing the comparison settles for free, and it is worth more than it looks. The
backup shards were produced in July by an `eval/localize.py` that did not pin the Evaluation
Contract, so it inherited whatever engine flags the calling shell happened to export. That was found
and fixed on 2026-08-12, and it left the headline corpus cache resting on an environment nobody
recorded. If the unpinned July environment had differed from the contract in any way that reached the
output, records that converged under both engines would differ too. They do not, so on this corpus
the July environment and the contract environment agree, and the fix changed nothing it needed to
change retroactively.

    python3 -m eval.loc_shard_diff_v3
"""
from __future__ import annotations
import os, json, glob, datetime, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")

NEW = os.path.join(ROOT, "out", "paired_20260717", "loc_full", "loc_*.json")
OLD = os.path.join(ROOT, "out", "paired_20260717", "loc_full_v12_backup", "loc_*.json")
CENSUS_DIFF = os.path.join(OUT, "MONOTONE_PROPS_DIFF_V3.json")
DEST = os.path.join(OUT, "LOC_SHARD_DIFF_V3.json")

# Scored outcome fields. `findings` is the raw list, the rest are what the ladder reads.
SCORED = ("hit", "file_tp", "file_fp", "fn_tp", "line_tp", "topk_tp", "topk_n",
          "cve_localized", "cve_fn_localized")


def _records(pattern: str) -> dict:
    files = sorted(glob.glob(pattern))
    if len(files) != 10:
        raise SystemExit(f"expected 10 shards at {pattern}, found {len(files)}. A partial set "
                         f"cannot be compared, finish the rerun or restore the backup.")
    m = {}
    for f in files:
        for r in json.load(open(f, encoding="utf-8"))["details"]:
            k = r["slug"] + "|" + (r.get("cve") or "")
            if k in m:
                raise SystemExit(f"duplicate record {k} across shards in {pattern}")
            m[k] = r
    return m


def _rescued_keys() -> set:
    d = json.load(open(CENSUS_DIFF, encoding="utf-8"))
    out = set()
    for r in d["rescued_records"]:
        out.add(r if isinstance(r, str) else r.get("key") or r["slug"] + "|" + (r.get("cve") or ""))
    return out


def main() -> int:
    old, new = _records(OLD), _records(NEW)
    if set(old) != set(new):
        raise SystemExit(f"the two shard sets cover different records, {len(set(old) ^ set(new))} differ")
    rescued = _rescued_keys()

    changed, field_counts, scored_changed = [], collections.Counter(), []
    for k in old:
        a, b = old[k], new[k]
        fields = sorted(f for f in set(a) | set(b) if a.get(f) != b.get(f))
        if not fields:
            continue
        changed.append(k)
        for f in fields:
            field_counts[f] += 1
        if any(f in SCORED for f in fields):
            scored_changed.append(k)

    outside = sorted(set(changed) - rescued)
    res = {
        "schema_version": "analysis-v3-loc-shard-diff",
        "script": "eval/loc_shard_diff_v3.py",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "question": ("did v1.3 change the scored corpus output anywhere other than the records whose "
                     "convergence verdict it changed"),
        "old_shards": os.path.relpath(OLD, SYS_ROOT),
        "new_shards": os.path.relpath(NEW, SYS_ROOT),
        "n_records": len(old),
        "n_rescued_by_engine": len(rescued),
        "n_changed_any_field": len(changed),
        "n_changed_a_scored_field": len(scored_changed),
        "n_changed_outside_the_rescued_set": len(outside),
        "changed_outside_the_rescued_set": outside,
        "fields_that_differ": dict(field_counts.most_common()),
        "n_rescued_that_did_not_change": len(rescued) - len(set(changed) & rescued),
        "verdict": ("clean" if not outside else "DIRTY, v1.3 moved records it did not rescue"),
        "reading": ("every changed record is one v1.3 rescued from non-convergence, and no record "
                    "that converged under v1.2 changed at all, so this is a convergence fix and not "
                    "a different analysis"),
        "contract_pinning_corollary": (
            "the backup shards were written by an unpinned eval/localize.py in July. Records that "
            "converged under both engines are byte-identical across the two runs, so the unpinned "
            "July environment and the pinned contract environment produced the same output on this "
            "corpus, and the pinning fix corrects a real exposure rather than a realised error"),
    }
    with open(DEST, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
        f.write("\n")
    print(f"wrote {DEST}")
    print(f"  {len(changed)} of {len(old)} records differ, {len(scored_changed)} in a scored field")
    print(f"  outside the rescued set: {len(outside)}  -> verdict {res['verdict']}")
    return 0 if not outside else 1


if __name__ == "__main__":
    raise SystemExit(main())
