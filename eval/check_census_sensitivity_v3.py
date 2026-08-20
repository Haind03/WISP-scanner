#!/usr/bin/env python3
"""Refuse a census whose sensitivity block was computed over a different finding population.

The defect this exists for, found 2026-08-20. `PATCH_SHAPE_CENSUS_V3.json` holds two things with
different inputs. The per-record rows come from the vendor diffs. The
`exact_line_sensitivity_matched_100` block underneath them comes from the shipped finding
population, which is regenerated whenever a tool's findings change. The rows were diffed on
2026-08-02 and the population was regenerated on 2026-08-13, when WISP's findings moved. Nothing
recomputed the block, so it went on describing 710 top-3 findings and 280 WISP findings while
`GEOMETRIC_LADDER_V3.json`, from the same population, described 701 and 271, and the manuscript
printed both.

No guard could see it. `check_paper_macros_v3` compares each macro to its JSON and both agreed;
the JSON was internally consistent and externally stale. A guard cannot check the source it
derives from, so this one goes to the source's own source: it recomputes the block from the rows
on disk and the population as it stands, and requires the stored block to equal it exactly.

    python3 -m eval.check_census_sensitivity_v3
    python3 -m eval.check_census_sensitivity_v3 --selftest   # prove it fires

Exit 0 when the stored block is what the current inputs produce, 1 otherwise.
"""
from __future__ import annotations
import os, sys, json, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from eval import patch_shape_census_v3 as C


def _flat(d, p=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(_flat(v, f"{p}.{k}" if p else k))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            out.update(_flat(v, f"{p}[{i}]"))
    else:
        out[p] = d
    return out


def _compare(stored, fresh):
    fo, fn = _flat(stored or {}), _flat(fresh)
    keys = sorted(set(fo) | set(fn))
    return [(k, fo.get(k), fn.get(k)) for k in keys
            if fo.get(k) != fn.get(k) and not k.endswith(".note")]


def check(path=None, verbose=True):
    path = path or C.OUT
    census = json.load(open(path))
    rows = census.get("datasets", {}).get("matched-100", {}).get("records")
    if rows is None:
        print("SKIP: this census carries no matched-100 rows, so it has no sensitivity block")
        return 0

    fresh = C.exact_line_sensitivity(rows)
    diff = _compare(census.get("exact_line_sensitivity_matched_100"), fresh)

    fp = C.population_fingerprint()
    stamp = census.get("sensitivity_population")
    problems = []
    if diff:
        problems.append(f"{len(diff)} leaf values in exact_line_sensitivity_matched_100 are not "
                        f"what the current population produces")
    if stamp is None:
        problems.append("the census carries no sensitivity_population stamp, so which population "
                        "the block was computed over is unrecorded")
    elif stamp.get("sha256") != fp["sha256"]:
        problems.append(f"the stamped population sha256 {str(stamp.get('sha256'))[:12]} is not the "
                        f"population on disk {fp['sha256'][:12]}")

    if not problems:
        if verbose:
            print(f"OK: the sensitivity block reproduces from {fp['n_findings_at_topk']} findings "
                  f"at top-{fp['topk']}, and the stamped population is the one on disk")
        return 0

    print("CENSUS SENSITIVITY IS STALE")
    for p in problems:
        print(f"  {p}")
    for k, a, b in diff[:12]:
        print(f"    {k}: stored {a}   current inputs give {b}")
    if len(diff) > 12:
        print(f"    ... and {len(diff) - 12} more")
    print("  fix: python3 -m eval.patch_shape_census_v3 --sensitivity-only")
    return 1


def selftest():
    """Require the check to fire on a perturbed copy, and to stay silent on the real one."""
    import tempfile, shutil
    census = json.load(open(C.OUT))
    if "exact_line_sensitivity_matched_100" not in census:
        raise SystemExit("selftest cannot run: the census on disk has no sensitivity block")

    with tempfile.TemporaryDirectory() as td:
        broken_p = os.path.join(td, "broken.json")
        broken = json.loads(json.dumps(census))
        arm = broken["exact_line_sensitivity_matched_100"]["all_records"]["wisp"]
        arm["n_findings"] = int(arm["n_findings"]) + 1
        json.dump(broken, open(broken_p, "w"))
        if check(broken_p, verbose=False) == 0:
            raise SystemExit("selftest FAILED: one added finding in the stored block did not fire")
        print("selftest: adding one finding to the stored block fires the check")

        clean_p = os.path.join(td, "clean.json")
        clean = json.loads(json.dumps(census))
        clean["exact_line_sensitivity_matched_100"] = C.exact_line_sensitivity(
            clean["datasets"]["matched-100"]["records"])
        clean["sensitivity_population"] = C.population_fingerprint()
        json.dump(clean, open(clean_p, "w"))
        if check(clean_p, verbose=False) != 0:
            raise SystemExit("selftest FAILED: a freshly recomputed block was rejected, so the "
                             "check fires on a clean tree and is worthless")
        print("selftest: a freshly recomputed block passes, so it is not firing on everything")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--census", default=None)
    a = ap.parse_args()
    sys.exit(selftest() if a.selftest else check(a.census))
