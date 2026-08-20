#!/usr/bin/env python3
"""Per-tool split of the share of in-patched-file findings that had no exact-line target.

A reviewer's serious point is that the exact-changed-line rung is structurally biased against
taint tools. The paper answers with a pooled number: of 347 findings that landed in a
patch-changed file, 33 landed in a file the patch deleted or only inserted into, so 0.095 of the
in-file findings were in the rung's denominator and could never be in its numerator.

Pooled, that number cannot answer the objection. "Biased against taint tools" is a claim about how
the share differs between tools, and one pooled share is equally consistent with the four shares
being identical and with one tool carrying all 33. Splitting it is the measurement the objection
actually asks for, and no JSON on disk carried the split.

This derives it without re-running the census, which would re-diff every record and move a shipped
result file for a number that is already inside it. It reads the census rows and the finding
population the census itself read, recomputes the pooled figures the paper prints, and refuses to
write anything unless they come out identical to the shipped ones. A derivation that cannot
reproduce its own source's published totals is not measuring the same thing, so it should not be
allowed to publish a split of them.

    python3 -m eval.unanchorable_per_tool_v3
    python3 -m eval.unanchorable_per_tool_v3 --selftest   # prove the agreement check fires

Writes revision-cns-v2/out/UNANCHORABLE_PER_TOOL_V3.json.
"""
from __future__ import annotations
import os, sys, json, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

OUT_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CENSUS = os.path.join(OUT_DIR, "PATCH_SHAPE_CENSUS_V3.json")
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
OUT = os.path.join(OUT_DIR, "UNANCHORABLE_PER_TOOL_V3.json")

# Both fixed by eval/patch_shape_census_v3.py, which is the file this one derives from. They are
# repeated rather than imported because importing that module pulls in the scan path.
TOPK = 3
TOOLS = ("wisp", "semgrep", "wpt", "progpilot")


def _shape_index(census):
    rows = census["datasets"]["matched-100"]["records"]
    return {r["key"]: r for r in rows if not r["error"]}


def _population():
    pop = []
    with open(POP, encoding="utf-8") as fh:
        for ln in fh:
            if not ln.strip():
                continue
            g = json.loads(ln)
            if g["rank"] <= TOPK:
                pop.append(g)
    return pop


def _split(shape, pop):
    """Return (pooled, per_tool). Same two predicates the census uses, in the same order."""
    def unanchorable(g):
        s = shape.get(g["slug"] + "|" + g["cve"])
        return bool(s) and g.get("file") in set(s.get("unanchorable_php_files") or [])

    infile = [g for g in pop if g["in_patched_file"] and g["slug"] + "|" + g["cve"] in shape]
    pooled = {
        "n_top3_findings": len(pop),
        "n_in_patched_file": len(infile),
        "n_in_unanchorable_file": sum(1 for g in infile if unanchorable(g)),
    }
    pooled["share_of_in_file_findings"] = (
        round(pooled["n_in_unanchorable_file"] / len(infile), 4) if infile else None)

    per_tool = {}
    for t in TOOLS:
        mine = [g for g in infile if g["tool"] == t]
        if not mine:
            continue
        n_un = sum(1 for g in mine if unanchorable(g))
        per_tool[t] = {
            "n_in_patched_file": len(mine),
            "n_in_unanchorable_file": n_un,
            "share_of_in_file_findings": round(n_un / len(mine), 4),
        }
    return pooled, per_tool


def _raw(v):
    """A tool's share from its own counts, so a ratio of two shares never divides rounded numbers."""
    return v["n_in_unanchorable_file"] / v["n_in_patched_file"] if v["n_in_patched_file"] else 0.0


def _agree_or_die(pooled, shipped):
    """The whole licence for this file. Derived pooled totals must equal the published ones."""
    bad = [k for k in ("n_top3_findings", "n_in_patched_file", "n_in_unanchorable_file",
                       "share_of_in_file_findings") if pooled[k] != shipped.get(k)]
    if bad:
        lines = [f"  {k}: derived {pooled[k]!r} vs shipped {shipped.get(k)!r}" for k in bad]
        raise SystemExit("ABORT, nothing written: this derivation does not reproduce the pooled "
                         "unanchorable-file figures the paper already prints, so its per-tool "
                         "split is a split of something else.\n" + "\n".join(lines))


def selftest():
    """Break the agreement on purpose and require the check to fire, then require it not to."""
    census = json.load(open(CENSUS))
    shape = _shape_index(census)
    pop = _population()
    shipped = census["exact_line_sensitivity_matched_100"]["unanchorable_file_share"]

    pooled, per_tool = _split(shape, pop)
    _agree_or_die(pooled, shipped)
    print(f"selftest: clean tree agrees, {pooled['n_in_unanchorable_file']} of "
          f"{pooled['n_in_patched_file']} pooled, and the check stayed silent")

    # Take away an unanchorable file that a finding actually landed in, so the pooled count has
    # to drop. Picking any record with an unanchorable file is not enough: most of those files
    # host no finding, and removing one of those moves nothing and proves nothing.
    hit = None
    for g in pop:
        k = g["slug"] + "|" + g["cve"]
        r = shape.get(k)
        if g["in_patched_file"] and r and g.get("file") in set(r.get("unanchorable_php_files") or []):
            hit = (r, g["file"])
            break
    if hit is None:
        raise SystemExit("selftest inconclusive: no finding sits in an unanchorable file, so the "
                         "probe has nothing to remove")
    victim, drop_file = hit
    keep = victim["unanchorable_php_files"]
    victim["unanchorable_php_files"] = [f for f in keep if f != drop_file]
    broken, _ = _split(shape, pop)
    victim["unanchorable_php_files"] = keep
    if broken["n_in_unanchorable_file"] == pooled["n_in_unanchorable_file"]:
        raise SystemExit(f"selftest inconclusive: removing {drop_file} from "
                         f"{victim['key']} changed no count, so the probe missed")
    try:
        _agree_or_die(broken, shipped)
    except SystemExit:
        print(f"selftest: the check fires when {victim['key']} loses one unanchorable file "
              f"({broken['n_in_unanchorable_file']} instead of "
              f"{pooled['n_in_unanchorable_file']}), and it is silent on the clean tree")
        return 0
    raise SystemExit("selftest FAILED: the agreement check passed on a tree it should refuse")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    if a.selftest:
        return selftest()

    census = json.load(open(CENSUS))
    shape = _shape_index(census)
    pop = _population()
    shipped = census["exact_line_sensitivity_matched_100"]["unanchorable_file_share"]
    pooled, per_tool = _split(shape, pop)
    _agree_or_die(pooled, shipped)

    ranked = sorted(per_tool, key=lambda t: per_tool[t]["share_of_in_file_findings"])
    result = {
        "schema_version": "unanchorable-per-tool-v1",
        "derived_from": {
            "census": os.path.relpath(CENSUS, SYS_ROOT),
            "census_generated_utc": census.get("generated_utc"),
            "population": os.path.relpath(POP, SYS_ROOT),
            "topk": TOPK,
        },
        "unit": ("one top-3 finding that landed in a patch-changed PHP file of the matched "
                 "100-record sample; the share is over that tool's own in-file findings, so the "
                 "four denominators differ and the shares do not pool by averaging"),
        "pooled": pooled,
        "per_tool": per_tool,
        "spread": {
            "lowest": ranked[0],
            "highest": ranked[-1],
            # From the raw counts, never from the rounded shares. Dividing 0.1935 by 0.0417 gives
            # 4.64 and dividing 18/93 by 1/24 gives 4.65, and the second is the ratio of the two
            # things measured. This is the rounding-before-dividing class the arithmetic audit
            # lists, caught here by a peer review of this file on 2026-08-20.
            "ratio_highest_to_lowest": round(_raw(per_tool[ranked[-1]]) / _raw(per_tool[ranked[0]]), 2)
            if _raw(per_tool[ranked[0]]) else None,
            # Whether that ratio is worth reading at all. Progpilot's end of it is one finding, so
            # the ratio and the word "spread" are both driven by a single observation, and the
            # paper states the denominators instead of the ratio for that reason.
            "smallest_numerator": {"tool": min(per_tool, key=lambda t: per_tool[t]["n_in_unanchorable_file"]),
                                   "n_in_unanchorable_file": min(
                                       v["n_in_unanchorable_file"] for v in per_tool.values())},
        },
        "note": ("the pooled figures above are recomputed here and were required to equal the "
                 "ones the census publishes before this file was written, so the split is a "
                 "split of the number the paper already prints and not of a second measurement"),
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(result, open(a.out, "w"), indent=1, sort_keys=True)
    print("wrote", a.out)
    for t in ranked:
        v = per_tool[t]
        print(f"  {t:10s} {v['n_in_unanchorable_file']:3d} of {v['n_in_patched_file']:3d}"
              f"  {v['share_of_in_file_findings']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
