#!/usr/bin/env python3
"""Why every tool but Semgrep gains on the common subset.

The common-520 arm keeps the records all four tools completed, and on it every tool's class
emission rises against the full corpus except Semgrep's, which falls by more than a third while its
per-finding precision rises. Left unexplained that looks like an artefact. It is a selection
effect, and it is measurable rather than a story: the subset is defined by the two tools with the
worst coverage, whose failures are budget exhaustion on large plugins, so the subset is the
small-plugin half of the corpus. A tool that failed often gains the records the subset restores. A
tool that almost never failed gains nothing and simply loses the large plugins it was scoring on.

    python3 -m eval.common_subset_bias_v3
"""
from __future__ import annotations
import os, sys, json, glob, statistics

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "COMMON_SUBSET_BIAS_V3.json")
COMMON = os.path.join(ROOT, "out/fill_20260714/common_subset_keys.json")
SEMGREP = os.path.join(ROOT, "out/fill_20260714/atk_sg_1108.json")
WISP_GLOB = os.path.join(ROOT, "out/paired_20260717/loc_full/loc_*.json")


def key(r):
    return r["slug"] + "|" + r["cve"]


def main():
    common = set(json.load(open(COMMON, encoding="utf-8")))
    sg = {key(r): r for r in json.load(open(SEMGREP, encoding="utf-8"))["details"]}
    wisp = {}
    for f in sorted(glob.glob(WISP_GLOB)):
        for r in json.load(open(f, encoding="utf-8"))["details"]:
            wisp[key(r)] = r

    inside = [k for k in sg if k in common]
    outside = [k for k in sg if k not in common]

    def emission(keys):
        hit = sum(1 for k in keys if not sg[k].get("err") and sg[k].get("hit"))
        return {"hits": hit, "n": len(keys), "emission": round(hit / len(keys), 4)}

    def size(keys, field):
        v = [wisp[k][field] for k in keys if k in wisp and wisp[k].get(field) is not None]
        return {"median": statistics.median(v), "n": len(v)} if v else None

    res = {
        "schema_version": "common-subset-bias-v3",
        "script": "eval/common_subset_bias_v3.py",
        "question": ("why class emission rises on the common subset for every tool except Semgrep, "
                     "whose emission falls while its per-finding precision rises"),
        "subset_definition": ("records every one of the four tools completed, so the subset is "
                              "bounded by the two tools with the lowest coverage"),
        "semgrep_emission_inside": emission(inside),
        "semgrep_emission_outside": emission(outside),
        "plugin_size_proxy": {
            "note": "WISP findings per record and vendor-changed file count, measured on the "
                    "same records, as a size proxy independent of any baseline",
            "wisp_findings_median_inside": size(inside, "findings"),
            "wisp_findings_median_outside": size(outside, "findings"),
            "changed_files_median_inside": size(inside, "gt_files"),
            "changed_files_median_outside": size(outside, "gt_files"),
        },
    }
    json.dump(res, open(OUT, "w"), indent=1, sort_keys=True)
    print(f"wrote {OUT}")
    i, o = res["semgrep_emission_inside"], res["semgrep_emission_outside"]
    print(f"  semgrep emission inside {i['emission']} ({i['hits']}/{i['n']}), "
          f"outside {o['emission']} ({o['hits']}/{o['n']})")
    p = res["plugin_size_proxy"]
    print(f"  median WISP findings inside {p['wisp_findings_median_inside']['median']}, "
          f"outside {p['wisp_findings_median_outside']['median']}")
    print(f"  median changed files inside {p['changed_files_median_inside']['median']}, "
          f"outside {p['changed_files_median_outside']['median']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
