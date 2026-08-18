#!/usr/bin/env python3
"""Verify every cell of tab:fullcorpus and tab:common against the per-record data.

Written after an audit found Semgrep's file-precision@10 printed as 0.327 when the
data says 0.326. Nothing was miscomputed: the runner rounds to 4 decimals on the
way into its json, and the cell was then rounded again to 3, so 0.326460 became
0.3265 became 0.327. Double rounding is invisible in review and no amount of
re-reading the tex would catch it, so the fix is to check the printed cells
against ratios recomputed from the per-record details and rounded exactly once.

Every cell is derived, never transcribed: sums come from the same "details" lists
that the aggregates are built from, so a drift in either direction fails loudly.

    python3 -m eval.fourtool_check_paper           # check, exit 1 on any drift
    python3 -m eval.fourtool_check_paper --show    # print what the tex should say
"""
from __future__ import annotations
import os, re, sys, json, glob, argparse
from decimal import Decimal, ROUND_HALF_UP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SYS_ROOT = os.environ.get("WISP_SYS_ROOT") or os.path.dirname(ROOT)
TEX = [os.path.join(SYS_ROOT, "2026-07-07", "latex", "WISP-paper-CnS-elsarticle.tex")]
# WISP shards: prefer the rerun that carries per-record counters, fall back to the
# 2026-07-14 snapshot, whose aggregates are identical but whose details are older.
WISP_GLOBS = ["out/paired_20260717/loc_full/loc_*.json",
             "out/fill_20260714/loc_full/loc_*.json"]
BASE = {"Semgrep": "out/fill_20260714/atk_sg_1108.json",
        "Progpilot": "out/fill_20260714/atk_pp_1108.json",
        "wp-taint-scan": "out/fill_20260714/atk_wpt_1108.json"}
COMMON = "out/fill_20260714/common_subset_keys.json"
KS = ("1", "3", "5", "10")


def rnd(v, dec):
    return float(Decimal(str(v)).quantize(Decimal("1." + "0" * dec), rounding=ROUND_HALF_UP))


def wisp_records():
    for g in WISP_GLOBS:
        files = sorted(glob.glob(g))
        if not files:
            continue
        det = {}
        for f in files:
            for d in json.load(open(f))["details"]:
                det[d["slug"] + "|" + d["cve"]] = d
        # the 2026-07-14 snapshot predates the per-record @K counters, so it can
        # only answer part of the table. Fall through rather than KeyError.
        if det and "topk_tp" not in next(iter(det.values())):
            print(f"note: {g} has no per-record @K counters, skipping")
            continue
        return det, g
    sys.exit("no WISP localization shards with per-record @K counters found; "
             "run eval/run_paired_loc.sh")


def base_records(path):
    return {d["slug"] + "|" + d["cve"]: d
            for d in json.load(open(path))["details"]}


def stats(det, keys):
    sel = [det[k] for k in keys if k in det]
    if not sel:
        return None
    out = {}
    for k in KS:
        tp = sum(d["topk_tp"][k] for d in sel)
        n = sum(d["topk_n"][k] for d in sel)
        out[f"pf@{k}"] = tp / n if n else 0.0
    ft = sum(d["file_tp"] for d in sel)
    nf = sum(d["findings"] for d in sel)
    out["pool"] = ft / nf if nf else 0.0
    # failure-as-miss: a record a tool never answered simply is not a hit
    out["emission"] = sum(1 for d in sel if d.get("hit")) / len(sel)
    out["f_per_rec"] = nf / len(sel)
    out["n"] = len(sel)
    return out


def table_body(path, label):
    t = open(path).read()
    i = t.find("\\label{%s}" % label)
    if i < 0:
        return None
    return t[i:t.index("\\end{tabular}", i)]


def cells_of(body):
    """label -> list of floats, one per numeric column."""
    rows = {}
    for line in body.splitlines():
        if "&" not in line or "\\\\" not in line:
            continue
        cs = [c.strip() for c in line.split("\\\\")[0].split("&")]
        lab = re.split(r"\s*[($]", cs[0].replace("\\textbf{", "").replace("}", ""))[0].strip()
        nums = []
        for c in cs[1:]:
            m = re.search(r"\d+\.\d+|\d+", c.replace("\\textbf{", "").replace("}", ""))
            nums.append(float(m.group()) if m else None)
        if lab:
            rows[lab] = nums
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args()

    wisp, src = wisp_records()
    tools = {"WISP": wisp}
    tools.update({t: base_records(p) for t, p in BASE.items()})
    order = ["WISP", "Semgrep", "Progpilot", "wp-taint-scan"]
    full = sorted(wisp)
    common = sorted(set(json.load(open(COMMON))))
    print(f"WISP source: {src} ({len(full)} records); common subset {len(common)}")

    S = {v: {t: stats(tools[t], ks) for t in order}
         for v, ks in (("full", full), ("common", common))}

    if a.show:
        for v in ("full", "common"):
            print(f"\n=== {v} ===")
            for t in order:
                s = S[v][t]
                print(f"  {t:14} " + "  ".join(
                    f"{k}={rnd(s[k], 3)}" for k in ("pf@1", "pf@3", "pf@5", "pf@10",
                                                    "pool", "emission")) +
                    f"  f/rec={rnd(s['f_per_rec'], 2)}  n={s['n']}")
        return

    bad = 0
    for path in TEX:
        name = os.path.basename(path)
        body = table_body(path, "tab:fullcorpus")
        if body is None:
            print(f"[{name}] no tab:fullcorpus")
            bad += 1
        else:
            rows = cells_of(body)
            for k in KS:
                got = rows.get(k)
                exp = [rnd(S["full"][t][f"pf@{k}"], 3) for t in order]
                if got is None or got[:4] != exp:
                    print(f"[{name}] tab:fullcorpus K={k:<2} tex={got} data={exp}")
                    bad += 1
            for lab, key, dec in (("all findings", "pool", 3),
                                  ("class recall", "emission", 3)):
                got = rows.get(lab)
                exp = [rnd(S["full"][t][key], dec) for t in order]
                if got is None or got[:4] != exp:
                    print(f"[{name}] tab:fullcorpus {lab!r} tex={got} data={exp}")
                    bad += 1

        # tab:common is laid out exactly like tab:fullcorpus, so it checks the same way
        body = table_body(path, "tab:common")
        if body is None:
            print(f"[{name}] no tab:common")
            bad += 1
        else:
            rows = cells_of(body)
            for k in KS:
                got = rows.get(k)
                exp = [rnd(S["common"][t][f"pf@{k}"], 3) for t in order]
                if got is None or got[:4] != exp:
                    print(f"[{name}] tab:common K={k:<2} tex={got} data={exp}")
                    bad += 1
            for lab, key, dec in (("all findings", "pool", 3),
                                  ("class recall", "emission", 3),
                                  ("findings/record", "f_per_rec", 2)):
                got = rows.get(lab)
                exp = [rnd(S["common"][t][key], dec) for t in order]
                if got is None or got[:4] != exp:
                    print(f"[{name}] tab:common {lab!r} tex={got} data={exp}")
                    bad += 1
    if bad:
        sys.exit(f"\n{bad} cell(s) disagree with the per-record data.")
    print("all tab:fullcorpus and tab:common cells match the per-record data")


if __name__ == "__main__":
    main()
