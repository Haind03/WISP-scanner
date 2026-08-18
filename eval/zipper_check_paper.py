#!/usr/bin/env python3
"""Verify every ZIPPER number printed in the paper against ZIPPER_VS_WISP.json.

The tables were written while the tuned rerun was still going, so the figures in the tex are a
snapshot of an unfinished sweep. Coverage in particular can only move in ZIPPER's favour as
records that failed under contention complete on the idle box, and shipping a stale coverage
would understate a baseline, which is the exact unfairness the Progpilot exit-code bug caused.
This script is the guard: it re-reads the results and fails loudly on any cell that has drifted,
so the refresh cannot be forgotten.

    python3 -m eval.zipper_check_paper            # check
    python3 -m eval.zipper_check_paper --show     # print what the tex should say
"""
import json, re, sys, os, argparse

SYS_ROOT = os.environ.get("WISP_SYS_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEX = [os.path.join(SYS_ROOT, "2026-07-07", "latex", "WISP-paper-CnS-elsarticle.tex")]
RESULTS = "out/zipper/ZIPPER_VS_WISP.json"


def expected(d):
    """The cells tab:zipper prints, at the precision the tex prints them."""
    ep = {e["endpoint"]: e for e in d["endpoints"]}
    sil = d["silent_records"]
    rows = {}
    for k in ("1", "3", "5", "10"):
        e = ep[f"file_precision@{k}"]
        rows[f"file-precision@{k}"] = (round(e["wisp"], 3), round(e["zipper"], 3))
    e = ep["class_emission"]
    rows["class emission"] = (round(e["wisp"], 3), round(e["zipper"], 3))
    rows["coverage"] = (round(d["coverage"]["wisp"], 3), round(d["coverage"]["zipper"], 3))
    rows["findings/record"] = (round(d["findings_per_record"]["wisp"], 1),
                               round(d["findings_per_record"]["zipper"], 1))
    # key normalised the same way tex_rows normalises its labels (parenthetical dropped)
    rows["silent"] = (round(sil["wisp"] / d["paired_records"], 3),
                      round(sil["zipper_frac_of_completed"], 3))
    return rows


def tex_rows(path):
    """Parse the body rows of tab:zipper out of the tex."""
    t = open(path).read()
    i = t.find("\\label{tab:zipper}")
    if i < 0:
        return None
    body = t[i:t.index("\\end{tabular}", i)]
    out = {}
    for line in body.splitlines():
        if "&" not in line or "\\\\" not in line:
            continue
        cells = [c.strip() for c in line.split("\\\\")[0].split("&")]
        if len(cells) < 3:
            continue
        # Normalise the row label: a caveat like "coverage ($\ge$, see text)" is the same row as
        # "coverage" for checking purposes, so drop any trailing parenthetical or math.
        label = re.split(r"\s*[($]", cells[0].strip())[0].strip()
        nums = []
        for c in cells[1:3]:
            m = re.search(r"[\d.]+", c.replace("\\textbf{", "").replace("}", ""))
            nums.append(float(m.group()) if m else None)
        if label and all(n is not None for n in nums):
            out[label] = tuple(nums)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--emit", action="store_true", help="print ready-to-paste tab:zipper body")
    a = ap.parse_args()
    if not os.path.exists(RESULTS):
        sys.exit(f"missing {RESULTS}: run eval.zipper_compare first")
    d = json.load(open(RESULTS))
    exp = expected(d)

    print(f"results: {d['zipper_completed']}/{d['paired_records']} records completed by ZIPPER")
    if a.show:
        for k, (n, z) in exp.items():
            print(f"  {k:24} WISP {n}   ZIPPER {z}")
        return
    if a.emit:
        # Emit the exact body lines. The winner of each row is bolded, except coverage, which is a
        # lower bound and is never bolded, and the CI rows keep the file-precision intervals.
        ci = {e["endpoint"]: e["ci95"] for e in d["endpoints"]}
        def cell(v, win, dec=3):
            s = f"{v:.{dec}f}"
            return f"\\textbf{{{s}}}" if win else s
        for k in ("1", "3", "5", "10"):
            n, z = exp[f"file-precision@{k}"]
            lo, hi = ci[f"file_precision@{k}"]
            print(f"file-precision@{k:<7} & {cell(n, n>z)} & {cell(z, z>n)} & "
                  f"[${lo:+.3f}$, ${hi:+.3f}$] \\\\")
        n, z = exp["class emission"]; lo, hi = ci["class_emission"]
        print(f"class emission          & {cell(n, n>z)} & {cell(z, z>n)} & [${lo:+.3f}$, ${hi:+.3f}$] \\\\")
        n, z = exp["coverage"]
        print(f"coverage ($\\ge$, see text) & {n:.3f} & {z:.3f} & \\\\")
        n, z = exp["findings/record"]
        print(f"findings/record         & {n:.1f} & {cell(z, z<n, 1)} & \\\\")
        n, z = exp["silent"]
        print(f"silent (of completed)   & {cell(n, n<z)} & {z:.3f} & \\\\")
        return

    bad = 0
    for path in TEX:
        rows = tex_rows(path)
        name = os.path.basename(path)
        if rows is None:
            print(f"[{name}] no tab:zipper found")
            continue
        for label, (en, ez) in exp.items():
            got = rows.get(label)
            if got is None:
                print(f"[{name}] MISSING row {label!r}")
                bad += 1
            elif abs(got[0] - en) > 1e-9 or abs(got[1] - ez) > 1e-9:
                print(f"[{name}] STALE {label:24} tex={got}  json=({en}, {ez})")
                bad += 1
    if bad:
        sys.exit(f"\n{bad} cell(s) stale. Refresh tab:zipper in both tex files, and re-check the "
                 f"prose figures too (0.449/0.409, +0.546, 71%, 1.4 vs 59.8, LFI/SQLi/XSS/RCE).")
    print("all tab:zipper cells match the results json")


if __name__ == "__main__":
    main()
