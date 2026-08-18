#!/usr/bin/env python3
"""The access-control sub-class split, regenerated from the corpus and the corpus scan.

`tab:authsplit` was the one supplement table with no source anywhere: its five rows were
hand-written and no JSON in the tree produced them. The grouping is recoverable, though - the
advisory's raw Patchstack type is in the corpus - so this reconstructs it explicitly rather
than leaving five numbers in the paper that nothing can check.

The grouping below is the unique assignment consistent with the published row counts
(282 + 19 + 21 + 19 + 14 = 355). It is written out so a reader can disagree with a placement
instead of guessing what it was.

Emission is computed under the contract failure policy: a record whose analysis did not
converge earns nothing, exactly as in the main text. The published table predates that policy,
so its rates were higher.

    python3 -m eval.auth_split_v3
"""
from __future__ import annotations
import os, sys, json, glob, argparse
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

from eval.datasets.patchstack import load_rows

WISP_GLOB = "out/paired_20260717/loc_full/loc_*.json"
from eval.wisp_contract import census_path
CENSUS = census_path()
OUT_JSON = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "AUTH_SPLIT_V3.json")
OUT_TEX = os.path.join(SYS_ROOT, "2026-07-07", "latex", "AUTHSPLIT_TABLE.tex")
# The per-class figure read a 2026-07-13 scan and a 2026-07-17 interval file while the paragraph
# printed beside it came from the join below, so a reader saw access control at 0.90 in the figure
# and 0.66 in the sentence above it. The same join now emits the figure's data as well, on the
# contract basis, with the intervals recomputed on that basis rather than carried over.
OUT_PERCLASS = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "PERCLASS_CONTRACT_V3.json")
OUT_MISS = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "MISS_ANALYSIS_V3.json")
PERCLASS_B = 10000
PERCLASS_SEED = 20260730

# raw Patchstack type -> reported sub-class. Every auth type in the corpus appears here; an
# unmapped one is an error rather than a silent "other", because a silent bucket is how a
# taxonomy quietly stops meaning anything.
GROUPS = [
    ("Missing authorization", ["Missing Authorization", ": Missing Authorization"]),
    ("Privilege escalation", ["Incorrect Privilege Assignment", "Privilege Escalation"]),
    ("Authorization bypass / IDOR", ["Authorization Bypass Through User-Controlled Key",
                                     "Insecure Direct Object References (IDOR)"]),
    ("Authentication bypass", ["Authentication Bypass Using an Alternate Path or Channel",
                               "Authentication Bypass by Spoofing", "Broken Authentication",
                               "Weak Authentication"]),
    ("Broken access control (other)", ["Broken Access Control", "Bypass Vulnerability"]),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-json", default=OUT_JSON)
    ap.add_argument("--out-tex", default=OUT_TEX)
    a = ap.parse_args()

    auth = [r for r in load_rows() if r["cls"] == "auth"]
    mapping = {t: g for g, ts in GROUPS for t in ts}
    unmapped = sorted({r["type"] for r in auth if r["type"] not in mapping})
    if unmapped:
        sys.exit("unmapped auth sub-types (add them to GROUPS, do not bucket silently): "
                 + ", ".join(repr(u) for u in unmapped))

    hit, nfind = {}, {}
    for f in sorted(glob.glob(os.path.join(ROOT, WISP_GLOB))):
        for d in json.load(open(f))["details"]:
            k = d["slug"] + "|" + d["cve"]
            hit[k] = bool(d.get("hit"))
            nfind[k] = int(d.get("findings") or 0)
    def _nonconv(path: str) -> set:
        if not os.path.isfile(path):
            return set()
        return {r["slug"] + "|" + r["cve"] for r in json.load(open(path))["records"]
                if not r.get("wisp_err") and r.get("wisp_converged") is False}

    nonconv = _nonconv(CENSUS)
    # The baseline count is carried alongside because the ordering inside this class turned on it.
    # Non-convergence was concentrated in the missing-authorization records, so under the baseline
    # engine the dominant sub-class read as the weakest, and the paragraph explained that as a
    # property of the weakness. It was a property of the analysis not finishing.
    nonconv_baseline = _nonconv(census_path(True))

    rows, tot_n, tot_h = [], 0, 0
    for label, _ in GROUPS:
        keys = [r["slug"] + "|" + r["cve"] for r in auth if mapping[r["type"]] == label]
        n = len(keys)
        h = sum(1 for k in keys if hit.get(k) and k not in nonconv)
        rows.append({"sub_class": label, "records": n, "hits": h,
                     "emission": round(h / n, 4) if n else None})
        tot_n += n
        tot_h += h

    res = {
        "schema_version": "auth-split-v3",
        "note": "class emission of the auth class, split by the advisory's raw Patchstack type, "
                "under the contract failure policy (a non-converged record earns nothing)",
        "n_auth_records": tot_n,
        "n_non_converged_in_auth": sum(1 for r in auth
                                       if r["slug"] + "|" + r["cve"] in nonconv),
        "n_non_converged_in_auth_baseline": sum(1 for r in auth
                                                if r["slug"] + "|" + r["cve"] in nonconv_baseline),
        "census": os.path.basename(CENSUS),
        "census_baseline": os.path.basename(census_path(True)),
        "grouping": {g: ts for g, ts in GROUPS},
        "raw_type_counts": dict(Counter(r["type"] for r in auth)),
        "rows": rows,
        "all_auth": {"records": tot_n, "hits": tot_h,
                     "emission": round(tot_h / tot_n, 4) if tot_n else None},
    }
    json.dump(res, open(a.out_json, "w"), indent=1, sort_keys=True)

    L = ["% Auto-generated by eval/auth_split_v3.py. Do not edit by hand."]
    top = max(rows, key=lambda r: r["emission"] or 0)
    for r in rows:
        v = "%.3f" % r["emission"]
        if r is top:
            v = "\\textbf{%s}" % v
        L.append("%s & %d & %s \\\\" % (r["sub_class"], r["records"], v))
    L.append(r"\midrule")
    L.append("All \\code{auth} & %d & %.3f \\\\" % (tot_n, res["all_auth"]["emission"]))
    L.append(r"\bottomrule")
    open(a.out_tex, "w", encoding="utf-8").write("\n".join(L) + "\n")

    print(f"{tot_n} auth records, {res['n_non_converged_in_auth']} non-converged")
    for r in rows:
        print(f"  {r['sub_class']:32} {r['records']:>4}  {r['emission']:.3f}")
    print(f"  {'All auth':32} {tot_n:>4}  {res['all_auth']['emission']:.3f}")
    # macro-able figures for the prose that quotes this table
    mac = os.path.join(SYS_ROOT, "2026-07-07", "latex", "AUTHSPLIT_MACROS.tex")
    top = max(rows, key=lambda r: r["emission"] or 0)
    ma = {"AuthMissingN": rows[0]["records"], "AuthMissingEmis": "%.3f" % rows[0]["emission"],
          "AuthAllN": tot_n, "AuthAllEmis": "%.3f" % res["all_auth"]["emission"],
          "AuthTopName": top["sub_class"].lower(), "AuthTopEmis": "%.3f" % top["emission"],
          "AuthTopN": top["records"],
          "AuthIdorEmis": "%.3f" % rows[2]["emission"], "AuthIdorN": rows[2]["records"],
          "AuthOtherEmis": "%.3f" % rows[4]["emission"], "AuthOtherN": rows[4]["records"],
          # How many records the failure policy withholds inside this class, under each engine. The
          # ordering of the sub-classes turned on this, so the paragraph has to be able to say it.
          "AuthNonConv": res["n_non_converged_in_auth"],
          "AuthNonConvBaseline": res["n_non_converged_in_auth_baseline"],
          # True while the dominant sub-class is also the strongest, which is what the shipped
          # engine reports and the baseline engine did not. The prose reads differently either way,
          # so it is generated rather than assumed.
          "AuthTopIsDominant": "yes" if top["sub_class"] == rows[0]["sub_class"] else "no"}
    with open(mac, "w", encoding="utf-8") as fh:
        fh.write("% Auto-generated by eval/auth_split_v3.py. Do not edit by hand.\n")
        for k, v in ma.items():
            fh.write("\\newcommand{\\%s}{%s}\n" % (k, v))
    print("wrote", mac)
    print("wrote", a.out_json)
    # The RQ2 per-class list quotes the same quantity for every class, so it is generated from
    # the same join rather than kept as a second hand-written copy that drifts.
    per = {}
    for r in load_rows():
        k = r["slug"] + "|" + r["cve"]
        e = per.setdefault(r["cls"], [0, 0])
        e[1] += 1
        if hit.get(k) and k not in nonconv:
            e[0] += 1
    NAMES = {"auth": "access control", "csrf": "CSRF", "deserial": "object injection",
             "lfi": "LFI", "ssrf": "SSRF", "sqli": "SQLi", "upload": "upload",
             "xss": "XSS", "rce": "RCE", "other": "\\code{other}"}
    order = sorted(per, key=lambda c: -per[c][0] / per[c][1])
    parts = ["%s %.3f" % (NAMES.get(c, c), per[c][0] / per[c][1]) for c in order]
    wp = [c for c in ("auth", "csrf", "deserial") if c in per]
    gen = [c for c in per if c not in wp]
    wh, wn = sum(per[c][0] for c in wp), sum(per[c][1] for c in wp)
    gh, gn = sum(per[c][0] for c in gen), sum(per[c][1] for c in gen)
    pc = os.path.join(SYS_ROOT, "2026-07-07", "latex", "PERCLASS_FRAGMENT.tex")
    with open(pc, "w", encoding="utf-8") as fh:
        fh.write("% Auto-generated by eval/auth_split_v3.py. Do not edit by hand.\n")
        fh.write(", ".join(parts[:-1]) + ", and " + parts[-1] + ".\n")
    pm = os.path.join(SYS_ROOT, "2026-07-07", "latex", "PERCLASS_MACROS.tex")
    with open(pm, "w", encoding="utf-8") as fh:
        fh.write("% Auto-generated by eval/auth_split_v3.py. Do not edit by hand.\n")
        fh.write("\\newcommand{\\PcWpEmis}{%.3f}\n" % (wh / wn))
        fh.write("\\newcommand{\\PcWpN}{%d}\n" % wn)
        fh.write("\\newcommand{\\PcWpHits}{%d}\n" % wh)
        fh.write("\\newcommand{\\PcGenEmis}{%.3f}\n" % (gh / gn))
        fh.write("\\newcommand{\\PcGenN}{%d}\n" % gn)
        fh.write("\\newcommand{\\PcGenHits}{%d}\n" % gh)
    print("wrote", pc)
    print("wrote", pm)
    print("wrote", a.out_tex)

    # Same join again, this time per record so the figure can be drawn from it with its own
    # plugin-clustered intervals. boot_rate is the estimator every other clustered interval in the
    # revision uses, so the figure's error bars and the paper's are the same construction.
    from eval.analyze_v3 import boot_rate
    units = []
    for r in load_rows():
        k = r["slug"] + "|" + r["cve"]
        units.append({"slug": r["slug"], "cls": r["cls"],
                      "hit": bool(hit.get(k)) and k not in nonconv})
    per_ci = {}
    for cls in sorted(per):
        u = [x for x in units if x["cls"] == cls]
        b = boot_rate(u, lambda x: x["hit"], PERCLASS_B, seed=PERCLASS_SEED)
        per_ci[cls] = {"hits": b["count"], "n": b["n"], "rate": b["rate"],
                       "ci95": b["ci95"], "n_slugs": len({x["slug"] for x in u})}
    json.dump({"schema_version": "perclass-contract-v3",
               "script": "eval/auth_split_v3.py",
               "basis": ("contract failure policy: a record whose analysis did not converge "
                         "earns nothing, the same basis as the per-class sentence in the text"),
               "wisp_source": WISP_GLOB,
               "census": os.path.relpath(CENSUS, SYS_ROOT),
               "bootstrap_replicates": PERCLASS_B,
               "bootstrap_unit": "plugin_slug",
               "seed": PERCLASS_SEED,
               "per_class": per_ci},
              open(OUT_PERCLASS, "w"), indent=1, sort_keys=True)
    print("wrote", OUT_PERCLASS)

    # The miss-analysis figure had its six bar heights typed into the plotting code, where no
    # check in this repository could see them. They are all correct, which is luck rather than
    # process, so the same join emits them. This one stays on the non-convergence-ignored basis
    # because both panels decompose a single run rather than state a level, and the axis and the
    # caption say so.
    kept = [(r, hit.get(r["slug"] + "|" + r["cve"], False),
             nfind.get(r["slug"] + "|" + r["cve"], 0)) for r in load_rows()]
    miss = [(r, h, n) for r, h, n in kept if not h]
    WP = ("auth", "csrf", "deserial")

    def subset(pred):
        s = [h for r, h, _ in kept if pred(r)]
        return {"hits": sum(1 for h in s if h), "n": len(s),
                "emission": round(sum(1 for h in s if h) / len(s), 4) if s else None}

    json.dump({"schema_version": "miss-analysis-v3",
               "script": "eval/auth_split_v3.py",
               "basis": ("non-convergence ignored, because both panels decompose one run rather "
                         "than state a level; the contract headline is lower"),
               "wisp_source": WISP_GLOB,
               "misses": {"total": len(miss),
                          "wrong_class_engine_active": sum(1 for _, _, n in miss if n > 0),
                          "blind_zero_findings": sum(1 for _, _, n in miss if n == 0)},
               "emission": {
                   "all_classes": subset(lambda r: True),
                   "in_scope_no_other": subset(lambda r: r["cls"] != "other"),
                   "wordpress_specific": subset(lambda r: r["cls"] in WP),
                   "generic_taint": subset(lambda r: r["cls"] not in WP and r["cls"] != "other")}},
              open(OUT_MISS, "w"), indent=1, sort_keys=True)
    print("wrote", OUT_MISS)


if __name__ == "__main__":
    main()
