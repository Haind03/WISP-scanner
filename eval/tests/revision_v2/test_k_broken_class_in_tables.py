"""K. The 2026-07-17 broken-class bug is still in the shipped class-and-file numbers.

The matched-100 baseline run was fed a manifest with no `vuln_type`, so every record was
scored with `cls = "other"` and every class-dependent metric asked "did the tool report
other?". The bug was found on 2026-07-17 and a corrected run was produced
(`final/results/matched_100_baselines_CLASSFIXED.json`). The class-emission prose was
updated to the corrected values. The class-and-file cells were not.

Three independent sources agree on the corrected values and disagree with the shipped
table:

    class-and-file@K      contract population   CLASSFIXED   broken run   printed in tab:localize
    semgrep  @1/3/5/10    .090 .100 .110 .120   .09 .10 .11 .12   .05 .07 .10 .12   .05 .07 .10 .12
    wpt      @1/3/5/10    .150 .190 .210 .250   .14 .18 .20 .24   .02 .03 .03 .05   .02 .03 .03 .05

The consequence is not cosmetic and it runs in WISP's favour:

  * `tab:localize`'s caption says "no tool exceeds 0.10 there". wp-taint-scan reaches 0.15.
  * The Results text says WISP "leads the other WordPress-aware tool at every cutoff, 0.10
    against 0.02 at K=1". Corrected, that is 0.10 against 0.15: WISP LOSES at K=1.
  * `tab:clusterp` prints class-and-file@1 versus wp-taint-scan as w=8, l=0. The corrected
    discordant counts are w=8, l=13.

These tests assert the post-fix invariant, so they FAIL while the stale cells are shipped.
"""
from __future__ import annotations
import json, os, re, collections
from . import _common
from ._common import SYS_ROOT

MAIN = os.path.join(SYS_ROOT, "2026-07-07", "latex", "WISP-paper-CnS-elsarticle.tex")
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
SAMPLE = os.path.join(SYS_ROOT, "revision-cns-v2", "baseline_v3", "matched100.sample")
BROKEN = os.path.join(SYS_ROOT, "final", "supplementary-data", "reproduce", "data",
                      "matched_100_baselines_final.json")
KS = (1, 3, 5, 10)


def _contract_class_and_file():
    """class-and-file@K per tool, from the patch_geometry-scored contract population."""
    keys = [l.strip() for l in open(SAMPLE) if l.strip()]
    by = collections.defaultdict(lambda: collections.defaultdict(list))
    for line in open(POP):
        g = json.loads(line)
        by[g["tool"]][g["slug"] + "|" + g["cve"]].append(g)
    out = {}
    for tool in ("wisp", "semgrep", "wpt", "progpilot"):
        if tool not in by:
            continue
        out[tool] = {}
        for K in KS:
            hits = sum(1 for k in keys
                       if any(f["in_patched_file"] and f["class_match"]
                              for f in by[tool].get(k, []) if f["rank"] <= K))
            out[tool][K] = hits / len(keys)
    return out


def _printed_class_and_file():
    """What tab:localize actually prints.

    The table is now macro-driven, so "printed" means the value the macro expands to. Reading
    the macro file rather than the table body is the point: a literal in the table would be a
    transcription and could drift again, and this test should fail loudly if one reappears.
    """
    macros = os.path.join(SYS_ROOT, "2026-07-07", "latex", "PAPER_MACROS_V3.tex")
    text = open(macros, encoding="utf-8").read()
    vals = dict(re.findall(r"\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}", text))
    kw = {1: "One", 3: "Three", 5: "Five", 10: "Ten"}
    name = {"semgrep": "Semgrep", "wpt": "Wpt", "wisp": "Wisp", "progpilot": "Progpilot"}
    out = {}
    for K in KS:
        row = {}
        for tool, tn in name.items():
            v = vals.get(f"Loc{tn}Cf{kw[K]}")
            if v is not None:
                row[tool] = float(v)
        if row:
            out[K] = row

    # a literal decimal in the class-and-file half of the table body means someone
    # transcribed a number back in
    t = open(MAIN, encoding="utf-8").read()
    i = t.find("\\label{tab:localize}")
    body = t[i:t.index("\\end{tabular}", i)] if i > 0 else ""
    literals = [ln.strip() for ln in body.splitlines()
                if re.match(r"\s*(1|3|5|10)\s*&", ln) and re.search(r"\d+\.\d+", ln)]
    assert not literals, ("tab:localize has hard-coded decimals again, so it can drift from "
                          "the data:\n  " + "\n  ".join(literals[:4]))
    return out


def test_class_and_file_cells_are_not_the_broken_class_run():
    contract = _contract_class_and_file()
    printed = _printed_class_and_file()
    assert printed, "could not parse tab:localize"

    stale = []
    for K in KS:
        for tool in ("semgrep", "wpt"):
            if tool not in contract or K not in printed:
                continue
            got, want = printed[K][tool], contract[tool][K]
            if abs(got - want) > 0.011:            # one record on a 100-record sample
                stale.append(f"class-and-file@{K} {tool}: printed {got:.2f}, "
                             f"contract population {want:.3f}")
    assert not stale, (
        "tab:localize still prints the 2026-07-17 broken-class values for the baselines:\n  "
        + "\n  ".join(stale)
        + "\n(the corrected run final/results/matched_100_baselines_CLASSFIXED.json agrees "
          "with the contract population, not with the printed cells)")


def test_no_claim_rests_on_the_broken_class_numbers():
    """The two sentences the stale cells support must not survive the correction."""
    t = open(MAIN, encoding="utf-8").read()
    contract = _contract_class_and_file()
    wpt1 = contract.get("wpt", {}).get(1)
    offending = []
    if wpt1 is not None and wpt1 > 0.10 and "no\ntool exceeds 0.10 there" in t.replace("  ", " "):
        offending.append("tab:localize caption claims no tool exceeds 0.10 at class-and-file@1, "
                         f"but wp-taint-scan reaches {wpt1:.2f}")
    if "0.10\nagainst 0.02 at $K{=}1$" in t or "0.10 against 0.02 at $K{=}1$" in t:
        offending.append("Results claims WISP 0.10 against wp-taint-scan 0.02 at class-and-file@1; "
                         f"the corrected value is {wpt1:.2f}, so WISP does not lead there")
    assert not offending, "claims still resting on the broken-class cells:\n  " + "\n  ".join(offending)


def test_the_broken_run_is_not_read_by_any_current_analysis():
    """Nothing in the current pipeline may take metrics from the cls='other' run."""
    if not os.path.isfile(BROKEN):
        return
    d = json.load(open(BROKEN))
    classes = {r.get("cls") for r in d["details"]}
    assert classes == {"other"}, f"expected the broken run to carry cls='other'; got {classes}"
    # It is still a legitimate source of RAW tool findings; only its metrics are poisoned.
    assert d["summary"]["wpt"]["class_emission"] == 0.15, (
        "the broken run's fingerprint changed; re-verify which file the tables read")
