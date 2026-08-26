#!/usr/bin/env python3
"""Pool invariant: a table that prints BOTH a finding count and a record count must satisfy
findings <= K * records for the K its caption declares.

Why this exists. On 2026-08-20 a reviewer read the full-corpus geometric ladder, whose caption says
"Each row is one top-3 finding", saw 2202 findings for wp-taint-scan, and read the record count for
wp-taint-scan out of the prose two sections away, 684. 684 * 3 = 2052 < 2202, which is impossible
for a top-3 prefix. Neither number was wrong. They came from two different corpus scans of the same
1108 records:

  RUN A  revision-cns-v2/out/CORPUS1108_<TOOL>_CONTRACT_V3.json   (contract rescan, 2026-08-09/12)
         -> tab:ladder panel (a). wp-taint-scan: 2202 top-3 findings on 802 emitting records.
  RUN B  wisp-artifact/out/fill_20260714/atk_<tool>_1108.json     (pre-contract fill, 2026-07-15)
         + wisp-artifact/out/paired_20260717/loc_full/loc_*.json  (WISP, re-made 2026-08-12)
         -> tab:fullcorpus, tab:failaudit. wp-taint-scan: 684 emitting records, 1849 top-3.

WISP is byte-identical across the two (1077 records, 3141 top-3, 72951 findings), which is exactly
why the mismatch was invisible: the one row a reader checks first agrees.

The check is deliberately arithmetic and pointer-keyed. It does not read prose, it reads the JSON a
macro is bound to, so it survives a paragraph being trimmed and it cannot be satisfied by editing a
sentence.

    python3 check_pool_invariants.py              # both arms: --arm current then --arm fixed
    python3 check_pool_invariants.py --arm current   # must FAIL (proves the guard bites)
    python3 check_pool_invariants.py --arm fixed     # must PASS
    python3 check_pool_invariants.py --selftest      # the guard fires and does not false-fire
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import glob
import collections

# Derived, not hardcoded, so the check travels with the artifact bundle.
SYS_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
DATA = os.path.join(SYS_ROOT, "revision-cns-v2", "data")
ART = os.path.join(SYS_ROOT, "wisp-artifact")

TOOLS = ("wisp", "semgrep", "wpt", "progpilot")
PRETTY = {"wisp": "WISP", "semgrep": "Semgrep", "wpt": "wp-taint-scan", "progpilot": "Progpilot"}


# --------------------------------------------------------------------------- data readers
def _json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def pointer(doc, ptr):
    """Dotted pointer with [i] indexing, the same shape PAPER_MACROS_V3.manifest.json uses."""
    cur = doc
    for part in ptr.split("."):
        while part.endswith("]"):
            part, idx = part[:-1].split("[", 1)
            if part:
                cur = cur[part]
                part = ""
            cur = cur[int(idx)]
        if part:
            cur = cur[part]
    return cur


def jsonl_counts(path, topk=3):
    """(findings_in_topk_prefix, records_with_at_least_one, max_findings_per_record) per tool."""
    per = collections.Counter()
    recs = collections.defaultdict(set)
    allper = collections.defaultdict(collections.Counter)
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            t = o["tool"]
            key = (o["slug"], o.get("cve"))
            allper[t][key] += 1
            if o.get("rank", 10 ** 9) <= topk:
                per[t] += 1
                recs[t].add(key)
    return {t: (per[t], len(recs[t]), max(allper[t].values()) if allper[t] else 0)
            for t in allper}


def contract_scan_counts():
    """RUN A: per tool, (top3 pool, records emitting >=1, all findings, max per record, errors)."""
    out = {}
    for t in TOOLS:
        p = os.path.join(OUT, "CORPUS1108_%s_CONTRACT_V3.json" % t.upper())
        d = _json(p)
        top3 = emit = allf = mx = err = 0
        for r in d["details"]:
            b = r.get(t) or {}
            if b.get("err"):
                err += 1
            fs = b.get("findings") or []
            n = b.get("n", len(fs))
            allf += n
            mx = max(mx, n)
            if fs:
                emit += 1
            top3 += min(len(fs), 3)
        out[t] = dict(top3=top3, emitting=emit, all_findings=allf, max_per_record=mx,
                      errors=err, n_records=len(d["details"]))
    return out


def fill_run_counts():
    """RUN B: per tool, the same five quantities off the pre-contract fill + WISP loc shards."""
    src = {"semgrep": "out/fill_20260714/atk_sg_1108.json",
           "progpilot": "out/fill_20260714/atk_pp_1108.json",
           "wpt": "out/fill_20260714/atk_wpt_1108.json"}
    recs = {}
    for t, rel in src.items():
        recs[t] = _json(os.path.join(ART, rel))["details"]
    wisp = {}
    for f in sorted(glob.glob(os.path.join(ART, "out/paired_20260717/loc_full/loc_*.json"))):
        for d in _json(f)["details"]:
            wisp[d["slug"] + "|" + d["cve"]] = d
    recs["wisp"] = list(wisp.values())
    out = {}
    for t, sel in recs.items():
        err = [r for r in sel if r.get("err")]
        ok = [r for r in sel if not r.get("err")]
        out[t] = dict(top3=sum(min(r["findings"], 3) for r in sel),
                      emitting=sum(1 for r in ok if r["findings"] > 0),
                      all_findings=sum(r["findings"] for r in sel),
                      max_per_record=max(r["findings"] for r in sel),
                      errors=len(err), n_records=len(sel))
    return out


# --------------------------------------------------------------------------- the checks
class Check:
    """One table cell pair: a finding count, a record count, and the K the caption declares."""

    def __init__(self, table, row, findings, findings_src, records, records_src, k, note=""):
        self.table, self.row = table, row
        self.findings, self.findings_src = findings, findings_src
        self.records, self.records_src = records, records_src
        self.k, self.note = k, note

    def run(self):
        if self.k is None:
            ok = self.findings >= self.records
            cap = "uncapped"
            expr = "%d findings on %d records (no per-record cap declared)" % (
                self.findings, self.records)
        else:
            cap = self.k * self.records
            ok = self.findings <= cap
            expr = "%d <= %d x %d = %d" % (self.findings, self.k, self.records, cap)
        return ok, expr


def build(arm, A, B, ladder_kept, ladder_matched, mech, pop_corpus, pop_matched):
    """arm 'current' reproduces what the manuscript prints today; 'fixed' pairs each finding
    count with the record count from ITS OWN run and declares the real K."""
    C = []

    # ---- tab:ladder panel (a): "Each row is one top-3 finding", full corpus. RUN A findings.
    for t in ("wisp", "wpt", "semgrep", "progpilot"):
        f = pointer(ladder_kept, "per_tool.%s.n_findings" % t)
        if arm == "current":
            # what a reader does: take the record count from the prose / tab:fullcorpus row
            r = pointer(B["accounting_src"], "accounting.full_1108.with_findings.%s" % t)
            rsrc = ("FULLCORPUS_FAILURE_AS_MISS_V3.json"
                    " /accounting/full_1108/with_findings/%s  [RUN B]" % t)
        else:
            r = A[t]["emitting"]
            rsrc = "CORPUS1108_%s_CONTRACT_V3.json  records with >=1 finding  [RUN A]" % t.upper()
        C.append(Check("tab:ladder (a) full corpus", PRETTY[t], f,
                       "CORPUS_LADDER_KEPT_V3.json /per_tool/%s/n_findings  [RUN A]" % t,
                       r, rsrc, 3))

    # ---- tab:ladder panel (a) pooled caption: "1108 records, 8467 findings", 4 tools x top-3
    pooled = sum(pointer(ladder_kept, "per_tool.%s.n_findings" % t) for t in TOOLS)
    C.append(Check("tab:ladder (a) caption", "pooled over 4 tools", pooled,
                   "sum of CORPUS_LADDER_KEPT_V3.json /per_tool/*/n_findings",
                   pointer(ladder_kept, "records_scored") if "records_scored" in ladder_kept
                   else 1108, "CORPUS_LADDER_V3.json /records_scored", 3 * len(TOOLS),
                   note="4 tools x top-3 = 12 findings per record, not 3"))

    # ---- tab:ladder panel (b): matched 100, top-3
    for t in ("wisp", "wpt", "semgrep", "progpilot"):
        f = pointer(ladder_matched, "per_tool.%s.n_findings" % t)
        if arm == "current":
            r = pointer(ladder_matched, "n_records_matched")
            rsrc = "GEOMETRIC_LADDER_V3.json /n_records_matched"
        else:
            r = pointer(ladder_matched, "per_tool.%s.n_answered_records" % t)
            rsrc = "GEOMETRIC_LADDER_V3.json /per_tool/%s/n_answered_records" % t
        C.append(Check("tab:ladder (b) matched 100", PRETTY[t], f,
                       "GEOMETRIC_LADDER_V3.json /per_tool/%s/n_findings" % t, r, rsrc, 3))

    # ---- Supplement Table S13, per-mechanism precision. Scope printed as "the matched-100
    #      diagnostic", which a reader pairs with the ladder's top-3 slice. It is not top-3.
    f = pointer(mech, "all_mechanisms.findings")
    if arm == "current":
        C.append(Check("supp tab S13 mechanisms", "WISP all mechanisms", f,
                       "MECH_PRECISION_V3.json /all_mechanisms/findings",
                       pointer(ladder_matched, "n_records_matched"),
                       "GEOMETRIC_LADDER_V3.json /n_records_matched (top-3 scope assumed)", 3))
    else:
        C.append(Check("supp tab S13 mechanisms", "WISP all mechanisms", f,
                       "MECH_PRECISION_V3.json /all_mechanisms/findings",
                       pointer(ladder_matched, "per_tool.wisp.n_answered_records"),
                       "GEOMETRIC_LADDER_V3.json /per_tool/wisp/n_answered_records", None,
                       note="whole emitted pool, no rank cap; max %d findings on one record"
                            % pop_matched["wisp"][2]))

    # ---- tab:fullcorpus: "records with >=1 finding" row against the whole pool it scores
    #      ("all findings" precision denominator). Uncapped by construction.
    for t in ("wisp", "semgrep", "progpilot", "wpt"):
        C.append(Check("tab:fullcorpus", PRETTY[t], B[t]["all_findings"],
                       "fill_20260714/paired_20260717 sum of details[].findings  [RUN B]",
                       pointer(B["accounting_src"],
                               "accounting.full_1108.with_findings.%s" % t),
                       "FULLCORPUS_FAILURE_AS_MISS_V3.json /accounting/full_1108/"
                       "with_findings/%s  [RUN B]" % t,
                       3 if arm == "current" else None,
                       note="whole emitted pool, no rank cap" if arm == "fixed" else
                            "reader assumes the ladder's top-3 pool"))

    return C


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", choices=("current", "fixed", "both"), default="both")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    ladder_kept = _json(os.path.join(OUT, "CORPUS_LADDER_KEPT_V3.json"))
    ladder_v3 = _json(os.path.join(OUT, "CORPUS_LADDER_V3.json"))
    ladder_kept.setdefault("records_scored", ladder_v3.get("records_scored", 1108))
    ladder_matched = _json(os.path.join(OUT, "GEOMETRIC_LADDER_V3.json"))
    mech = _json(os.path.join(OUT, "MECH_PRECISION_V3.json"))
    A = contract_scan_counts()
    B = fill_run_counts()
    B["accounting_src"] = _json(os.path.join(OUT, "FULLCORPUS_FAILURE_AS_MISS_V3.json"))
    pop_corpus = jsonl_counts(os.path.join(OUT, "CORPUS_FINDING_POPULATION_V3.jsonl"))
    pop_matched = jsonl_counts(os.path.join(DATA, "FINDING_POPULATION_V3.jsonl"))

    if a.selftest:
        return selftest(A, B, ladder_kept, ladder_matched, mech, pop_corpus, pop_matched)

    arms = ("current", "fixed") if a.arm == "both" else (a.arm,)
    worst = 0
    for arm in arms:
        checks = build(arm, A, B, ladder_kept, ladder_matched, mech, pop_corpus, pop_matched)
        fails = 0
        print("=" * 100)
        print("ARM: %s   (%s)" % (arm.upper(),
              "what the manuscript prints today" if arm == "current"
              else "each finding count paired with the record count from its own run"))
        print("=" * 100)
        last = None
        for c in checks:
            ok, expr = c.run()
            if c.table != last:
                print("\n--- %s" % c.table)
                last = c.table
            print("  [%s] %-16s K=%-4s %-44s" % ("PASS" if ok else "FAIL", c.row,
                                                 c.k if c.k is not None else "-", expr))
            print("           findings <- %s" % c.findings_src)
            print("           records  <- %s" % c.records_src)
            if c.note:
                print("           note: %s" % c.note)
            if not ok:
                fails += 1
        print("\n%s: %d check(s), %d FAIL" % (arm.upper(), len(checks), fails))
        if arm == "current":
            if fails == 0:
                print("VERDICT: GUARD BROKEN. The 'current' arm reproduces a known live defect "
                      "and MUST fail. It did not.")
                worst = max(worst, 2)
            else:
                print("VERDICT: expected. The guard bites on the numbers the manuscript "
                      "prints today.")
        if arm == "fixed":
            if fails:
                print("VERDICT: the corrected pairing still violates the invariant. Investigate.")
                worst = max(worst, 1)
            else:
                print("VERDICT: expected. Every corrected pairing satisfies findings <= K x "
                      "records.")
        print()
    return worst


def selftest(A, B, ladder_kept, ladder_matched, mech, pop_corpus, pop_matched):
    """A guard nobody has seen fire is a guard nobody should trust."""
    bad = 0
    cur = build("current", A, B, ladder_kept, ladder_matched, mech, pop_corpus, pop_matched)
    fix = build("fixed", A, B, ladder_kept, ladder_matched, mech, pop_corpus, pop_matched)
    nfail_cur = sum(1 for c in cur if not c.run()[0])
    nfail_fix = sum(1 for c in fix if not c.run()[0])
    print("selftest 1  guard fires on the live defect        : %s (%d failing checks)"
          % ("PASS" if nfail_cur > 0 else "FAIL", nfail_cur))
    bad += nfail_cur == 0
    print("selftest 2  guard is silent once each count is    : %s (%d failing checks)"
          % ("PASS" if nfail_fix == 0 else "FAIL", nfail_fix))
    bad += nfail_fix != 0
    # 3. an injected off-by-one must be caught
    probe = Check("probe", "synthetic", 3 * 802 + 1, "synthetic", 802, "synthetic", 3)
    print("selftest 3  catches a deliberate +1 over the cap  : %s"
          % ("PASS" if not probe.run()[0] else "FAIL"))
    bad += probe.run()[0]
    probe2 = Check("probe", "synthetic", 3 * 802, "synthetic", 802, "synthetic", 3)
    print("selftest 4  does not fire on an exactly-full pool : %s"
          % ("PASS" if probe2.run()[0] else "FAIL"))
    bad += not probe2.run()[0]
    # 5. the two runs really are different data, which is the whole finding
    diff = [t for t in TOOLS if A[t]["emitting"] != B[t]["emitting"]]
    print("selftest 5  RUN A and RUN B disagree on %d of 4    : %s (%s)"
          % (len(diff), "PASS" if diff else "FAIL", ", ".join(diff) or "none"))
    bad += not diff
    print("\nselftest: %s" % ("PASS" if bad == 0 else "FAIL"))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
