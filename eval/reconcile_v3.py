#!/usr/bin/env python3
"""Reconciliation aid for the tier-2 root-cause disagreements. It generates NO labels.

The two annotators agreed almost perfectly on the class axis but only fairly on root_cause_relation,
so a block of packets carries two different root-cause judgments. A single same-defect headline should
not be fixed until those are reconciled. This tool exports exactly the disputed packets to a CSV, and
folds a human-filled reconciliation back into a hashed JSON. It stays blinded: the worksheet never
shows the tool. A human types every final judgment.

    python3 -m eval.reconcile_v3 export
    python3 -m eval.reconcile_v3 import --csv <path>
    python3 -m eval.reconcile_v3 status
"""
from __future__ import annotations
import os, sys, csv, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C

RECON = os.path.join(C.TIER2_DIR, "reconciliation.json")
WORKSHEET = os.path.join(C.TIER2_DIR, "reconciliation.csv")
COLS = ["packet_id", "slug", "cve", "advisory_class", "finding_file", "finding_line", "packet_md",
        "A_root_cause", "B_root_cause", "A_reason", "B_reason",
        "final_root_cause_relation", "final_reason_code", "reconcile_notes"]


def _disputed():
    A = C.read_json(os.path.join(C.TIER2_DIR, "reviewer_A_findings.json"))["payload"]["labels"]
    B = C.read_json(os.path.join(C.TIER2_DIR, "reviewer_B_findings.json"))["payload"]["labels"]
    packets = {p["packet_id"]: p for p in
               C.read_json(os.path.join(C.TIER2_DIR, "PACKETS.json"))["payload"]["packets"]}
    rows = []
    for pid in sorted(A):
        if A[pid]["root_cause_relation"] != B[pid]["root_cause_relation"]:
            p = packets.get(pid, {})
            rows.append({"packet_id": pid, "slug": p.get("slug", ""), "cve": p.get("cve", ""),
                         "advisory_class": p.get("advisory_class", ""),
                         "finding_file": p.get("finding_file", ""), "finding_line": p.get("finding_line", ""),
                         "packet_md": f"packets/{pid}.md",
                         "A_root_cause": A[pid]["root_cause_relation"],
                         "B_root_cause": B[pid]["root_cause_relation"],
                         "A_reason": A[pid]["reason_code"], "B_reason": B[pid]["reason_code"],
                         "final_root_cause_relation": "", "final_reason_code": "", "reconcile_notes": ""})
    return rows


def export():
    rows = _disputed()
    with open(WORKSHEET, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader(); w.writerows(rows)
    print(f"exported {len(rows)} disputed packets -> {WORKSHEET}")
    print("  the worksheet is blinded (no tool). Reopen tier2/packets/<packet_id>.md, discuss, and")
    print("  fill final_root_cause_relation (and final_reason_code) from the rubric's allowed sets:")
    print(f"    final_root_cause_relation: {C.ROOT_CAUSE_RELATION}")
    print(f"    final_reason_code: {C.REASON_CODE}")
    print("  then: python3 -m eval.reconcile_v3 import --csv " + WORKSHEET)


def import_csv(path, allow_collapse=False):
    disputed = {r["packet_id"] for r in _disputed()}
    rows = list(csv.DictReader(open(path, encoding="utf-8-sig")))
    out, bad_key, bad_val, missing = {}, [], [], 0
    for r in rows:
        pid = (r.get("packet_id") or "").strip()
        if pid not in disputed:
            bad_key.append(pid or "(blank)")
            continue
        fr = (r.get("final_root_cause_relation") or "").strip()
        fc = (r.get("final_reason_code") or "").strip()
        if not fr:
            missing += 1
            continue
        if fr not in C.ROOT_CAUSE_RELATION:
            bad_val.append(f"{pid}:final_root_cause_relation={fr}"); continue
        if fc and fc not in C.REASON_CODE:
            bad_val.append(f"{pid}:final_reason_code={fc}"); continue
        out[pid] = {"final_root_cause_relation": fr, "final_reason_code": fc,
                    "notes": (r.get("reconcile_notes") or "").strip()}
    if bad_key:
        print(f"ERROR: {len(bad_key)} row(s) are not disputed packets: {bad_key[:5]}")
    if bad_val:
        print(f"ERROR: {len(bad_val)} value(s) outside the allowed set: {bad_val[:5]}")
    if bad_key or bad_val:
        sys.exit("no changes written; fix the CSV and re-run import")
    # A reconciliation session that lands on one value for every row it touches, or that adopts
    # one annotator's answer on every row, has stopped being two people arguing and become a rule
    # applied. That is the collapse the protocol names one layer down from the cross-class guard,
    # and it is invisible in the per-axis kappa because kappa is computed before reconciliation.
    if out:
        from collections import Counter
        vals = Counter(v["final_root_cause_relation"] for v in out.values())
        top, ntop = vals.most_common(1)[0]
        A = {r["packet_id"]: r.get("A_root_cause") for r in _disputed()}
        B = {r["packet_id"]: r.get("B_root_cause") for r in _disputed()}
        to_a = sum(1 for pid, v in out.items() if v["final_root_cause_relation"] == A.get(pid))
        to_b = sum(1 for pid, v in out.items() if v["final_root_cause_relation"] == B.get(pid))
        hard = []
        if len(out) >= 10 and ntop == len(out):
            hard.append(f"every one of the {len(out)} reconciled rows came back {top!r}")
        if len(out) >= 10 and max(to_a, to_b) == len(out):
            who = "A" if to_a == len(out) else "B"
            hard.append(f"every one of the {len(out)} reconciled rows adopted annotator {who}'s answer")
        print(f"  reconciled value spread: {dict(vals)}")
        print(f"  adopted A on {to_a}, adopted B on {to_b}, of {len(out)} resolved")
        if hard and not allow_collapse:
            for h in hard:
                print(f"  COLLAPSE: {h}")
            sys.exit("refusing to write a reconciliation with no spread; a session that produces "
                     "one value on every row is a rule, not an adjudication. Record what rule was "
                     "applied, check it is not computed from the patch geometry the study is "
                     "testing, and re-run with --allow-collapse only if it survives that check.")
    C.write_json(RECON, C.envelope("tier2_reconciliation",
                                   {"n_disputed": len(disputed), "n_resolved": len(out),
                                    "resolutions": out}))
    print(f"wrote {len(out)}/{len(disputed)} reconciled labels -> {RECON}")
    if missing:
        print(f"  {missing} disputed packet(s) still blank; fill them and re-import to complete")
    print("  then re-run: python3 -m eval.analyze_v3  (it will add same_defect_rate_reconciled)")


def status():
    disputed = _disputed()
    print(f"disputed root-cause packets: {len(disputed)}")
    if os.path.isfile(RECON):
        r = C.read_json(RECON)["payload"]
        print(f"reconciliation.json: {r['n_resolved']}/{r['n_disputed']} resolved")
    else:
        print("reconciliation.json: not created yet")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("export")
    im = sub.add_parser("import"); im.add_argument("--csv", default=WORKSHEET)
    im.add_argument("--allow-collapse", action="store_true",
                    help="write anyway; only for a collapse shown not to derive from patch geometry")
    sub.add_parser("status")
    a = ap.parse_args()
    {"export": lambda: export(), "import": lambda: import_csv(a.csv, getattr(a, "allow_collapse", False)), "status": lambda: status()}[a.cmd]()


if __name__ == "__main__":
    main()
