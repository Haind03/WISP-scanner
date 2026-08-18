#!/usr/bin/env python3
"""Score the adjudication v3 sheets AFTER humans have labeled them. Generates NO labels.

This program refuses to invent anything. If the reviewer sheets are empty it STOPS: a rate computed
from labels a program wrote would be a fabricated ground truth. It joins reviewer A and reviewer B by
packet_id (never by row position), aborts on any duplicate packet_id, and computes, on the five
separate axes, inter-annotator agreement and Cohen's kappa. The SAME_DEFECT rate on the
root_cause_relation axis is the human bottom rung the paper reports.

The sealed blinding key is opened only when BOTH tiers are locked (tier1/LOCK.json and
tier2/LOCK.json present); only then are per-tool rates produced. Without the locks, only the
key-free inter-annotator agreement is computed, and per-tool attribution is withheld.

Weighting is Horvitz-Thompson (weight = 1 / inclusion_probability); for the census every weight is 1,
so weighted and unweighted rates coincide, but a future probability sample scores correctly too.

    python3 -m eval.score_adjudication_v3
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C


def _load_sheet(path):
    env = C.read_json(path)
    if C.content_hash(env["payload"]) != env.get("content_hash"):
        sys.exit(f"ABORT: content hash mismatch on {path} (sheet edited without rehashing)")
    return env["payload"]


def _labeled(cell: dict, axes) -> bool:
    return any((cell.get(ax) or "").strip() for ax in axes)


def _cohen_kappa(pairs, categories):
    """Cohen's kappa for a list of (a_label, b_label) over a fixed category set."""
    n = len(pairs)
    if n == 0:
        return None
    po = sum(1 for a, b in pairs if a == b) / n
    pa = defaultdict(int)
    pb = defaultdict(int)
    for a, b in pairs:
        pa[a] += 1
        pb[b] += 1
    pe = sum((pa[c] / n) * (pb[c] / n) for c in categories)
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def _rate(rows, weight, predicate):
    """Weighted fraction of rows satisfying predicate (Horvitz-Thompson)."""
    num = sum(weight[pid] for pid, *_ in rows if predicate(pid))
    den = sum(weight[pid] for pid, *_ in rows)
    return (num / den) if den else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow-unlocked", action="store_true",
                    help="compute key-free agreement even if the lock files are absent")
    a = ap.parse_args()

    a_path = os.path.join(C.TIER2_DIR, "reviewer_A_findings.json")
    b_path = os.path.join(C.TIER2_DIR, "reviewer_B_findings.json")
    packets_path = os.path.join(C.TIER2_DIR, "PACKETS.json")
    if not (os.path.isfile(a_path) and os.path.isfile(b_path) and os.path.isfile(packets_path)):
        sys.exit("ABORT: Tier-2 packets/sheets not built. Run build_adjudication_v3 first.")

    A, B = _load_sheet(a_path), _load_sheet(b_path)
    axes = A["axes"]
    la, lb = A["labels"], B["labels"]

    # join by packet_id, abort on any duplicate within a sheet (json keys are unique, so also verify
    # the packet set matches between sheets)
    if set(la) != set(lb):
        sys.exit("ABORT: reviewer A and B cover different packet_id sets; cannot join by packet_id")
    packet_ids = sorted(la)

    # REFUSE to fabricate: if no human labels exist, stop here with no rates.
    labeled_ids = [pid for pid in packet_ids if _labeled(la[pid], axes) and _labeled(lb[pid], axes)]
    any_labeled = any(_labeled(la[pid], axes) or _labeled(lb[pid], axes) for pid in packet_ids)
    if not any_labeled:
        print("STOP: the reviewer sheets are EMPTY. No human labels are present.")
        print("      A program must not synthesize adjudication labels. Have the two annotators fill")
        print("      reviewer_A_findings.json and reviewer_B_findings.json, then re-run this scorer.")
        return 2
    print(f"labeled by both reviewers: {len(labeled_ids)}/{len(packet_ids)} packets")

    # per-axis agreement + Cohen's kappa (key-free; needs no tool identity)
    per_axis = {}
    for ax in axes:
        pairs = [(la[pid][ax].strip(), lb[pid][ax].strip()) for pid in labeled_ids
                 if la[pid].get(ax, "").strip() and lb[pid].get(ax, "").strip()]
        cats = sorted(set(C.TIER2_LABEL_DOMAINS.get(ax, [])) | {a_ for a_, _ in pairs} | {b_ for _, b_ in pairs})
        agree = (sum(1 for x, y in pairs if x == y) / len(pairs)) if pairs else None
        per_axis[ax] = {"n": len(pairs),
                        "agreement": round(agree, 4) if agree is not None else None,
                        "cohen_kappa": (round(_cohen_kappa(pairs, cats), 4)
                                        if pairs else None)}

    report = {"n_packets": len(packet_ids), "n_labeled_both": len(labeled_ids),
              "inter_annotator": per_axis, "per_tool": None, "note": ""}

    # per-tool rates require BOTH locks; only then open the sealed key
    t1lock = os.path.isfile(os.path.join(C.TIER1_DIR, "LOCK.json"))
    t2lock = os.path.isfile(os.path.join(C.TIER2_DIR, "LOCK.json"))
    keyp = os.path.join(C.TIER2_DIR, "BLINDING_KEY.json")
    if (t1lock and t2lock) or a.allow_unlocked:
        if not (t1lock and t2lock):
            report["note"] = "per-tool rates computed with --allow-unlocked; NOT a locked result"
        kmap = C.read_json(keyp)["payload"]["map"]
        packets = {p["packet_id"]: p for p in C.read_json(packets_path)["payload"]["packets"]}
        weight = {pid: 1.0 / (packets[pid].get("inclusion_probability") or 1.0) for pid in packet_ids}

        # agreed same-defect: both reviewers say SAME_DEFECT on root_cause_relation
        agreed_same = {pid for pid in labeled_ids
                       if la[pid].get("root_cause_relation", "").strip() == "SAME_DEFECT"
                       and lb[pid].get("root_cause_relation", "").strip() == "SAME_DEFECT"}
        agreed_class = {pid for pid in labeled_ids
                        if la[pid].get("class_relation", "").strip() == "MATCH"
                        and lb[pid].get("class_relation", "").strip() == "MATCH"}

        per_tool = defaultdict(lambda: {"n": 0, "labeled": 0})
        rows_by_tool = defaultdict(list)
        for pid in labeled_ids:
            tool = kmap[pid]["tool"]
            rows_by_tool[tool].append((pid,))
        for tool, rows in rows_by_tool.items():
            per_tool[tool] = {
                "n_labeled": len(rows),
                "same_defect_rate": round(_rate(rows, weight, lambda x: x in agreed_same), 4),
                "class_match_rate": round(_rate(rows, weight, lambda x: x in agreed_class), 4),
            }
        report["per_tool"] = dict(per_tool)
        report["locks"] = {"tier1": t1lock, "tier2": t2lock}
    else:
        report["note"] = ("locks absent (tier1/LOCK.json and/or tier2/LOCK.json); the sealed blinding "
                          "key was NOT opened and per-tool rates are withheld. Inter-annotator "
                          "agreement above needs no key.")

    C.write_json(os.path.join(C.ADJ_DIR, "SCORE_REPORT.json"), C.envelope("score_report", report))
    print("\n== inter-annotator (five axes) ==")
    for ax, d in per_axis.items():
        print(f"  {ax:22} n={d['n']:4}  agreement={d['agreement']}  kappa={d['cohen_kappa']}")
    if report["per_tool"]:
        print("\n== per tool (sealed key opened) ==")
        for tool, d in report["per_tool"].items():
            print(f"  [{tool}] n={d['n_labeled']}  same_defect={d['same_defect_rate']}  "
                  f"class_match={d['class_match_rate']}")
    if report["note"]:
        print("\nNOTE:", report["note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
