#!/usr/bin/env python3
"""Inter-reviewer agreement on the blinded 200-finding same-defect adjudication.

Reads the two reviewers' filled sheets (filled_A.csv carries reviewer_A, filled_B.csv
carries reviewer_B, aligned row for row) and reports, for the whole sample and for the
subset either reviewer marked above UR:

  - observed agreement p_o
  - Cohen's kappa (reproduces the 0.978 in the manuscript)
  - PABAK, the prevalence-adjusted kappa, (k*p_o - 1)/(k - 1)

Labels: SD = points at the patched defect, SC = same class and file but the wrong spot,
UR = unrelated.

Run:  python3 adjudication_agreement.py --out ADJ_AGREEMENT.json
"""
import argparse
import csv
import json
from collections import Counter


def kappa(a, b):
    n = len(a)
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    cats = sorted(set(a) | set(b))
    pe = sum((a.count(c) / n) * (b.count(c) / n) for c in cats)
    k = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    pabak = (len(cats) * po - 1) / (len(cats) - 1) if len(cats) > 1 else float("nan")
    return po, k, pabak, cats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", default="filled_A.csv")
    ap.add_argument("--b", default="filled_B.csv")
    ap.add_argument("--out", default="ADJ_AGREEMENT.json")
    args = ap.parse_args()

    ra = list(csv.DictReader(open(args.a)))
    rb = list(csv.DictReader(open(args.b)))
    assert len(ra) == len(rb), "sheets differ in length"
    assert all(x["finding_id"] == y["finding_id"] for x, y in zip(ra, rb)), \
        "sheets are not in the same row order"

    A = [x["reviewer_A"].strip().upper() for x in ra]
    B = [y["reviewer_B"].strip().upper() for y in rb]

    po, k, pabak, cats = kappa(A, B)
    sub = [i for i in range(len(A)) if A[i] != "UR" or B[i] != "UR"]
    spo, sk, spabak, _ = kappa([A[i] for i in sub], [B[i] for i in sub])

    disagree = [{"finding_id": ra[i]["finding_id"], "class": ra[i]["advisory_class"],
                 "A": A[i], "B": B[i]}
                for i in range(len(A)) if A[i] != B[i]]

    rep = {
        "n": len(A),
        "labels": cats,
        "confusion_AB": {f"{a}|{b}": c
                         for (a, b), c in Counter(zip(A, B)).items()},
        "overall": {"agree": sum(1 for x, y in zip(A, B) if x == y),
                    "p_o": round(po, 4), "cohen_kappa": round(k, 4),
                    "pabak": round(pabak, 4)},
        "above_UR_subset": {"n": len(sub),
                            "agree": sum(1 for i in sub if A[i] == B[i]),
                            "p_o": round(spo, 4), "cohen_kappa": round(sk, 4),
                            "pabak": round(spabak, 4)},
        "disagreements": disagree,
    }
    json.dump(rep, open(args.out, "w"), indent=2)
    print(json.dumps(rep, indent=2))


if __name__ == "__main__":
    main()
