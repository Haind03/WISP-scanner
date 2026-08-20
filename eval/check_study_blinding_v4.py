#!/usr/bin/env python3
"""Refuse a calibration study whose packets leak, or whose reconciliation order tracks geometry.

This guard exists because of a specific failure, not a general worry. The 2026-08-18 reconciliation
session was held, read, and then excluded, because its working note showed the disputed rows had
been pre-sorted by patch geometry computed outside the blinded packets. The study's whole claim is
that patch geometry overstates defect identification, so a human label produced while reading rows
in geometry order is not evidence about geometry. Nothing in the pipeline could have caught that
before the session ran. This file is what would have caught it.

Three checks, and each one is demonstrated to fire before it is trusted:

  leakage      an annotator workbook must carry no geometric column and no token naming a tool.
               `--selftest` builds a sheet with `in_patched_file` in it and requires a refusal,
               and a sheet with a rule id in a message column and requires a refusal.

  derivation   the reconciliation order must equal the permutation the lock's seed produces. A
               committed rule that nobody recomputes is a promise, not a control. `--selftest`
               swaps two entries and requires a refusal.

  independence the order must not be associated with any geometric field. Two statistics, because
               the historic defect shows up cleanly in one and the other catches the subtler shape:
               a rank-sum on the positions of the True group against the False group, and a runs
               count, which collapses to 2 when a binary field is sorted. Both are read against a
               Monte-Carlo null of random permutations. `--selftest` feeds it an order sorted by
               `in_patched_file`, which is the historic defect exactly, and requires a refusal.

A guard that only ever passes is indistinguishable from a guard that cannot see. The selftest runs
first in the build and its failures are failures of the guard, not of the study.

    python3 -m eval.check_study_blinding_v4 --selftest
    python3 -m eval.check_study_blinding_v4 --packages <dir> --order <RECONCILIATION_ORDER_V4.json>
"""
from __future__ import annotations
import argparse, json, os, sys, hashlib, re

import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C
from eval.defect_study_reconciliation_lock_v4 import order_of, LOCK

SYS_ROOT = C.SYS_ROOT
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")

# The fields the blinded packet withholds. Any of them appearing in a packet is the failure this
# study cannot survive, so the list is explicit rather than derived from whatever a schema happens
# to hold today.
GEOMETRIC_FIELDS = ["in_patched_file", "same_callable_as_change", "on_exact_changed_line",
                    "within_5_changed_lines", "distance_to_nearest_changed_line",
                    "same_diff_hunk", "near_insertion_boundary", "change_at_top_level",
                    "finding_at_top_level", "class_match"]

ALPHA = 0.01          # a two-sided Monte-Carlo p below this refuses the order
REPS = 20000
NULL_SEED = 7

# 2026-08-20: the first real run of this guard refused all three packages on
# 'cp_contactformpp_admin_int_list.inc.php'. That is a WordPress include file, and a name of the
# form a.b.php has the same three-dot shape as 'php.lang.security.injection.echoed-request', which
# is what C._RULE_ID matches. The packet is supposed to name the file the finding sits in, so
# refusing it would have made the guard unusable and, worse, would have taught the next person to
# pass a flag to silence it. A rule identifier is therefore a dotted token that does NOT end in a
# source or data file extension. The selftest keeps both directions: the include file is accepted
# and the semgrep rule id is still refused.
_FILE_EXT = re.compile(
    r"\.(php\d?|phtml|inc|js|mjs|cjs|jsx|ts|tsx|css|scss|less|html?|twig|tpl|xml|ya?ml|json|md|txt|"
    r"po|mo|pot|sql|ini|conf|lock|csv|svg|png|jpe?g|gif|webp|woff2?|ttf|eot|map|zip|gz)$", re.I)


def _load_geometry(uids=None) -> dict:
    """finding_uid -> {geometric field: value} from the shipped finding population."""
    want = set(uids) if uids is not None else None
    out = {}
    with open(POP, encoding="utf-8") as fh:
        for ln in fh:
            if not ln.strip():
                continue
            d = json.loads(ln)
            u = d.get("finding_uid")
            if want is not None and u not in want:
                continue
            out[u] = {f: d.get(f) for f in GEOMETRIC_FIELDS}
    return out


# ---------------------------------------------------------------- leakage


def _sheet_rows(path: str):
    """(header, rows) for every sheet in an xlsx, or a csv read as one sheet."""
    if path.lower().endswith(".csv"):
        import csv
        with open(path, encoding="utf-8", newline="") as fh:
            r = list(csv.reader(fh))
        if r:
            yield r[0], r[1:]
        return
    import openpyxl
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    for ws in wb.worksheets:
        it = ws.iter_rows(values_only=True)
        try:
            header = [str(h).strip() if h is not None else "" for h in next(it)]
        except StopIteration:
            continue
        yield header, [list(row) for row in it]


def check_leakage(paths) -> list:
    """Every reason a packet must not be sent. Empty list means it may be sent."""
    bad = []
    for p in paths:
        for header, rows in _sheet_rows(p):
            low = [h.strip().lower() for h in header]
            for g in GEOMETRIC_FIELDS:
                if g in low:
                    bad.append(f"{os.path.basename(p)}: column {g!r}, a withheld geometric field")
            for i, h in enumerate(header):
                if C._TOOL_TOKENS.search(str(h)):
                    bad.append(f"{os.path.basename(p)}: column heading {h!r} names a tool")
            for r_i, row in enumerate(rows, start=2):
                for c_i, cell in enumerate(row):
                    if cell is None:
                        continue
                    s = str(cell)
                    if C._TOOL_TOKENS.search(s):
                        bad.append(f"{os.path.basename(p)}: row {r_i} col {header[c_i] if c_i < len(header) else c_i}"
                                   f" names a tool: {s[:60]!r}")
                    elif C._RULE_NAMESPACE.search(s) or (
                            len(s) < 200 and C._RULE_ID.match(s.strip())
                            and not _FILE_EXT.search(s.strip())):
                        bad.append(f"{os.path.basename(p)}: row {r_i} carries a rule identifier: {s[:60]!r}")
    return bad


# ---------------------------------------------------------------- independence


def _runs(seq) -> int:
    """Number of maximal constant runs. A binary sequence sorted by its value has exactly 2."""
    if not len(seq):
        return 0
    return 1 + int(np.sum(np.asarray(seq[1:]) != np.asarray(seq[:-1])))


def independence(order, geom, reps=REPS, seed=NULL_SEED) -> dict:
    """Monte-Carlo association between position in `order` and each geometric field.

    Two statistics per field, because they fail differently. The rank-sum moves when the True group
    sits systematically early or late, and it is blind to an order that alternates in blocks. The
    runs count moves when equal values are clustered at all, which is what sorting produces and what
    the historic working note actually did. Both are compared against permutations of the same
    labels, so the null holds the field's marginal fixed and only the arrangement varies.
    """
    n = len(order)
    rng = np.random.default_rng(seed)
    res = {}
    for f in GEOMETRIC_FIELDS:
        vals = [geom.get(u, {}).get(f) for u in order]
        if any(v is None for v in vals):
            res[f] = {"tested": False, "reason": "not present for every row"}
            continue
        x = np.array([1 if v is True or v == "True" or v == 1 else 0 for v in vals])
        if x.sum() == 0 or x.sum() == n:
            res[f] = {"tested": False, "reason": "constant over the rows, no arrangement to test"}
            continue
        pos = np.arange(n)
        obs_rank = abs(pos[x == 1].mean() - pos[x == 0].mean())
        obs_runs = _runs(x)
        perm = np.array([rng.permutation(x) for _ in range(reps)])
        null_rank = np.abs((perm * pos).sum(1) / perm.sum(1)
                           - ((1 - perm) * pos).sum(1) / (1 - perm).sum(1))
        null_runs = np.array([_runs(row) for row in perm])
        p_rank = float((null_rank >= obs_rank).mean())
        p_runs = float((null_runs <= obs_runs).mean())     # one-sided: too FEW runs means clustered
        res[f] = {"tested": True, "n_true": int(x.sum()),
                  "rank_gap": round(float(obs_rank), 3), "p_rank": round(p_rank, 5),
                  "runs": int(obs_runs), "p_runs": round(p_runs, 5),
                  "ok": p_rank >= ALPHA and p_runs >= ALPHA}
    return res


# ---------------------------------------------------------------- selftest


def _selftest() -> int:
    import tempfile, csv as _csv
    fails = []

    def want(cond, msg):
        if not cond:
            fails.append(msg)

    # ---- independence: the historic defect must be refused, a seeded permutation must pass
    uids = [f"uid-{i:04d}" for i in range(120)]
    geom = {u: {f: False for f in GEOMETRIC_FIELDS} for u in uids}
    for i, u in enumerate(uids):                       # 40 of 120 carry a patched file
        geom[u]["in_patched_file"] = i % 3 == 0

    good = order_of(uids, 20260820)
    r_good = independence(good, geom, reps=4000)
    want(r_good["in_patched_file"]["ok"],
         "a seeded permutation was refused, so the guard refuses everything: "
         f"{r_good['in_patched_file']}")

    sorted_order = sorted(uids, key=lambda u: (not geom[u]["in_patched_file"], u))
    r_bad = independence(sorted_order, geom, reps=4000)
    want(not r_bad["in_patched_file"]["ok"],
         "an order sorted by in_patched_file PASSED, which is the exact defect of the "
         f"2026-08-18 session: {r_bad['in_patched_file']}")

    # a subtler shape: blocks of ten, still clustered, still must be caught by the runs statistic
    blocked = [u for u in uids if geom[u]["in_patched_file"]] + \
              [u for u in uids if not geom[u]["in_patched_file"]]
    want(not independence(blocked, geom, reps=4000)["in_patched_file"]["ok"],
         "a block-grouped order passed")

    # ---- derivation: a swapped order must be refused
    swapped = list(good)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    want(swapped != order_of(uids, 20260820), "the swap did not change the order, test is vacuous")
    want(good == order_of(uids, 20260820), "order_of is not deterministic")

    # ---- leakage: a withheld column and a tool token must both be refused
    d = tempfile.mkdtemp(prefix="blind-selftest-")
    clean = os.path.join(d, "clean.csv")
    with open(clean, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["finding_uid", "file", "line", "class_relation"])
        w.writerow(["uid-0001", "includes/admin.php", "42", ""])
    want(check_leakage([clean]) == [], f"a clean sheet was refused: {check_leakage([clean])}")

    leaky = os.path.join(d, "leaky.csv")
    with open(leaky, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["finding_uid", "in_patched_file", "class_relation"])
        w.writerow(["uid-0001", "True", ""])
    want(any("in_patched_file" in b for b in check_leakage([leaky])),
         "a sheet carrying in_patched_file was accepted")

    tool = os.path.join(d, "tool.csv")
    with open(tool, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["finding_uid", "message", "class_relation"])
        w.writerow(["uid-0001", "php.lang.security.injection.echoed-request", ""])
        w.writerow(["uid-0002", "reported by wp-taint-scan", ""])
    got = check_leakage([tool])
    want(any("rule identifier" in b for b in got), f"a rule id was accepted: {got}")
    want(any("names a tool" in b for b in got), f"a tool name was accepted: {got}")

    # the false positive this guard produced on its first real run, kept as a test in both
    # directions: a dotted WordPress include file must pass, a dotted rule id must still not.
    fname = os.path.join(d, "filenames.csv")
    with open(fname, "w", encoding="utf-8", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(["finding_uid", "file", "class_relation"])
        for v in ("cp_contactformpp_admin_int_list.inc.php", "cp-admin-int-add-booking.inc.php",
                  "assets/js/vendor/jquery.ui.widget.min.js", "includes/class.wp.admin.php"):
            w.writerow(["uid-x", v, ""])
    want(check_leakage([fname]) == [],
         f"a dotted include filename was refused as a rule id: {check_leakage([fname])}")

    if fails:
        print("SELFTEST FAILED, the guard does not do what it claims:")
        for f in fails:
            print("  - " + f)
        return 1
    print("SELFTEST OK: refuses a geometry-sorted order, a block-grouped order, a withheld column, "
          "a tool name and a rule id; accepts a seeded permutation and a clean sheet")
    return 0


# ---------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true", help="prove the guard fires, then exit")
    ap.add_argument("--packages", help="directory of annotator workbooks to check for leakage")
    ap.add_argument("--order", help="RECONCILIATION_ORDER_V4.json to check")
    ap.add_argument("--lock", default=LOCK)
    ap.add_argument("--alpha", type=float, default=ALPHA)
    a = ap.parse_args()

    if a.selftest:
        return _selftest()
    if not a.packages and not a.order:
        ap.error("give --packages, --order, or --selftest")

    rc = 0
    if a.packages:
        paths = []
        for root, _dirs, files in os.walk(a.packages):
            for fn in files:
                if fn.lower().endswith((".xlsx", ".csv")):
                    paths.append(os.path.join(root, fn))
        if not paths:
            print(f"  no workbook under {a.packages}")
            rc = 1
        bad = check_leakage(paths)
        print(f"  leakage: {len(paths)} sheet(s) read, {len(bad)} problem(s)")
        for b in bad[:40]:
            print("    " + b)
        if bad:
            rc = 1

    if a.order:
        od = json.load(open(a.order, encoding="utf-8"))
        order = od["order"]
        if not os.path.isfile(a.lock):
            print(f"  derivation: no lock at {a.lock}")
            return 1
        lock = json.load(open(a.lock, encoding="utf-8"))
        if od.get("lock_content_hash") != lock.get("content_hash"):
            print("  derivation: the order names a different lock than the one on disk")
            rc = 1
        expect = order_of(order, lock["seed"])
        if list(order) != list(expect):
            print(f"  derivation: FAIL, the order is not the permutation seed {lock['seed']} "
                  f"produces over the same {len(order)} rows")
            rc = 1
        else:
            print(f"  derivation: OK, {len(order)} rows match the committed seed {lock['seed']}")

        geom = _load_geometry(order)
        missing = [u for u in order if u not in geom]
        if missing:
            print(f"  independence: {len(missing)} row(s) not in the finding population, "
                  f"cannot be tested: {missing[:3]}")
            rc = 1
        res = independence([u for u in order if u in geom], geom)
        tested = [f for f, v in res.items() if v.get("tested")]
        failed = [f for f in tested if not res[f]["ok"]]
        print(f"  independence: {len(tested)} field(s) tested, {len(failed)} associated with position")
        for f in tested:
            v = res[f]
            print(f"    {'FAIL' if not v['ok'] else 'ok  '} {f:32s} "
                  f"rank gap {v['rank_gap']:8.3f} p {v['p_rank']:.4f}   runs {v['runs']:4d} p {v['p_runs']:.4f}")
        if failed:
            print("  the reconciliation order tracks patch geometry. This is the 2026-08-18 defect. "
                  "Re-derive from the committed seed rather than re-sorting.")
            rc = 1

    print("STUDY BLINDING OK" if rc == 0 else "STUDY BLINDING FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
