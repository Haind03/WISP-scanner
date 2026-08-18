#!/usr/bin/env python3
"""Independent taint-engine capability test: WISP on the SAST-PHP benchmark
(datasets/java05_xast-benchmark/sast-php — from XAST/YASA, paper 05).

290 labelled cases: *_T.php = a real src->sink taint flow (engine SHOULD fire);
*_F.php = no reaching flow / sanitized (engine should stay SILENT). The benchmark
marks the source as the variable `$__taint_src` and the sink as `__taint_sink()`
(which wraps shell_exec/eval/...). WISP's source model is WP/PHP superglobals, so we
inject `$__taint_src` as a source; shell_exec/eval/include are already WISP sinks.

Score: T -> fired=TP, silent=FN ; F -> fired=FP, silent=TN.
Report overall TPR/TNR/accuracy + per top-category (accuracy vs completeness and
their sub-capabilities) so known gaps (cross-file, dynamic eval) show, not hide.
"""
import os, sys, json, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))   # artifact root
from wisp.engine import taint_engine as te

# inject the benchmark's source marker into the engine source model
te.SUPERGLOBALS = set(te.SUPERGLOBALS) | {"$__taint_src"}

BASE = os.environ.get("WISP_SASTPHP_DIR",
    "datasets/sast-php/case")   # SAST-PHP capability benchmark (XAST/YASA)


def all_cases():
    for root, _, fs in os.walk(BASE):
        for f in fs:
            if not f.endswith(".php"):
                continue
            if f.endswith("_T.php"):
                lab = 1
            elif f.endswith("_F.php"):
                lab = 0
            else:
                continue
            rel = os.path.relpath(os.path.join(root, f), BASE)
            yield os.path.join(root, f), rel, lab


def fired(abs_file, rel):
    try:
        finds, _ = te.detect_file(abs_file, rel, {})
        return len(finds) > 0
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="out/out_sastphp.json")
    args = ap.parse_args()

    from collections import defaultdict
    cat = defaultdict(lambda: {"T": 0, "T_hit": 0, "F": 0, "F_fire": 0})
    tp = fn = tn = fp = 0
    details = []
    for abs_file, rel, lab in all_cases():
        top = rel.split(os.sep)[0]                       # accuracy | completeness
        sub = "/".join(rel.split(os.sep)[:3])            # top/dim/capability
        did = fired(abs_file, rel)
        if lab == 1:
            cat[sub]["T"] += 1
            if did: tp += 1; cat[sub]["T_hit"] += 1
            else:   fn += 1
        else:
            cat[sub]["F"] += 1
            if did: fp += 1; cat[sub]["F_fire"] += 1
            else:   tn += 1
        details.append({"rel": rel, "label": lab, "fired": did})

    # ---- cross-file cases: each is a DIR (*_T / *_F) with main.php + helper(s).
    # Score fairly by accumulating inter-file summaries (how WISP does multi-file):
    # analyze dependency files first to build summaries, then re-scan all with them.
    cf = {"T": 0, "T_hit": 0, "F": 0, "F_fire": 0}
    cf_root = os.path.join(BASE, "completeness/single_app_tracing/cross_file_package_namespace")
    if os.path.isdir(cf_root):
        for case in sorted(os.listdir(cf_root)):
            cdir = os.path.join(cf_root, case)
            if not os.path.isdir(cdir):
                continue
            lab = 1 if case.endswith("_T") else 0 if case.endswith("_F") else None
            if lab is None:
                continue
            files = sorted(os.listdir(cdir), key=lambda f: (f == "main.php", f))  # main last
            summ = {}
            did = False
            for _ in range(2):                      # 2 passes to let summaries settle
                for f in files:
                    if not f.endswith(".php"):
                        continue
                    fi, ls = te.detect_file(os.path.join(cdir, f), f, summ)
                    summ = {**summ, **ls}
                    if fi:
                        did = True
            if lab == 1:
                cf["T"] += 1; tp += did; fn += (not did); cf["T_hit"] += did
            else:
                cf["F"] += 1; fp += did; tn += (not did); cf["F_fire"] += did
            details.append({"rel": f"cross_file/{case}", "label": lab, "fired": did})
    rep_cf = {**cf,
              "TPR": round(cf["T_hit"] / cf["T"], 3) if cf["T"] else None,
              "FPR": round(cf["F_fire"] / cf["F"], 3) if cf["F"] else None}

    n = tp + fn + tn + fp
    tpr = tp / (tp + fn) if (tp + fn) else 0
    tnr = tn / (tn + fp) if (tn + fp) else 0
    acc = (tp + tn) / n if n else 0
    rep = {
        "benchmark": "SAST-PHP (XAST/YASA paper05)", "n_cases": n,
        "TPR_recall": round(tpr, 4), "TNR_specificity": round(tnr, 4),
        "accuracy": round(acc, 4),
        "tp": tp, "fn": fn, "tn": tn, "fp": fp,
        "cross_file": rep_cf,
        "per_capability": {k: {**v,
            "TPR": round(v["T_hit"] / v["T"], 3) if v["T"] else None,
            "FPR": round(v["F_fire"] / v["F"], 3) if v["F"] else None}
            for k, v in sorted(cat.items())},
        "details": details,
    }
    os.makedirs("out", exist_ok=True)
    json.dump(rep, open(args.out, "w"), indent=2)
    print(f"=== WISP on SAST-PHP (paper05 XAST/YASA) — {n} labelled cases ===")
    print(f"TPR(recall)={tpr:.3f}  TNR(specificity)={tnr:.3f}  accuracy={acc:.3f}")
    print(f"  T: {tp} hit / {tp+fn}   |   F: {tn} silent / {tn+fp}  (fp={fp})")
    print("per-capability (top/dimension):")
    agg2 = defaultdict(lambda: [0, 0, 0, 0])   # dim -> [T_hit,T,F_fire,F]
    for k, v in rep["per_capability"].items():
        dim = "/".join(k.split("/")[:2])
        agg2[dim][0] += v["T_hit"]; agg2[dim][1] += v["T"]
        agg2[dim][2] += v["F_fire"]; agg2[dim][3] += v["F"]
    for dim, (th, t, ff, f) in sorted(agg2.items()):
        tprd = f"{th/t:.2f}" if t else "  - "
        fprd = f"{ff/f:.2f}" if f else "  - "
        print(f"  {dim:45} TPR={tprd} ({th}/{t})  FPR={fprd} ({ff}/{f})")
    print(f"  {'completeness/cross_file (multi-file)':45} "
          f"TPR={rep_cf['TPR']} ({rep_cf['T_hit']}/{rep_cf['T']})  "
          f"FPR={rep_cf['FPR']} ({rep_cf['F_fire']}/{rep_cf['F']})")


if __name__ == "__main__":
    main()
