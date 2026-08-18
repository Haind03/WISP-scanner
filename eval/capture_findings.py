#!/usr/bin/env python3
"""Run WISP once per record and store, per record: the patch-diff GT file set, the
advisory class, and every finding's ranking-relevant attributes. Downstream
sweep_rank.py then re-ranks in post-processing to calibrate the exploitability
score on a TRAIN split and evaluate cf@1/pf@1 on a disjoint TEST split, without
re-scanning per weight (reviewer 2.9/2.11: calibrate on train, report on test).
"""
import os, sys, json, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wisp.engine import taint_engine as te
from wisp.engine import l1_ingest
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _changed_lines


def keyof(p):
    parts = p.split("/") if "/" in p else p.split(os.sep)
    return os.sep.join(parts[1:]) if len(parts) > 1 else p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    want = {s.strip() for s in open(a.sample) if s.strip()}
    rows = [r for r in load_rows() if r["slug"] + "|" + r["cve"] in want]
    out = []
    for r in rows:
        zp, patched = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(zp) and os.path.isfile(patched)):
            continue
        vroot, proot = _unzip(zp), _unzip(patched)
        if not vroot or not proot:
            continue
        try:
            vmap, pmap = _php_map(vroot), _php_map(proot)
            gt = sorted({rel for rel, vf in vmap.items()
                         if rel in pmap and _changed_lines(vf, pmap[rel])})
            plug = l1_ingest.load_plugin(zp)
            fnds = te.detect(plug) if (plug and plug.php_files) else []
            if plug:
                plug.cleanup()
            # store findings in the ENGINE's current order (already ranked); we
            # re-rank in the sweep, so also store the raw attributes.
            F = [{"cls": f.vuln_class, "file": keyof(f.file),
                  "line": int(getattr(f, "line", 0) or 0),
                  "function": getattr(f, "function", ""),
                  "sink_file": keyof(getattr(f, "sink_file", "")),
                  "sink_line": int(getattr(f, "sink_line", 0) or 0),
                  "sink_function": getattr(f, "sink_function", ""),
                  "ep": getattr(f, "entry_point", "unknown"),
                  "ip": bool(getattr(f, "interprocedural", False)),
                  "conf": float(getattr(f, "confidence", 0.6)),
                  "sink": getattr(f, "sink", ""),
                  "source": getattr(f, "source", "")} for f in fnds]
            out.append({"slug": r["slug"], "cve": r["cve"], "cls": r["cls"],
                        "gt": gt, "findings": F})
            print(f"  {r['slug'][:34]:34s} n={len(F)} gt={len(gt)}", flush=True)
        finally:
            import shutil
            shutil.rmtree(vroot, ignore_errors=True)
            shutil.rmtree(proot, ignore_errors=True)
    json.dump(out, open(a.out, "w"))
    print(f"captured {len(out)} records -> {a.out}")


if __name__ == "__main__":
    main()
