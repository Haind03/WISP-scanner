#!/usr/bin/env python3
"""Line-level precision/recall on the Patchstack gold set (diff-based GT).

For each CVE we have the VULNERABLE and PATCHED zip. The security patch's changed
lines are a high-quality ground truth for WHERE the vulnerability is. We:

  1. diff vuln vs patched per PHP file -> GT = {relpath: set(changed vuln-side lines)};
  2. run WISP on the vulnerable code -> findings (file, line, class);
  3. score localization:
       FILE-level  : a finding lands in a patched file;
       LINE-level  : a finding line is within +/-WINDOW of a patched line;
       CVE-hit     : a finding of the CVE class lands in a patched file (did WISP
                     localize the actual reported vulnerability?).

This is a real precision GT (not the CVE-class proxy): findings outside patched
files/lines are genuine localization false positives.

    python3 -m eval.localize --window 5 --out out/localize.json
"""
from __future__ import annotations
import os, sys, json, zipfile, tempfile, shutil, difflib, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # project root
sys.path.insert(0, ROOT)
from eval import wisp_contract as _WC
# Contract v1 s1: pin the whole configuration here, not just WISP_NO_GDA.
#
# Until 2026-08-12 this module set no flags at all. Its driver, eval/run_paired_loc.sh, exported
# WISP_NO_GDA=1 and left every other flag to be inherited from whichever shell ran it. That is the
# same defect test_i_scan_testset_contract.py was written to catch in eval/testset/scan_testset.py,
# and the guard was scoped to that one file while this one produced the corpus WISP cache behind 89
# of the paper's macros, including the headline corpus class emission. A guard scoped to where a bug
# was found lets the bug live everywhere else.
#
# This must run before the engine module is imported, because the engine reads its flags at import.
_WC.apply_canonical_env()

from wisp.engine import l1_ingest, taint_engine as te      # noqa: E402
from eval.datasets.patchstack import load_rows, PS_DIR     # noqa: E402


def _unzip(path):
    d = tempfile.mkdtemp()
    try:
        zipfile.ZipFile(path).extractall(d)
    except Exception:
        return None
    return d


def _php_map(root):
    """relpath (below the single top dir) -> absolute path, for *.php."""
    out = {}
    for r, _, files in os.walk(root):
        for fn in files:
            if fn.endswith(".php"):
                ap = os.path.join(r, fn)
                rel = os.path.relpath(ap, root)
                # strip leading top-folder so vuln/patched align even if the top
                # dir name carries a version
                parts = rel.split(os.sep)
                key = os.sep.join(parts[1:]) if len(parts) > 1 else rel
                out[key] = ap
        # keep cap reasonable
    return out


def _fn_ranges(php_file):
    """List of (start_line, end_line) 1-based for every function/method in file.

    The right localization unit for inter-procedural / guard findings is the
    enclosing function: a security patch that *inserts* a nonce/capability check
    at the top of a function fixes the whole function, so a finding anywhere in
    that function has localized the bug even if the exact line differs by >window.
    """
    try:
        src = open(php_file, "rb").read()
    except OSError:
        return []
    try:
        root = te._parser().parse(src).root_node
        return [(fn.start_point[0] + 1, fn.end_point[0] + 1)
                for fn in te._collect_functions(root, src)]
    except Exception:
        return []


def _enclosing_fn(line, ranges):
    """Smallest function range containing `line`; None if top-level."""
    best = None
    for s, e in ranges:
        if s <= line <= e and (best is None or (e - s) < (best[1] - best[0])):
            best = (s, e)
    return best


def _changed_lines(vuln_file, patched_file):
    """Vuln-side line numbers that the patch removed/changed."""
    try:
        a = open(vuln_file, encoding="utf-8", errors="ignore").read().splitlines()
        b = open(patched_file, encoding="utf-8", errors="ignore").read().splitlines()
    except OSError:
        return set()
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    lines = set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("replace", "delete"):
            lines.update(range(i1 + 1, i2 + 1))   # 1-based vuln-side lines
        elif tag == "insert":
            lines.add(i1 + 1)                      # boundary on vuln side
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--out", default="out/localize.json")
    # --verify makes this a taint-only vs +LLM-verify ablation: each finding is
    # additionally passed through the l5 verify gate (model from .env), and the
    # SAME diff-based precision GT is recomputed over the KEPT findings. Caps bound
    # the verify-call budget. Without --verify the behaviour is unchanged.
    ap.add_argument("--verify", action="store_true", help="also score +LLM-verify gate")
    ap.add_argument("--limit", type=int, default=0, help="max scored plugins (0=all)")
    ap.add_argument("--maxf", type=int, default=20, help="findings verified per plugin")
    ap.add_argument("--vcap", type=int, default=300, help="global verify-call cap")
    ap.add_argument("--sample", default="", help="file of slug|cve keys to restrict to")
    args = ap.parse_args()
    rows = load_rows()
    if args.sample:
        want = {s.strip() for s in open(args.sample) if s.strip()}
        rows = [r for r in rows if r["slug"] + "|" + r["cve"] in want]

    V = None
    vstate = {"calls": 0}
    if args.verify:
        # load .env so the verify gate uses the configured CLI bin/model
        # (CLI_VERIFY_BIN/MODEL); without this Verifier falls back to its 'agy'
        # default. Mirrors rq2_eval.py.
        if os.path.exists(".env"):
            for _l in open(".env"):
                _l = _l.strip()
                if _l and not _l.startswith("#") and "=" in _l:
                    _k, _v = _l.split("=", 1)
                    os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
        from wisp.engine.l4_verify import Verifier
        from wisp.engine import slicer
        V = Verifier()
        print(f"ABLATION verify gate: {V.model}  (maxf={args.maxf}, vcap={args.vcap})",
              flush=True)

    KS = (1, 3, 5, 10)     # exploitability-ranked precision@K cutoffs
    agg = {"file_tp": 0, "file_fp": 0, "gt_files": 0, "files_hit": 0,
           "line_tp": 0, "line_fp": 0, "cve_localized": 0, "n": 0,
           "findings": 0, "fn_tp": 0, "fn_fp": 0, "cve_fn_localized": 0,
           # +verify (kept-findings) accumulators — only filled when --verify
           "v_file_tp": 0, "v_file_fp": 0, "v_files_hit": 0, "v_cve_localized": 0,
           "v_findings": 0}
    # ranking@K accumulators: findings are returned exploitability-ranked, so the
    # top-K per plugin are the triaged shortlist an analyst actually reads.
    for k in KS:
        agg[f"top{k}_tp"] = 0        # top-K findings landing in a patched file
        agg[f"top{k}_n"] = 0         # top-K findings considered (<=k*n_plugins)
        agg[f"top{k}_cve"] = 0       # plugins whose CVE class is localized within top-K
    details = []
    for r in rows:
        if args.limit and agg["n"] >= args.limit:
            break
        zp, patched = r["vuln_zip"], r["patched_zip"]
        if not (os.path.isfile(zp) and os.path.isfile(patched)):
            continue
        vroot, proot = _unzip(zp), _unzip(patched)
        if not vroot or not proot:
            continue
        try:
            vmap, pmap = _php_map(vroot), _php_map(proot)
            gt = {}      # relpath -> changed vuln lines
            for rel, vf in vmap.items():
                if rel in pmap:
                    cl = _changed_lines(vf, pmap[rel])
                    if cl:
                        gt[rel] = cl
                else:
                    pass  # file removed in patch; rare, skip
            gt_files = set(gt)

            plug = l1_ingest.load_plugin(zp)
            findings = []
            kept = set()                       # id(finding) surviving the verify gate
            if plug and plug.php_files:
                try:
                    findings = te.detect(plug)
                except Exception:
                    findings = []
                if args.verify and V is not None:
                    for f in findings[:args.maxf]:
                        if vstate["calls"] >= args.vcap:
                            break
                        try:
                            sl = slicer.extract_slice(f.abs_file, f.line, 8, 4000)["text"]
                        except Exception:
                            sl = ""
                        try:
                            vd = V.verify(f, sl, {"has_request_source": True,
                                                  "has_sanitizer": False,
                                                  "reachability": "likely"})
                            if vd.is_vulnerable and vd.confidence >= 0.5:
                                kept.add(id(f))
                        except Exception:
                            kept.add(id(f))    # fail-open: keep on verify error
                        vstate["calls"] += 1
                plug.cleanup()

            # normalize finding file to the same key space (strip top dir)
            def keyof(p):
                parts = p.split("/") if "/" in p else p.split(os.sep)
                return os.sep.join(parts[1:]) if len(parts) > 1 else p

            f_tp = f_fp = l_tp = l_fp = fn_tp = fn_fp = 0
            cve_loc = False
            cve_fn_loc = False
            hit_files = set()
            # +verify (kept-findings) per-plugin tallies
            v_f_tp = v_f_fp = 0
            v_cve_loc = False
            v_hit_files = set()
            _rng_cache = {}
            for f in findings:
                k = keyof(f.file)
                in_file = k in gt
                if in_file:
                    f_tp += 1
                    hit_files.add(k)
                    near = any(abs(f.line - g) <= args.window for g in gt[k])
                    if near:
                        l_tp += 1
                    else:
                        l_fp += 1
                    # function-level: does the finding's enclosing function also
                    # contain a patched line? Parse the localize-side vuln file
                    # (vmap[k] is alive until finally; the plugin's own unzip is
                    # already cleaned up). Same content => same line numbers.
                    if k not in _rng_cache:
                        _rng_cache[k] = _fn_ranges(vmap[k]) if k in vmap else []
                    encl = _enclosing_fn(f.line, _rng_cache[k])
                    in_gt_fn = encl is not None and any(
                        encl[0] <= g <= encl[1] for g in gt[k])
                    if in_gt_fn:
                        fn_tp += 1
                    else:
                        fn_fp += 1
                    if f.vuln_class == r["cls"]:
                        cve_loc = True
                        if in_gt_fn:
                            cve_fn_loc = True
                else:
                    f_fp += 1
                    l_fp += 1
                    fn_fp += 1
                # mirror the file-level tally over the verify-surviving subset
                if args.verify and id(f) in kept:
                    if in_file:
                        v_f_tp += 1
                        v_hit_files.add(k)
                        if f.vuln_class == r["cls"]:
                            v_cve_loc = True
                    else:
                        v_f_fp += 1
            # exploitability-ranked precision@K over the top-K findings per plugin
            for k in KS:
                topk = findings[:k]
                agg[f"top{k}_n"] += len(topk)
                agg[f"top{k}_tp"] += sum(1 for f in topk if keyof(f.file) in gt)
                if any(keyof(f.file) in gt and f.vuln_class == r["cls"] for f in topk):
                    agg[f"top{k}_cve"] += 1
            agg["file_tp"] += f_tp; agg["file_fp"] += f_fp
            agg["line_tp"] += l_tp; agg["line_fp"] += l_fp
            agg["fn_tp"] += fn_tp; agg["fn_fp"] += fn_fp
            agg["gt_files"] += len(gt_files); agg["files_hit"] += len(hit_files & gt_files)
            agg["cve_localized"] += 1 if cve_loc else 0
            agg["cve_fn_localized"] += 1 if cve_fn_loc else 0
            agg["findings"] += len(findings); agg["n"] += 1
            if args.verify:
                agg["v_file_tp"] += v_f_tp; agg["v_file_fp"] += v_f_fp
                agg["v_files_hit"] += len(v_hit_files & gt_files)
                agg["v_cve_localized"] += 1 if v_cve_loc else 0
                agg["v_findings"] += len(kept)
            details.append({"slug": r["slug"], "cve": r["cve"], "cls": r["cls"],
                            "gt_files": len(gt_files), "findings": len(findings),
                            "file_tp": f_tp, "file_fp": f_fp, "line_tp": l_tp,
                            "fn_tp": fn_tp, "cve_localized": cve_loc,
                            "cve_fn_localized": cve_fn_loc,
                            # per-record copies of the @K counters already accumulated into
                            # agg above: same values, kept so a paired bootstrap can resample
                            # plugins. Purely additive, no aggregate depends on them.
                            "topk_n": {str(k): len(findings[:k]) for k in KS},
                            "topk_tp": {str(k): sum(1 for f in findings[:k]
                                                    if keyof(f.file) in gt) for k in KS},
                            "hit": any(f.vuln_class == r["cls"] for f in findings)})
            print(f"{'LOC ' if cve_loc else '    '} {r['slug']:30} {r['cls']:8} "
                  f"gtfiles={len(gt_files)} find={len(findings)} fileTP={f_tp} fileFP={f_fp} lineTP={l_tp}",
                  flush=True)
        finally:
            shutil.rmtree(vroot, ignore_errors=True)
            shutil.rmtree(proot, ignore_errors=True)

    ft, ff = agg["file_tp"], agg["file_fp"]
    lt, lf = agg["line_tp"], agg["line_fp"]
    nt, nf = agg["fn_tp"], agg["fn_fp"]
    rep = {
        "n_plugins": agg["n"], "total_findings": agg["findings"],
        "file_precision": round(ft / (ft + ff), 4) if (ft + ff) else 0,
        "file_recall": round(agg["files_hit"] / agg["gt_files"], 4) if agg["gt_files"] else 0,
        "line_precision": round(lt / (lt + lf), 4) if (lt + lf) else 0,
        "fn_precision": round(nt / (nt + nf), 4) if (nt + nf) else 0,
        "cve_localized": agg["cve_localized"],
        "cve_localized_rate": round(agg["cve_localized"] / agg["n"], 4) if agg["n"] else 0,
        "cve_fn_localized": agg["cve_fn_localized"],
        "cve_fn_localized_rate": round(agg["cve_fn_localized"] / agg["n"], 4) if agg["n"] else 0,
        "window": args.window,
        "agg": dict(agg),      # raw counters, for exact cross-shard merging
        "rank_at_k": {
            str(k): {
                "precision": round(agg[f"top{k}_tp"] / agg[f"top{k}_n"], 4) if agg[f"top{k}_n"] else 0,
                "cve_localized_rate": round(agg[f"top{k}_cve"] / agg["n"], 4) if agg["n"] else 0,
            } for k in KS
        },
        "details": details,
    }
    if args.verify:
        def _f3(p, rr):
            return round(10 * p * rr / (9 * p + rr), 4) if (9 * p + rr) else 0.0
        vtp, vfp = agg["v_file_tp"], agg["v_file_fp"]
        v_prec = round(vtp / (vtp + vfp), 4) if (vtp + vfp) else 0
        v_rec = round(agg["v_cve_localized"] / agg["n"], 4) if agg["n"] else 0
        pre_rec = rep["cve_localized_rate"]      # taint-only CVE-localization recall
        rep["ablation"] = {
            "gate": V.model, "verify_calls": vstate["calls"],
            "taint_only":   {"file_precision": rep["file_precision"], "recall": pre_rec,
                             "F3": _f3(rep["file_precision"], pre_rec)},
            "plus_verify":  {"file_precision": v_prec, "recall": v_rec,
                             "F3": _f3(v_prec, v_rec)},
            "kept_findings": agg["v_findings"], "all_findings": agg["findings"],
        }
    os.makedirs("out", exist_ok=True)
    json.dump(rep, open(args.out, "w"), indent=2)
    print("\n=== Patchstack line-level (diff GT) ===")
    print(json.dumps({k: rep[k] for k in ("n_plugins", "total_findings", "file_precision",
          "file_recall", "line_precision", "fn_precision", "cve_localized",
          "cve_localized_rate", "cve_fn_localized", "cve_fn_localized_rate")}, indent=2))
    print("\n=== exploitability-ranked precision@K (triaged shortlist) ===")
    print(f"{'K':>4}{'file_precision@K':>18}{'cve_localized@K':>18}")
    for k in KS:
        d = rep["rank_at_k"][str(k)]
        print(f"{k:>4}{d['precision']:>18}{d['cve_localized_rate']:>18}")
    print(f"{'(all)':>4}{rep['file_precision']:>18}{rep['cve_localized_rate']:>18}")
    if args.verify:
        a = rep["ablation"]
        print(f"\n=== ABLATION taint-only vs +verify ({a['gate']}, "
              f"{a['verify_calls']} calls, {a['kept_findings']}/{a['all_findings']} kept) ===")
        print(f"{'':14}{'file_prec':>11}{'recall':>9}{'F3':>9}")
        for name, key in (("taint-only", "taint_only"), ("+verify", "plus_verify")):
            d = a[key]
            print(f"{name:14}{d['file_precision']:>11}{d['recall']:>9}{d['F3']:>9}")


if __name__ == "__main__":
    main()
