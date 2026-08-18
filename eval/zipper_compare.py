#!/usr/bin/env python3
"""Pair WISP against ZIPPER on the records where ZIPPER's vocabulary applies.

Both tools are scored by the same harness on the same archives, so the only thing that varies
is the analyzer. The comparison is restricted to xss/sqli/rce/lfi because those are the four
classes ZIPPER's five VulnKind values can express; scoring it on deserial, ssrf, upload, other,
auth, or csrf would measure our corpus rather than ZIPPER.

Reported endpoints:
  file-precision@K  fraction of the top-K findings that name a file the vendor patched
  class emission    did the tool report the advisory's class anywhere in the plugin
  coverage          records the tool completed (a failure is a miss, never a silent drop)

CIs are plugin-clustered bootstraps, and the paired difference is resampled over plugins too,
so a plugin contributing several advisories cannot masquerade as independent evidence.
"""
import json, glob, os, sys, random
from collections import defaultdict

OUT = "out/zipper"
KS = ("1", "3", "5", "10")


def load_wisp():
    """Shards, then the make-up chunks, then the clean redo of records the OOM killer spoiled.
    Later files win, so a contaminated record is always replaced by its clean rerun."""
    det = {}
    for pat in ("wisp_[0-9].json", "nesm_[0-9].json", "nesb_[0-9].json", "wisp_redo.json"):
        for p in sorted(glob.glob(os.path.join(OUT, pat))):
            for d in json.load(open(p)).get("details", []):
                det[(d["slug"], d["cve"])] = d
    return det


def load_zipper():
    """First sweep, then the idle-box retry, then the tuned rerun. The first sweep shared the
    machine with WISP and ran a stock JVM at a 300s budget, so a failure there is not evidence
    about ZIPPER until it survives a clean rerun with a 512MB stack, a 10GB heap, 900s, and the
    crash fallback. Later files win, except that a failure never displaces an earlier success:
    the reruns exist to give ZIPPER more chances, not fewer."""
    det = {}
    for name in ("zipper_335.json", "zipper_retry.json", "zipper_tuned.json"):
        p = os.path.join(OUT, name)
        if not os.path.exists(p):
            continue
        for x in json.load(open(p))["details"]:
            prev = det.get((x["slug"], x["cve"]))
            # never let a retry failure overwrite a first-sweep success
            if prev and not prev["err"] and x["err"]:
                continue
            det[(x["slug"], x["cve"])] = x
    return det


def prec_at_k(recs, k):
    n = sum(r["topk_n"][k] for r in recs)
    tp = sum(r["topk_tp"][k] for r in recs)
    return (tp / n if n else 0.0), tp, n


def boot_diff(pairs, fn, B=10000, seed=42):
    """Plugin-clustered bootstrap of a paired difference of ratios."""
    by = defaultdict(list)
    for slug, a, b in pairs:
        by[slug].append((a, b))
    slugs = sorted(by)
    rng = random.Random(seed)
    xs = []
    for _ in range(B):
        samp = []
        for _ in range(len(slugs)):
            samp.extend(by[slugs[rng.randrange(len(slugs))]])
        xs.append(fn(samp))
    xs.sort()
    return xs[int(0.025 * B)], xs[int(0.975 * B)]


# Errors that are our harness's doing, not ZIPPER's: extraction died under our own memory
# pressure, or the JVM was starved of heap by our worker count. A record whose only ZIPPER outcome
# is one of these was never actually run by ZIPPER, so scoring it as a ZIPPER miss would blame the
# tool for our scheduling. Such records are excluded from the paired comparison and reported as an
# exclusion, exactly as a corpus reports samples it could not process, rather than counted against
# either tool.
OUR_FAULT = {"archive_extract_error", "oom_our_config", "missing_archive"}


def main():
    wisp, zip_ = load_wisp(), load_zipper()
    keys = sorted(set(wisp) & set(zip_))
    excluded = [k for k in keys if zip_[k]["err"].split(":")[0] in OUR_FAULT]
    keys = [k for k in keys if k not in set(excluded)]
    print(f"paired records: {len(keys)}  (wisp={len(wisp)} zipper={len(zip_)})")
    if excluded:
        exc = defaultdict(int)
        for k in excluded:
            exc[zip_[k]["err"].split(":")[0]] += 1
        print(f"excluded {len(excluded)} records where OUR harness failed (not scored vs ZIPPER): "
              f"{dict(exc)}")
    if not keys:
        sys.exit("no overlap yet")

    zok = [k for k in keys if not zip_[k]["err"]]
    print(f"zipper completed {len(zok)}/{len(keys)}  errors={len(keys)-len(zok)}")
    errs = defaultdict(int)
    for k in keys:
        if zip_[k]["err"]:
            errs[zip_[k]["err"].split(":")[0]] += 1
    for e, c in sorted(errs.items(), key=lambda x: -x[1]):
        print(f"    {e:24} {c}")

    # Which configuration produced each completed record. A record scored under the fallback ran
    # without --enable-enhanced-dynamic-call, so it is not ZIPPER's headline configuration and the
    # paper says so rather than folding it silently into the RQ1 column.
    cfg = defaultdict(int)
    for k in zok:
        cfg[zip_[k].get("config", "rq1")] += 1
    for c, n in sorted(cfg.items(), key=lambda x: -x[1]):
        print(f"    config {c:17} {n}")

    # failure-as-miss: a record ZIPPER could not complete counts against it, exactly as the
    # paper treats Progpilot and Semgrep timeouts. Errors contribute 0 tp over 0 shown files.
    def z(k):
        r = zip_[k]
        if r["err"]:
            return {"topk_n": {x: 0 for x in KS}, "topk_tp": {x: 0 for x in KS},
                    "hit": False, "findings": 0}
        return r

    rows = []
    print(f"\n{'endpoint':22}{'WISP':>10}{'ZIPPER':>10}{'diff':>9}   {'95% CI (paired)':>20}")
    for k in KS:
        pn, ntp, nn = prec_at_k([wisp[x] for x in keys], k)
        pz, ztp, zn = prec_at_k([z(x) for x in keys], k)
        pairs = [(x[0], (wisp[x]["topk_tp"][k], wisp[x]["topk_n"][k]),
                  (z(x)["topk_tp"][k], z(x)["topk_n"][k])) for x in keys]
        f = lambda s: ((sum(a[0] for a, b in s) / max(1, sum(a[1] for a, b in s)))
                       - (sum(b[0] for a, b in s) / max(1, sum(b[1] for a, b in s))))
        lo, hi = boot_diff(pairs, f)
        print(f"file-prec@{k:<12}{pn:>10.4f}{pz:>10.4f}{pn-pz:>+9.4f}   [{lo:+.4f}, {hi:+.4f}]")
        rows.append({"endpoint": f"file_precision@{k}", "wisp": round(pn, 4),
                     "zipper": round(pz, 4), "diff": round(pn - pz, 4),
                     "ci95": [round(lo, 4), round(hi, 4)],
                     "wisp_tp_n": [ntp, nn], "zipper_tp_n": [ztp, zn]})

    en = sum(1 for x in keys if wisp[x]["hit"]) / len(keys)
    ez = sum(1 for x in keys if z(x)["hit"]) / len(keys)
    pairs = [(x[0], (1 if wisp[x]["hit"] else 0, 1), (1 if z(x)["hit"] else 0, 1)) for x in keys]
    f = lambda s: (sum(a[0] for a, b in s) - sum(b[0] for a, b in s)) / max(1, len(s))
    lo, hi = boot_diff(pairs, f)
    print(f"{'class emission':22}{en:>10.4f}{ez:>10.4f}{en-ez:>+9.4f}   [{lo:+.4f}, {hi:+.4f}]")
    rows.append({"endpoint": "class_emission", "wisp": round(en, 4), "zipper": round(ez, 4),
                 "diff": round(en - ez, 4), "ci95": [round(lo, 4), round(hi, 4)]})

    cn = sum(1 for x in keys if wisp[x]["findings"] > 0) / len(keys)
    cz = len(zok) / len(keys)
    fn_ = sum(wisp[x]["findings"] for x in keys) / len(keys)
    fz = sum(z(x)["findings"] for x in keys) / len(keys)
    print(f"{'coverage':22}{cn:>10.4f}{cz:>10.4f}")
    print(f"{'findings/record':22}{fn_:>10.2f}{fz:>10.2f}")

    # Silence: records the tool completed but reported nothing on. This separates "wrong" from
    # "absent", which the precision endpoints cannot: a tool that reports almost nothing scores
    # well per finding while saying nothing about most of the corpus.
    #
    # Stratified by config, and the paper must quote the rq1-only figure. The fallback disables
    # --enable-enhanced-dynamic-call, which is a capability that finds flows, so a record scored
    # under it can be silent because we weakened ZIPPER rather than because ZIPPER is silent.
    # Pooling the two would inflate our own headline claim using a config ZIPPER never chose.
    sil_n = sum(1 for x in keys if wisp[x]["findings"] == 0)
    sil_z = sum(1 for x in zok if zip_[x]["findings"] == 0)
    rq1 = [x for x in zok if zip_[x].get("config", "rq1") == "rq1"]
    fb = [x for x in zok if zip_[x].get("config", "rq1") != "rq1"]
    sil_rq1 = sum(1 for x in rq1 if zip_[x]["findings"] == 0)
    sil_fb = sum(1 for x in fb if zip_[x]["findings"] == 0)
    print(f"{'silent (completed,':22}{sil_n:>10}{sil_z:>10}")
    print(f"{'  0 findings)':22}{sil_n/len(keys):>10.4f}{sil_z/max(1,len(zok)):>10.4f}"
          f"   <- as frac of completed")
    print(f"{'  zipper @rq1 only':22}{'':>10}{sil_rq1}/{len(rq1)}"
          f"{(sil_rq1/len(rq1) if rq1 else 0):>8.4f}   <- QUOTE THIS ONE in the paper")
    print(f"{'  zipper @fallback':22}{'':>10}{sil_fb}/{len(fb)}"
          f"{(sil_fb/len(fb) if fb else 0):>8.4f}   <- weaker config, report separately")

    # Emission split the same way, for the same reason.
    em_rq1 = sum(1 for x in rq1 if zip_[x]["hit"])
    em_fb = sum(1 for x in fb if zip_[x]["hit"])
    print(f"{'emission @rq1':22}{'':>10}{em_rq1}/{len(rq1)}"
          f"{(em_rq1/len(rq1) if rq1 else 0):>8.4f}")
    print(f"{'emission @fallback':22}{'':>10}{em_fb}/{len(fb)}"
          f"{(em_fb/len(fb) if fb else 0):>8.4f}")

    print("\nper-class class emission:")
    byc = defaultdict(lambda: [0, 0, 0])
    for x in keys:
        c = byc[wisp[x]["cls"]]
        c[0] += 1; c[1] += 1 if wisp[x]["hit"] else 0; c[2] += 1 if z(x)["hit"] else 0
    for c, (n, a, b) in sorted(byc.items()):
        print(f"  {c:8} n={n:<4} WISP {a/n:.3f}   ZIPPER {b/n:.3f}")

    json.dump({"paired_records": len(keys), "excluded_our_fault": len(excluded),
               "zipper_completed": len(zok),
               "zipper_errors": dict(errs), "scope": "xss/sqli/rce/lfi = ZIPPER's VulnKind",
               "coverage": {"wisp": round(cn, 4), "zipper": round(cz, 4)},
               "findings_per_record": {"wisp": round(fn_, 2), "zipper": round(fz, 2)},
               "silent_records": {"wisp": sil_n, "zipper": sil_z,
                                  "zipper_frac_of_completed": round(sil_z/max(1, len(zok)), 4),
                                  "zipper_rq1_only": [sil_rq1, len(rq1)],
                                  "zipper_rq1_frac": round(sil_rq1/len(rq1), 4) if rq1 else None,
                                  "zipper_fallback": [sil_fb, len(fb)]},
               "emission_by_config": {"rq1": [em_rq1, len(rq1)], "fallback": [em_fb, len(fb)]},
               "zipper_config_counts": dict(cfg),
               "endpoints": rows,
               "per_class_emission": {c: {"n": n, "wisp": round(a/n, 4), "zipper": round(b/n, 4)}
                                      for c, (n, a, b) in sorted(byc.items())}},
              open(os.path.join(OUT, "ZIPPER_VS_WISP.json"), "w"), indent=1)
    print(f"\n-> {OUT}/ZIPPER_VS_WISP.json")


if __name__ == "__main__":
    main()
