#!/usr/bin/env python3
"""Independent head-to-head on the stivalet PVts (SARD) benchmark — NOT WISP's own
data. Runs all three token-free tools (WISP / Semgrep / Progpilot) on the SAME
sampled files so the comparison has no home-field advantage. Real superglobal
sources + real sinks, so Semgrep/Progpilot run natively (fair).

Label = path safe/ vs unsafe/. Metric = file-level "fired" (tool reports ANY
finding in the file) — the only taxonomy-neutral cross-tool metric.
TPR = fired on unsafe ; FPR = fired on safe ; precision = TP/(TP+FP).
"""
import os, sys, json, random, shutil, subprocess, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))   # artifact root
from wisp.engine import taint_engine as te

DS = os.environ.get("WISP_STIVALET_DIR",
    "datasets/php02_stivalet/Injection")   # SARD stivalet PVts, Injection/ subtree
SCRATCH = os.environ.get("WISP_STIVALET_SCRATCH", "/tmp/wisp-stiv3way")
SG_CONFIGS = ["--config", "p/php", "--config", "p/security-audit"]
PHAR = os.environ.get("PROGPILOT_PHAR", "progpilot.phar")   # Progpilot >= 1.1
CWES = {"CWE_78": "rce", "CWE_89": "sqli"}


def sample(cwe, label, n, rng):
    d = os.path.join(DS, cwe, label)
    fs = [f for f in os.listdir(d) if f.endswith(".php")]
    rng.shuffle(fs)
    return [os.path.join(d, f) for f in fs[:n]]


def stage(paths, dst):
    shutil.rmtree(dst, ignore_errors=True)
    os.makedirs(dst, exist_ok=True)
    m = {}
    for i, p in enumerate(paths):
        b = f"{i:04d}_{os.path.basename(p)}"
        shutil.copy(p, os.path.join(dst, b))
        m[b] = p
    return m


def wisp_fired(p):
    try:
        f, _ = te.detect_file(p, os.path.basename(p), {})
        return len(f) > 0
    except Exception:
        return False


def semgrep_fired(dst):
    try:
        cmd = ["semgrep", *SG_CONFIGS, "--json", "--quiet", "--metrics=off",
               "--jobs", "4", "--timeout", "20", dst]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        data = json.loads(p.stdout) if p.stdout.strip() else {"results": []}
        return {os.path.basename(r.get("path", "")) for r in data.get("results", [])}
    except Exception as e:
        print("  semgrep err:", e); return set()


def progpilot_fired(dst):
    fired = set()
    try:
        p = subprocess.run(["php", PHAR, dst], capture_output=True, text=True, timeout=600)
        out = p.stdout.strip(); i = out.find("[")
        res = json.loads(out[i:]) if i >= 0 else []
        for x in res:
            fp = x.get("sink_file") or ""
            if isinstance(fp, list): fp = fp[0] if fp else ""
            if fp: fired.add(os.path.basename(fp))
    except Exception as e:
        print("  progpilot err:", e)
    return fired


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--out", default="out/out_stivalet_3way.json")
    args = ap.parse_args()
    rng = random.Random(42)
    agg = {t: {"tp": 0, "fp": 0, "nU": 0, "nS": 0} for t in ("WISP", "Semgrep", "Progpilot")}
    per_cwe = {}
    for cwe, cls in CWES.items():
        uf = sample(cwe, "unsafe", args.n, rng)
        sf = sample(cwe, "safe", args.n, rng)
        du = stage(uf, os.path.join(SCRATCH, cwe, "unsafe"))
        ds = stage(sf, os.path.join(SCRATCH, cwe, "safe"))
        print(f"[{cwe}/{cls}] unsafe={len(uf)} safe={len(sf)} — running 3 tools...")
        res = {}
        # WISP
        nu = {b for b, p in du.items() if wisp_fired(p)}
        ns = {b for b, p in ds.items() if wisp_fired(p)}
        # Semgrep
        su = semgrep_fired(os.path.join(SCRATCH, cwe, "unsafe"))
        ss = semgrep_fired(os.path.join(SCRATCH, cwe, "safe"))
        # Progpilot
        pu = progpilot_fired(os.path.join(SCRATCH, cwe, "unsafe"))
        ps = progpilot_fired(os.path.join(SCRATCH, cwe, "safe"))
        fired = {"WISP": (nu, ns), "Semgrep": (su, ss), "Progpilot": (pu, ps)}
        per_cwe[cwe] = {}
        for t, (fu, fs) in fired.items():
            tp = len(fu & set(du)); fp = len(fs & set(ds))
            agg[t]["tp"] += tp; agg[t]["fp"] += fp
            agg[t]["nU"] += len(du); agg[t]["nS"] += len(ds)
            per_cwe[cwe][t] = {"TPR": round(tp/len(du), 3), "FPR": round(fp/len(ds), 3)}
        shutil.rmtree(os.path.join(SCRATCH, cwe), ignore_errors=True)

    rep = {"benchmark": "stivalet PVts (SARD), in-scope CWE_78/89", "n_per_cell": args.n,
           "note": "file-level fired; real sources/sinks so all 3 run natively",
           "per_cwe": per_cwe, "overall": {}}
    print("\n=== INDEPENDENT head-to-head — stivalet PVts (not WISP's data) ===")
    print(f"{'tool':10}{'TPR(recall)':>14}{'FPR':>8}{'precision':>12}")
    for t, a in agg.items():
        tpr = a["tp"]/a["nU"] if a["nU"] else 0
        fpr = a["fp"]/a["nS"] if a["nS"] else 0
        prec = a["tp"]/(a["tp"]+a["fp"]) if (a["tp"]+a["fp"]) else 0
        rep["overall"][t] = {"TPR": round(tpr,4), "FPR": round(fpr,4), "precision": round(prec,4),
                             "tp": a["tp"], "fp": a["fp"], "nU": a["nU"], "nS": a["nS"]}
        print(f"{t:10}{tpr:>14.3f}{fpr:>8.3f}{prec:>12.3f}")
    print("(context: AutoVulnPHP paper reports 99.7% on this suite — see analysis)")
    os.makedirs("out", exist_ok=True)
    json.dump(rep, open(args.out, "w"), indent=2)


if __name__ == "__main__":
    main()
