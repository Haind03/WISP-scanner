#!/usr/bin/env python3
"""Cluster-aware paired tests on matched-100, with a multiple-comparison policy.

The matched sample's 100 records draw 98 distinct slugs, and two slugs contribute
two records each. McNemar's exact test treats those 100 records as independent,
which is very nearly but not exactly true. This script reports, for every paired
comparison the paper makes on this sample:

  * McNemar's exact test, as published;
  * a slug-level permutation test, which flips the tool labels of all records of a
    plugin together and is therefore valid under within-plugin correlation;
  * the slug-clustered bootstrap interval for the difference;
  * Holm-Bonferroni adjusted p-values over the whole family of tests reported here.

No tool is re-executed. WISP's per-record indicators come from the granularity run
(rank_first_* fields), the baselines' from the class-corrected matched-100 run.

    PYTHONHASHSEED=0 python3 -m eval.matched100_cluster_paired \
        --out out/ratio/MATCHED100_CLUSTER.json
"""
from __future__ import annotations
import os, sys, json, random, argparse, collections
from math import comb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval.datasets.patchstack import load_rows

_RD = os.environ.get("WISP_REPRO_DATA")


def _rp(path):
    """Resolve an input against the standalone bundle dir when WISP_REPRO_DATA is set."""
    return os.path.join(_RD, os.path.basename(path)) if _RD else path


SYS_ROOT = os.environ.get("WISP_SYS_ROOT") or os.path.dirname(ROOT)
WISP_RUN = _rp(os.path.join(SYS_ROOT, "final", "results", "granularity_gda_off_after_emission_final.json"))
BASE_RUN = _rp(os.path.join(SYS_ROOT, "final", "results", "matched_100_baselines_CLASSFIXED.json"))
TOOLS = ("semgrep", "progpilot", "wpt")
KS = (1, 3, 5, 10)


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    lo = min(b, c)
    tail = sum(comb(n, i) for i in range(lo + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def perm_cluster_exact(x, y, slugs):
    """Exact two-sided cluster sign-flip test. No seed, no replicate count, no Monte Carlo error.

    Flipping a plugin exchanges the two tools' labels for every record of that plugin at once, so a
    plugin contributes its summed difference d_k to the statistic and a flip negates it. The null
    distribution of sum(+/- d_k) is a convolution over the plugins whose d_k is nonzero, and a
    plugin with d_k = 0 is unaffected by its own flip and drops out, which is what keeps the
    convolution small enough to enumerate.

    This replaces a Monte Carlo permutation whose answer moved with its seed. Re-running the family
    under 200 seeds gave Holm survivor counts from 18 to 21, and the single exact-line comparison
    the paper singles out survived in about half of them. A headline that turns on --seed is not a
    statement about the data.
    """
    by = collections.defaultdict(int)
    for a, b, s in zip(x, y, slugs):
        by[s] += a - b
    obs = abs(sum(by.values()))
    ds = [d for d in by.values() if d != 0]
    if not ds:
        return 1.0
    # Probabilities rather than counts. Counting sign assignments makes every weight an integer of
    # len(ds) bits, and at this scale that is hundreds of bits carried through millions of
    # additions, which turned a build step into twenty minutes of big-integer arithmetic. Each flip
    # is independent and fair, so carrying probability mass costs nothing in accuracy and keeps
    # every number a machine float.
    dist = {0: 1.0}
    for d in ds:
        nxt = collections.defaultdict(float)
        for t, c in dist.items():
            half = c * 0.5
            nxt[t + d] += half
            nxt[t - d] += half
        dist = nxt
    return sum(c for t, c in dist.items() if abs(t) >= obs)


def perm_cluster(x, y, slugs, B, seed):
    """Two-sided permutation test that exchanges the two tools' labels for all
    records of a plugin at once. The unit of exchangeability is the plugin."""
    rnd = random.Random(seed)
    by = collections.defaultdict(list)
    for a, b, s in zip(x, y, slugs):
        by[s].append((a, b))
    keys = sorted(by)
    n = len(x)
    obs = abs(sum(x) - sum(y)) / n
    hits = 0
    for _ in range(B):
        tot = 0
        for k in keys:
            flip = rnd.random() < 0.5
            for a, b in by[k]:
                tot += (b - a) if flip else (a - b)
        if abs(tot) / n >= obs - 1e-12:
            hits += 1
    return (hits + 1) / (B + 1)


def boot_delta(x, y, slugs, B, seed):
    rnd = random.Random(seed)
    by = collections.defaultdict(list)
    for a, b, s in zip(x, y, slugs):
        by[s].append((a, b))
    keys = sorted(by)
    out = []
    for _ in range(B):
        pairs = [p for k in (rnd.choice(keys) for _ in keys) for p in by[k]]
        m = len(pairs)
        out.append(sum(p[0] for p in pairs) / m - sum(p[1] for p in pairs) / m)
    out.sort()
    return [round(out[int(0.025 * B)], 3), round(out[int(0.975 * B)], 3)]


def holm(pairs):
    """Holm-Bonferroni over (name, p), returning adjusted p-values."""
    order = sorted(pairs, key=lambda t: t[1])
    m = len(order)
    adj, run = {}, 0.0
    for i, (name, p) in enumerate(order):
        v = min(1.0, (m - i) * p)
        run = max(run, v)
        # Six decimal places destroys a genuinely tiny p. The exact permutation test produces
        # values down to 1e-16, and rounding those to 0.0 both loses the number and hands a zero to
        # a formatter that loops on it. The Monte Carlo test this replaced could never go below
        # 1/(B+1), so its floor hid the problem rather than solving it. Significant figures keep a
        # small value small and still cut float noise off a large one.
        adj[name] = float(f"{run:.6g}")
    return adj


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--B", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260722)
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    wisp = {d["slug"] + "|" + d["cve"]: d for d in json.load(open(WISP_RUN))["details"]}
    base = {d["slug"] + "|" + d["cve"]: d for d in json.load(open(BASE_RUN))["details"]}
    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    keys = sorted(k for k in wisp if k in base and k in rows)
    slugs = [k.split("|")[0] for k in keys]
    dup = [s for s, c in collections.Counter(slugs).items() if c > 1]
    print(f"{len(keys)} records, {len(set(slugs))} slugs, duplicated: {dup}")

    ind = {"wisp": {}, **{t: {} for t in TOOLS}}
    ind["wisp"]["class"] = [1 if wisp[k].get("rank_first_class") is not None else 0
                           for k in keys]
    for K in KS:
        ind["wisp"][f"pf@{K}"] = [1 if (wisp[k].get("rank_first_patch_file") or 99) <= K
                                 else 0 for k in keys]
        ind["wisp"][f"cf@{K}"] = [1 if (wisp[k].get("rank_first_class_file") or 99) <= K
                                 else 0 for k in keys]
    for t in TOOLS:
        ind[t]["class"] = []
        for k in keys:
            cls = rows[k]["cls"]
            fs = (base[k].get(t) or {}).get("findings") or []
            ind[t]["class"].append(1 if any(cls in (f.get("classes") or [])
                                            for f in fs) else 0)
        for K in KS:
            ind[t][f"pf@{K}"] = [int((base[k].get(t) or {}).get("pf", {})
                                     .get(str(K), 0)) for k in keys]
            ind[t][f"cf@{K}"] = [int((base[k].get(t) or {}).get("cf", {})
                                     .get(str(K), 0)) for k in keys]

    endpoints = ["class"] + [f"pf@{K}" for K in KS] + [f"cf@{K}" for K in KS]
    print("\npoint estimates (should match the published tables)")
    print(f"{'endpoint':10} {'WISP':>6} " + " ".join(f"{t:>10}" for t in TOOLS))
    for e in endpoints:
        print(f"{e:10} {sum(ind['wisp'][e]) / len(keys):>6.3f} " +
              " ".join(f"{sum(ind[t][e]) / len(keys):>10.3f}" for t in TOOLS))

    res, family = {}, []
    print(f"\n{'comparison':22} {'w':>3} {'l':>3} {'McNemar':>11} {'cluster perm':>13} "
          f"{'clustered CI':>18}")
    print("-" * 76)
    for e in endpoints:
        for t in TOOLS:
            x, y = ind["wisp"][e], ind[t][e]
            b = sum(1 for u, v in zip(x, y) if u and not v)
            c = sum(1 for u, v in zip(x, y) if v and not u)
            pm = mcnemar_exact(b, c)
            pp = perm_cluster(x, y, slugs, a.B, a.seed)
            ci = boot_delta(x, y, slugs, a.B, a.seed)
            name = f"{e} WISP vs {t}"
            res[name] = {"endpoint": e, "baseline": t, "wisp_wins": b, "wisp_loses": c,
                         "delta": round(sum(x) / len(x) - sum(y) / len(y), 3),
                         "mcnemar_p": pm, "cluster_perm_p": round(pp, 6),
                         "delta_ci95_clustered": ci}
            family.append((name, pp))
            f = lambda p: f"{p:.2e}" if p < 1e-4 else f"{p:.4f}"
            print(f"{name:22} {b:>3} {c:>3} {f(pm):>11} {f(pp):>13} {str(ci):>18}")

    adj = holm(family)
    for name, v in adj.items():
        res[name]["cluster_perm_p_holm"] = v
        res[name]["survives_holm_005"] = v < a.alpha
    n_sig = sum(1 for v in adj.values() if v < a.alpha)
    print(f"\nHolm-Bonferroni over {len(family)} tests at alpha={a.alpha}: "
          f"{n_sig} survive, {len(family) - n_sig} do not")
    for name in sorted(adj, key=lambda k: adj[k]):
        mark = "yes" if adj[name] < a.alpha else "no "
        print(f"  {mark}  {name:22} raw {res[name]['cluster_perm_p']:.2e} "
              f"-> holm {adj[name]:.4f}")

    rep = {"n_records": len(keys), "n_slugs": len(set(slugs)),
           "duplicated_slugs": dup, "B": a.B, "seed": a.seed, "alpha": a.alpha,
           "family_size": len(family), "n_survive_holm": n_sig,
           "note": "cluster_perm_p flips tool labels per plugin; holm is applied "
                   "over the whole family printed here",
           "tests": res}
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(rep, open(a.out, "w"), indent=1)
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
