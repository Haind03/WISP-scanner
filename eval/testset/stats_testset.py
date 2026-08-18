#!/usr/bin/env python3
"""Bootstrap intervals and paired tests for a slug-disjoint robustness set."""
import argparse, hashlib, json, os, random
from math import comb

HERE = os.path.dirname(os.path.abspath(__file__))
SEED, B = 42, 10000


def val(rec, tool, metric):
    tv = rec.get(tool, {})
    if metric == "emission":
        return tv.get("hit", 0)
    k, kk = metric.split("@")
    d = tv.get(k, {})
    return d.get(kk, d.get(int(kk), 0))


def boot_ci(vals, seed=SEED, draws=B):
    rng = random.Random(seed)
    n = len(vals)
    xs = sorted(sum(vals[rng.randrange(n)] for _ in range(n)) / n for _ in range(draws))
    return xs[int(0.025 * draws)], xs[int(0.975 * draws)]


def mcnemar(pairs):
    b = sum(1 for a, c in pairs if a and not c)
    c = sum(1 for a, cc in pairs if cc and not a)
    n = b + c
    if n == 0:
        return b, c, 1.0
    k = min(b, c)
    p = min(1.0, 2 * sum(comb(n, i) for i in range(k + 1)) / 2 ** n)
    return b, c, p


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=os.path.join(HERE, "out", "testset_scored.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "out", "testset_stats.json"))
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--bootstrap", type=int, default=B)
    args = ap.parse_args()
    with open(args.input, encoding="utf-8") as handle:
        data = json.load(handle)
    details = data["details"]
    tools = data.get("summary", {}).get("tools") or [
        tool for tool in ("wisp", "semgrep", "progpilot", "wpt")
        if any(tool in row for row in details)]
    slugs = [row["slug"] for row in details]
    if len(set(slugs)) != len(slugs):
        raise SystemExit("duplicate plugin slugs require clustered, not record-level, bootstrap")
    metrics = ["emission", "pf@1", "pf@10", "cf@1", "cf@10",
               "cfn@1", "cfn@10", "ch@1", "ch@10"]
    rep = {"n": len(details), "input": os.path.abspath(args.input),
           "input_sha256": _sha256(args.input), "seed": args.seed,
           "bootstrap_draws": args.bootstrap,
           "note": "unique plugins; record bootstrap; failure-as-miss"}
    print(f"{'metric':>8} | " + " | ".join(f"{t:>18}" for t in tools))
    for m in metrics:
        rep[m] = {}
        cells = []
        for t in tools:
            vals = [val(r, t, m) for r in details]
            mean = sum(vals) / len(vals)
            lo, hi = boot_ci(vals, args.seed, args.bootstrap)
            rep[m][t] = {"value": round(mean, 4), "ci95": [round(lo, 4), round(hi, 4)]}
            cells.append(f"{mean:.3f} [{lo:.2f},{hi:.2f}]")
        print(f"{m:>8} | " + " | ".join(f"{c:>18}" for c in cells))
    # paired WISP vs each baseline
    print("\nPaired WISP vs baseline (McNemar exact):")
    rep["paired"] = {}
    for other in [tool for tool in tools if tool != "wisp"]:
        rep["paired"][other] = {}
        for m in metrics:
            pairs = [(val(r, "wisp", m), val(r, other, m)) for r in details]
            b, c, p = mcnemar(pairs)
            rep["paired"][other][m] = {"wisp_only": b, "other_only": c, "p": round(p, 8)}
        row = rep["paired"][other]
        print(f"  WISP vs {other:9}: " + "  ".join(
            f"{m}: +{row[m]['wisp_only']}/-{row[m]['other_only']} p={row[m]['p']:.1e}"
            for m in ("emission", "pf@1", "cf@1", "cf@10")))
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(rep, handle, indent=1)


if __name__ == "__main__":
    main()
