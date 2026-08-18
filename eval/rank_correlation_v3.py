#!/usr/bin/env python3
"""Rank correlation between the two ends of the geometric ladder, at every unit of analysis.

The question "does the patch-file rung rank things the way the exact-changed-line rung does" has
no single answer, because it is not a single question. It is four, and they differ in the unit
being ranked:

  by_tool    rank the four scanners at each rung, n=4.        Does the endpoint change the leaderboard?
  by_plugin  rank the plugin slugs at each rung, n<=834.      Is the coarse rung a proxy for the fine one?
  by_class   rank the advisory classes at each rung, k<=10.   Are the same classes easy at both rungs?
  by_rank    the tool's OWN rank against each rung, n<=3140.  Does its ordering of its own findings carry
                                                              geometric information?

All four are reported rather than one, because the answers disagree in sign and in strength, and
picking the one that suits the argument would be the whole error this paper is about. The family of
unit-level tests carries a Holm correction so that reporting four readings cannot buy significance.

Inference. Every cell gets a plugin-clustered bootstrap CI, the same unit the rest of the paper
resamples, computed exactly rather than by re-scoring findings: each slug's contribution to every
statistic is a fixed vector of counts, so a bootstrap replicate is a multinomial reweighting of
those vectors. by_plugin resamples its slug-level pairs directly. Where a permutation null is
well defined (the unit's labels are exchangeable under H0) a permutation p is reported too, exact
over all k! assignments when k <= 8. by_rank has no such null at the finding level without
breaking the clustering, so its CI is the inference and it stays out of the Holm family.

    python3 -m eval.rank_correlation_v3            # writes RANK_CORRELATION_V3.json
    python3 -m eval.rank_correlation_v3 --check    # verify against shipped, do not rewrite
"""
from __future__ import annotations
import os, sys, json, time, platform, argparse, hashlib, itertools, warnings
import numpy as np
from scipy import stats

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import analyze_v3 as A

OUT_DIR = A.OUT_DIR
CORPUS_POP = os.path.join(OUT_DIR, "CORPUS_FINDING_POPULATION_V3.jsonl")
MATCHED_POP = os.path.join(os.path.dirname(OUT_DIR), "data", "FINDING_POPULATION_V3.jsonl")
RESULT = os.path.join(OUT_DIR, "RANK_CORRELATION_V3.json")

TOOLS = ("wisp", "semgrep", "wpt", "progpilot")
COARSE, FINE = "in_patched_file", "on_exact_changed_line"
TOPK = 3
REPS = 10000
MIN_CLASS_FINDINGS = 20          # a class ranked on three findings is noise, not a rank
EXACT_PERM_MAX = 8               # 8! = 40320 assignments, still cheap to enumerate


# --------------------------------------------------------------------------- population


def load_pop(path, slice_topk):
    """The pooled rank-3 slice. The corpus file is already that slice, the matched one is not,
    and scoring them differently is how two 'samples' stop being comparable."""
    units = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    if slice_topk:
        units = [u for u in units if u["rank"] <= TOPK]
    return units


def hit(u, rung, arm):
    """Contract v1 s4 rule 3 at the record level, or the kept arm that ignores it."""
    if arm == "contract" and u.get("credit_withheld_non_convergence"):
        return 0
    return 1 if u[rung] else 0


# --------------------------------------------------------------------------- statistics


def spearman(x, y):
    # A bootstrap replicate can draw a constant column, where the coefficient is undefined rather
    # than zero. That is a NaN to be dropped, not a warning to be printed thousands of times.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        r = stats.spearmanr(x, y).statistic
    return float(r) if np.isfinite(r) else float("nan")


def rho_from_counts(num, den):
    """Spearman over per-unit rates, given aligned coarse/fine (numerator, denominator) matrices.

    num, den are (k, 2) arrays: column 0 the coarse rung, column 1 the fine one. Units whose
    denominator is zero in a replicate drop out, which is what resampling slugs is supposed to do.
    """
    ok = (den[:, 0] > 0) & (den[:, 1] > 0)
    if ok.sum() < 3:
        return float("nan")
    r = num[ok] / den[ok]
    return spearman(r[:, 0], r[:, 1])


def perm_p(x, y, rho, rng, reps=REPS):
    """Two-sided permutation p for a rank correlation, exact when the unit count is small."""
    k = len(x)
    if not np.isfinite(rho):
        return float("nan"), "undefined"
    if k <= EXACT_PERM_MAX:
        vals = [spearman(x, list(p)) for p in itertools.permutations(y)]
        hits = sum(1 for r in vals if abs(r) >= abs(rho) - 1e-12)
        return hits / len(vals), "exact permutation over %d! assignments" % k
    y = np.asarray(y, float)
    hits = sum(1 for _ in range(reps)
               if abs(spearman(x, rng.permutation(y))) >= abs(rho) - 1e-12)
    return (hits + 1) / (reps + 1), "%d-replicate permutation" % reps


def boot_ci_multinomial(per_slug_num, per_slug_den, rng, reps=REPS):
    """Plugin-clustered CI for a rho computed from per-unit count vectors.

    per_slug_num/den are (n_slugs, k, 2). Resampling slugs with replacement is exactly a
    multinomial reweighting of their contributions, so no finding is ever re-scored.
    """
    n = per_slug_num.shape[0]
    vals = []
    for _ in range(reps):
        w = rng.multinomial(n, np.full(n, 1.0 / n)).astype(float)
        r = rho_from_counts(np.tensordot(w, per_slug_num, axes=(0, 0)),
                            np.tensordot(w, per_slug_den, axes=(0, 0)))
        if np.isfinite(r):
            vals.append(r)
    if len(vals) < reps // 2:
        return [float("nan"), float("nan")]
    return [round(float(v), 4) for v in np.percentile(vals, [2.5, 97.5])]


def boot_ci_pairs(x, y, rng, reps=REPS):
    """Clustered CI when the unit already IS the plugin: resample the slug-level pairs."""
    x, y = np.asarray(x, float), np.asarray(y, float)
    n = len(x)
    vals = []
    for _ in range(reps):
        idx = rng.integers(0, n, n)
        r = spearman(x[idx], y[idx])
        if np.isfinite(r):
            vals.append(r)
    return [round(float(v), 4) for v in np.percentile(vals, [2.5, 97.5])]


def cell(rho, n, ci, p=None, method="", extra=None):
    d = {"rho": round(rho, 4) if np.isfinite(rho) else None, "n_units": n, "ci95": ci}
    if p is not None:
        d["p"] = float("%.4g" % p)
    if method:
        d["method"] = method
    if extra:
        d.update(extra)
    return d


# --------------------------------------------------------------------------- the four readings


def group_counts(units, keys, arm, slugs):
    """(n_slugs, k, 2) numerator and denominator tensors over an arbitrary grouping key."""
    kidx = {k: i for i, k in enumerate(keys)}
    sidx = {s: i for i, s in enumerate(slugs)}
    num = np.zeros((len(slugs), len(keys), 2))
    den = np.zeros((len(slugs), len(keys), 2))
    for u in units:
        j = kidx.get(u["_key"])
        if j is None:
            continue
        i = sidx[u["slug"]]
        den[i, j, :] += 1
        num[i, j, 0] += hit(u, COARSE, arm)
        num[i, j, 1] += hit(u, FINE, arm)
    return num, den


def reading_by_group(units, keys, arm, label, rng):
    """One reading whose unit of analysis is a group: the tools, or the advisory classes."""
    slugs = sorted({u["slug"] for u in units})
    num, den = group_counts(units, keys, arm, slugs)
    tot_n, tot_d = num.sum(axis=0), den.sum(axis=0)
    coarse, fine = tot_n[:, 0] / tot_d[:, 0], tot_n[:, 1] / tot_d[:, 1]
    rho = spearman(coarse, fine)
    p, how = perm_p(coarse, fine, rho, rng)
    ci = boot_ci_multinomial(num, den, rng)
    return cell(rho, len(keys), ci, p, how,
                {"units": list(keys),
                 "coarse_rate": [round(float(v), 4) for v in coarse],
                 "fine_rate": [round(float(v), 4) for v in fine],
                 "reading": label})


def reading_by_plugin(units, arm, rng):
    """Unit of analysis = the plugin slug. Does a slug that scores at the coarse rung score at
    the fine one? This is the only reading with both a large n and a direct proxy interpretation."""
    by = {}
    for u in units:
        s = by.setdefault(u["slug"], [0, 0, 0])
        s[0] += hit(u, COARSE, arm)
        s[1] += hit(u, FINE, arm)
        s[2] += 1
    slugs = sorted(by)
    x = [by[s][0] / by[s][2] for s in slugs]
    y = [by[s][1] / by[s][2] for s in slugs]
    rho = spearman(x, y)
    p, how = perm_p(x, y, rho, rng)
    ci = boot_ci_pairs(x, y, rng)
    zero = float(np.mean([v == 0 for v in y]))
    return cell(rho, len(slugs), ci, p, how,
                {"slugs_scoring_zero_at_fine_rung": round(zero, 4),
                 "reading": "plugin slugs ranked at each rung"})


def reading_by_own_rank(units, arm, rng):
    """The tool's own rank against each rung. Spearman with a 3-valued x and a binary y is a
    function of the rank-by-hit contingency table, so the clustered bootstrap is a multinomial
    reweighting of per-slug tables and never re-scores a finding."""
    ranks = sorted({u["rank"] for u in units})
    slugs = sorted({u["slug"] for u in units})
    sidx = {s: i for i, s in enumerate(slugs)}
    ridx = {r: i for i, r in enumerate(ranks)}
    tab = np.zeros((len(slugs), len(ranks), 2, 2))     # slug, rank, rung, hit
    for u in units:
        i, j = sidx[u["slug"]], ridx[u["rank"]]
        tab[i, j, 0, hit(u, COARSE, arm)] += 1
        tab[i, j, 1, hit(u, FINE, arm)] += 1

    def rho_of(t, rung):
        xs, ys = [], []
        for j, r in enumerate(ranks):
            for h in (0, 1):
                c = int(round(t[j, rung, h]))
                if c:
                    xs.extend([r] * c)
                    ys.extend([h] * c)
        return spearman(xs, ys) if len(set(ys)) > 1 else float("nan")

    out = {}
    agg = tab.sum(axis=0)
    n = len(units)
    for rung, name in ((0, "coarse_patch_file"), (1, "fine_exact_line")):
        rho = rho_of(agg, rung)
        vals = []
        for _ in range(REPS // 5):                     # 2000 reps: the table is 3x2, not a curve
            w = rng.multinomial(len(slugs), np.full(len(slugs), 1.0 / len(slugs))).astype(float)
            r = rho_of(np.tensordot(w, tab, axes=(0, 0)), rung)
            if np.isfinite(r):
                vals.append(r)
        ci = [round(float(v), 4) for v in np.percentile(vals, [2.5, 97.5])]
        out[name] = cell(rho, n, ci, None, "2000-replicate plugin-clustered bootstrap",
                         {"reading": "the tool's own rank against the " + name.split("_")[0] + " rung"})
    return out


# --------------------------------------------------------------------------- driver


def holm(pairs):
    """Holm-Bonferroni over the family of unit-level tests, so four readings buy no significance."""
    ordered = sorted((p, k) for k, p in pairs if p is not None and np.isfinite(p))
    m, out, running = len(ordered), {}, 0.0
    for i, (p, k) in enumerate(ordered):
        running = max(running, min(1.0, p * (m - i)))
        out[k] = round(running, 4)
    return out, m


def build(rng):
    corpus = load_pop(CORPUS_POP, slice_topk=False)
    matched = load_pop(MATCHED_POP, slice_topk=True)
    res = {"by_tool": {}, "by_plugin": {}, "by_class": {}, "by_own_rank": {}}

    for label, units, arms in (("corpus", corpus, ("contract", "kept")),
                               ("matched", matched, ("kept",))):
        for arm in arms:
            tag = "%s_%s" % (label, arm)
            for u in units:
                u["_key"] = u["tool"]
            res["by_tool"][tag] = reading_by_group(units, TOOLS, arm, "the four tools ranked", rng)

    for arm in ("contract", "kept"):
        res["by_plugin"][arm] = {}
        res["by_class"][arm] = {}
        counts = {}
        for u in corpus:
            counts[u["advisory_class"]] = counts.get(u["advisory_class"], 0) + 1
        for tool in TOOLS + ("pooled",):
            sub = corpus if tool == "pooled" else [u for u in corpus if u["tool"] == tool]
            res["by_plugin"][arm][tool] = reading_by_plugin(sub, arm, rng)
            local = {}
            for u in sub:
                local[u["advisory_class"]] = local.get(u["advisory_class"], 0) + 1
            keys = tuple(sorted(c for c, n in local.items() if n >= MIN_CLASS_FINDINGS))
            for u in sub:
                u["_key"] = u["advisory_class"]
            res["by_class"][arm][tool] = reading_by_group(
                sub, keys, arm, "advisory classes ranked", rng)

    for tool in TOOLS:
        sub = [u for u in corpus if u["tool"] == tool]
        res["by_own_rank"][tool] = reading_by_own_rank(sub, "contract", rng)

    # The Holm family: the contract arm on the corpus, one test per unit-level reading, which is
    # what the supplement's table prints. Pooled rows are aggregates of rows already in the family
    # and would count the same evidence twice, so they stay out of it.
    fam = [("by_tool/corpus_contract", res["by_tool"]["corpus_contract"].get("p"))]
    for unit in ("by_plugin", "by_class"):
        for tool in TOOLS:
            fam.append(("%s/%s" % (unit, tool), res[unit]["contract"][tool].get("p")))
    adj, m = holm(fam)
    for key, p_adj in adj.items():
        unit, who = key.split("/")
        node = res[unit][who] if unit == "by_tool" else res[unit]["contract"][who]
        node["p_holm"] = p_adj
        node["survives_holm"] = bool(p_adj < 0.05)
    res["holm_family"] = {"size": m, "alpha": 0.05,
                          "members": sorted(k for k, _ in fam),
                          "survive": sorted(k for k, _ in fam
                                            if adj.get(k) is not None and adj[k] < 0.05),
                          "note": ("one test per unit-level reading on the contract arm, so "
                                   "reporting every reading cannot buy significance")}
    res["disagreement"] = {
        # Derived, never asserted. This field used to be a fixed string saying the tool-level sign
        # was unstable, which was true when the arms disagreed and false once wisp-scanner-v1.3 made
        # all three negative. The supplement had already been corrected while this note had not, so
        # the artifact and the paper contradicted each other. Compute the claim from the signs.
        "note": _sign_note(res["by_tool"]),
        "by_tool_signs": {k: (None if v["rho"] is None else
                              ("+" if v["rho"] > 0 else "-" if v["rho"] < 0 else "0"))
                          for k, v in res["by_tool"].items()},
    }
    return res


def provenance():
    commit, dirty = A._git_commit()
    return {"schema_version": "rank-correlation-v3", "script": "eval/rank_correlation_v3.py",
            "script_git_commit": commit, "git_dirty": dirty,
            "input_hashes": {"corpus_population": A._sha256(CORPUS_POP),
                             "matched_population": A._sha256(MATCHED_POP)},
            "seed": A.SEED, "bootstrap_replicates": REPS, "permutation_replicates": REPS,
            "bootstrap_unit": "plugin_slug", "topk": TOPK,
            "min_class_findings": MIN_CLASS_FINDINGS,
            "coarse_rung": COARSE, "fine_rung": FINE,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": platform.python_version(), "numpy_version": np.__version__}


def _strip(o, volatile):
    if isinstance(o, dict):
        return {k: _strip(v, volatile) for k, v in o.items() if k not in volatile}
    if isinstance(o, list):
        return [_strip(x, volatile) for x in o]
    return o


def _payload_fp(obj):
    volatile = {"timestamp_utc", "git_dirty", "script_git_commit", "python_version",
                "numpy_version", "input_hashes"}
    return hashlib.sha256(json.dumps(_strip(obj, volatile), sort_keys=True).encode()).hexdigest()[:16]


def _sign_note(by_tool):
    """State what the tool-level readings actually do, from the readings themselves."""
    signs = {k: (None if v["rho"] is None else
                 ("+" if v["rho"] > 0 else "-" if v["rho"] < 0 else "0"))
             for k, v in by_tool.items()}
    present = [s for s in signs.values() if s is not None]
    agree = len(set(present)) <= 1 and present
    if agree:
        return ("all %d tool-level readings share the sign %s, so the sign is stable across the "
                "failure-policy arm and the sample. With four tools a rank correlation carries "
                "little information either way, which is the reason to read the interval rather "
                "than the point estimate." % (len(present), present[0]))
    return ("the tool-level readings do not agree on a sign (%s), so the sign is not stable across "
            "the failure-policy arm or the sample" % ", ".join(f"{k}={v}" for k, v in signs.items()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify against shipped, do not rewrite")
    a = ap.parse_args()

    rng = np.random.default_rng(A.SEED)
    out = dict(provenance())
    out.update(build(rng))

    shipped = json.load(open(RESULT)) if os.path.isfile(RESULT) else None
    match = shipped is not None and _payload_fp(shipped) == _payload_fp(out)
    if not a.check:
        with open(RESULT, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1, sort_keys=True)

    pl = out["by_plugin"]["contract"]
    bt = out["by_tool"]
    print("rank correlation, patch-file rung against exact-changed-line rung")
    for k, v in bt.items():
        print("  by_tool   %-18s rho=%+.3f p=%.3f  (%s)" % (k, v["rho"], v["p"], v["method"]))
    for tool in TOOLS + ("pooled",):
        v = pl[tool]
        print("  by_plugin %-18s rho=%+.3f n=%d CI [%+.3f, %+.3f]"
              % (tool, v["rho"], v["n_units"], v["ci95"][0], v["ci95"][1]))
    print("  Holm family of %d, %d survive at alpha 0.05"
          % (out["holm_family"]["size"], len(out["holm_family"]["survive"])))

    if shipped is None:
        print("no shipped result to compare; wrote fresh RANK_CORRELATION_V3.json")
        return 0
    print("RANK CORRELATION: %s shipped payload." % ("MATCHES" if match else "MISMATCH against"))
    return 0 if match or not a.check else 1


if __name__ == "__main__":
    sys.exit(main())
