#!/usr/bin/env python3
"""Post-adjudication analysis v3 (Prompt 4). Validates the human labels, then computes agreement,
the class-agnostic geometric ladder, the semantic (human) results, sensitivity, tool comparison, and
provenance-stamped outputs.

The scorer never invents a label. Section 1 aborts on any of: duplicate packet id, reviewer sheet not
equal to the population, a missing label, a schema mismatch, a packet content hash that changed since
build, a sheet changed since lock, or a row that does not map to the finding population. Findings are
joined by packet id, never by row order. The sealed blinding key is opened only because both tiers
are locked.

Bootstrap unit is the plugin slug (a census resamples slugs with replacement, carrying every advisory
and finding of a sampled slug). The primary effect is the within-tool absolute drop from patched-file
to changed-region, with a slug-cluster 95% CI. Same-defect is a semantic secondary, reported with a
sensitivity analysis over INSUFFICIENT_EVIDENCE.

    python3 -m eval.analyze_v3 --reps 10000
"""
from __future__ import annotations
import os, sys, json, time, argparse, subprocess, hashlib, platform
from collections import defaultdict
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C

OUT_DIR = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out")
SEED = 20260730
TOOLS = ["wisp", "semgrep", "wpt", "progpilot"]
GEOM_EVENTS = ["in_patched_file", "same_callable_as_change", "on_exact_changed_line",
               "within_2_changed_lines", "within_5_changed_lines", "within_10_changed_lines",
               "same_diff_hunk"]
ORDERED = {"evidence_quality": ["INSUFFICIENT", "PARTIAL", "SUFFICIENT"],
           "confidence": ["LOW", "MEDIUM", "HIGH"]}


# ---------------------------------------------------------------- provenance
def _git_commit():
    try:
        h = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "HEAD"],
                                    stderr=subprocess.DEVNULL).decode().strip()
        dirty = (subprocess.call(["git", "-C", ROOT, "diff", "--quiet"]) != 0 or
                 subprocess.call(["git", "-C", ROOT, "diff", "--cached", "--quiet"]) != 0)
        return h, dirty
    except Exception:
        return "unknown", None


def _sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.isfile(path) else ""


def provenance(reps, inputs):
    commit, dirty = _git_commit()
    return {"schema_version": "analysis-v3", "script": "eval/analyze_v3.py",
            "script_git_commit": commit, "git_dirty": dirty,
            "input_hashes": {k: _sha256(v) for k, v in inputs.items()},
            "seed": SEED, "bootstrap_replicates": reps,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python_version": platform.python_version(), "numpy_version": np.__version__,
            "config": {"tools": TOOLS, "topk": 3, "bootstrap_unit": "plugin_slug",
                       "insufficient_set": "root_cause_relation==INSUFFICIENT_EVIDENCE (either reviewer)"}}


def stamped(prov, kind, payload):
    return {**prov, "artifact_kind": kind, **payload}


# ---------------------------------------------------------------- section 1: input validation
def validate_inputs():
    p = {
        "population": C.POPULATION, "ladder": C.LADDER,
        "packets": os.path.join(C.TIER2_DIR, "PACKETS.json"),
        "reviewerA": os.path.join(C.TIER2_DIR, "reviewer_A_findings.json"),
        "reviewerB": os.path.join(C.TIER2_DIR, "reviewer_B_findings.json"),
        "key": os.path.join(C.TIER2_DIR, "BLINDING_KEY.json"),
        "manifest": os.path.join(C.TIER2_DIR, "MANIFEST.json"),
        "lock1": os.path.join(C.TIER1_DIR, "LOCK.json"),
        "lock2": os.path.join(C.TIER2_DIR, "LOCK.json"),
    }
    for k, v in p.items():
        if not os.path.isfile(v):
            sys.exit(f"ABORT (input validation): missing {k} at {v}")

    A, B = C.read_json(p["reviewerA"]), C.read_json(p["reviewerB"])
    PK, MAN = C.read_json(p["packets"]), C.read_json(p["manifest"])
    KEY = C.read_json(p["key"])
    L1, L2 = C.read_json(p["lock1"]), C.read_json(p["lock2"])
    axes = A["payload"]["axes"]

    def die(msg):
        sys.exit(f"ABORT (input validation): {msg}")

    # schema versions identical
    schemas = {A["schema_version"], B["schema_version"], PK["schema_version"], KEY["schema_version"]}
    if schemas != {C.SCHEMA_VERSION}:
        die(f"schema version mismatch: {schemas}")
    # content-hash integrity (sheet/packets not edited without rehash)
    for name, env in (("reviewerA", A), ("reviewerB", B), ("packets", PK), ("key", KEY)):
        if C.content_hash(env["payload"]) != env["content_hash"]:
            die(f"{name} content hash does not match its body (tampered)")
    # packet content hash unchanged since build
    if PK["content_hash"] != MAN["payload"]["files"].get("PACKETS.json"):
        die("packet content hash changed after build (packets edited post-adjudication)")
    # sheets unchanged since lock
    if L2.get("reviewer_A_sheet_hash") != A["content_hash"] or L2.get("reviewer_B_sheet_hash") != B["content_hash"]:
        die("a reviewer sheet changed after tier-2 lock (lock hash mismatch)")
    # duplicate packet ids
    ids = [x["packet_id"] for x in PK["payload"]["packets"]]
    if len(ids) != len(set(ids)):
        die("duplicate packet_id in PACKETS.json")
    pkset = set(ids)
    # sheets equal the population/packet set
    if set(A["payload"]["labels"]) != pkset or set(B["payload"]["labels"]) != pkset:
        die("reviewer sheet packet set differs from the packet population")
    if set(KEY["payload"]["map"]) != pkset:
        die("blinding key packet set differs from the packet population")
    # no missing label
    for who, env in (("A", A), ("B", B)):
        for pid, row in env["payload"]["labels"].items():
            miss = [ax for ax in axes if not str(row.get(ax, "")).strip()]
            if miss:
                die(f"missing label reviewer {who} packet {pid}: {miss}")
            for ax in axes:
                if row[ax] not in C.TIER2_LABEL_DOMAINS[ax]:
                    die(f"out-of-vocabulary label reviewer {who} packet {pid} {ax}={row[ax]}")
    # every packet maps to a population finding_uid, one to one
    pop = C.load_population()
    pop_by_uid = {r["finding_uid"]: r for r in pop}
    fu = [KEY["payload"]["map"][pid]["finding_uid"] for pid in ids]
    if len(fu) != len(set(fu)):
        die("blinding key maps two packets to one finding_uid")
    missing = [u for u in fu if u not in pop_by_uid]
    if missing:
        die(f"{len(missing)} packet(s) map to a finding_uid absent from the population")
    # both tiers locked (key may be opened)
    if not (L1.get("locked_date") and L2.get("locked_date")):
        die("both tiers must be locked before scoring")

    print(f"input validation PASS: 629 packets, both sheets complete, both tiers locked "
          f"({L1['locked_date']}/{L2['locked_date']}), packet hash {PK['content_hash'][:12]} unchanged")
    return {"A": A, "B": B, "PK": PK, "KEY": KEY, "axes": axes, "pop_by_uid": pop_by_uid,
            "ids": ids}, p


# ---------------------------------------------------------------- unit assembly (join by id)
def build_units(V):
    A, B, KEY, pop_by_uid = V["A"], V["B"], V["KEY"], V["pop_by_uid"]
    la, lb, kmap = A["payload"]["labels"], B["payload"]["labels"], KEY["payload"]["map"]
    units = []
    for pid in V["ids"]:
        k = kmap[pid]
        g = pop_by_uid[k["finding_uid"]]
        d = g["distance_to_nearest_changed_line"]
        within = lambda n: (d is not None and d <= n)
        a, b = la[pid], lb[pid]
        units.append({
            "packet_id": pid, "slug": k["slug"], "cve": k["cve"], "tool": k["tool"],
            "rank": k["rank"], "finding_uid": k["finding_uid"],
            "in_patched_file": bool(g["in_patched_file"]),
            "same_callable_as_change": bool(g["same_callable_as_change"]),
            "on_exact_changed_line": bool(g["on_exact_changed_line"]),
            "within_2_changed_lines": bool(within(2)),
            "within_5_changed_lines": bool(g["within_5_changed_lines"]),
            "within_10_changed_lines": bool(within(10)),
            "same_diff_hunk": bool(g["same_diff_hunk"]),
            "class_match": bool(g["class_match"]),
            "A_class": a["class_relation"], "B_class": b["class_relation"],
            "A_root": a["root_cause_relation"], "B_root": b["root_cause_relation"],
            "A_ev": a["evidence_quality"], "B_ev": b["evidence_quality"],
            "A_conf": a["confidence"], "B_conf": b["confidence"],
            "A_reason": a["reason_code"], "B_reason": b["reason_code"],
            "agreed_same_defect": a["root_cause_relation"] == "SAME_DEFECT" == b["root_cause_relation"],
            "agreed_class_match": a["class_relation"] == "MATCH" == b["class_relation"],
            "insufficient_either": "INSUFFICIENT_EVIDENCE" in (a["root_cause_relation"], b["root_cause_relation"]),
        })
    return units


# ---------------------------------------------------------------- bootstrap (slug cluster)
def _slug_index(units):
    slugs = sorted({u["slug"] for u in units})
    idx = {s: i for i, s in enumerate(slugs)}
    return slugs, idx


def boot_rate(units, prop, reps, seed=SEED):
    """Slug-cluster bootstrap of a per-finding rate. prop(u)->bool over the given unit list."""
    slugs, idx = _slug_index(units)
    k = np.zeros(len(slugs)); n = np.zeros(len(slugs))
    for u in units:
        i = idx[u["slug"]]; n[i] += 1; k[i] += 1 if prop(u) else 0
    N = n.sum()
    if N == 0:
        return {"count": 0, "n": 0, "rate": None, "ci95": [None, None]}
    base = k.sum() / N
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, len(slugs), size=(reps, len(slugs)))
    Ks = k[picks].sum(1); Ns = n[picks].sum(1)
    rates = np.divide(Ks, Ns, out=np.full(reps, np.nan), where=Ns > 0)
    lo, hi = np.nanpercentile(rates, [2.5, 97.5])
    return {"count": int(k.sum()), "n": int(N), "rate": round(float(base), 4),
            "ci95": [round(float(lo), 4), round(float(hi), 4)]}


def boot_diff(units, propA, propB, reps, seed=SEED):
    """Slug-cluster bootstrap of a per-finding rate difference propA-propB on the same units, plus a
    two-sided bootstrap p-value for diff==0."""
    slugs, idx = _slug_index(units)
    ka = np.zeros(len(slugs)); kb = np.zeros(len(slugs)); n = np.zeros(len(slugs))
    for u in units:
        i = idx[u["slug"]]; n[i] += 1
        ka[i] += 1 if propA(u) else 0; kb[i] += 1 if propB(u) else 0
    N = n.sum()
    base = (ka.sum() - kb.sum()) / N if N else None
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, len(slugs), size=(reps, len(slugs)))
    Ns = n[picks].sum(1)
    diffs = np.divide(ka[picks].sum(1) - kb[picks].sum(1), Ns, out=np.full(reps, np.nan), where=Ns > 0)
    lo, hi = np.nanpercentile(diffs, [2.5, 97.5])
    p = 2 * min(np.mean(diffs <= 0), np.mean(diffs >= 0))
    return {"diff": round(float(base), 4), "ci95": [round(float(lo), 4), round(float(hi), 4)],
            "boot_p": round(float(min(p, 1.0)), 4)}


# ---------------------------------------------------------------- kappa
def _kappa_from_matrix(m, weights=None):
    n = m.sum()
    if n == 0:
        return None
    row = m.sum(1) / n; col = m.sum(0) / n
    if weights is None:
        po = np.trace(m) / n
        pe = float((row * col).sum())
    else:
        po = float((weights * m).sum()) / n
        pe = float((weights * np.outer(row, col)).sum())
    if pe == 1:
        return 1.0
    return (po - pe) / (1 - pe)


def _weight_matrix(k):
    i = np.arange(k)
    return 1 - ((i[:, None] - i[None, :]) ** 2) / (k - 1) ** 2   # quadratic agreement weights


def confusion(units, fa, fb, cats):
    ci = {c: i for i, c in enumerate(cats)}
    m = np.zeros((len(cats), len(cats)))
    for u in units:
        m[ci[u[fa]], ci[u[fb]]] += 1
    return m


def boot_kappa(units, fa, fb, cats, reps, weighted=False, seed=SEED):
    slugs, idx = _slug_index(units)
    ci = {c: i for i, c in enumerate(cats)}
    k = len(cats)
    per = np.zeros((len(slugs), k * k))
    for u in units:
        per[idx[u["slug"]], ci[u[fa]] * k + ci[u[fb]]] += 1
    W = _weight_matrix(k) if weighted else None
    base = _kappa_from_matrix(per.sum(0).reshape(k, k), W)
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, len(slugs), size=(reps, len(slugs)))
    vals = []
    for r in range(reps):
        mat = per[picks[r]].sum(0).reshape(k, k)
        v = _kappa_from_matrix(mat, W)
        if v is not None:
            vals.append(v)
    lo, hi = np.percentile(vals, [2.5, 97.5])
    raw = np.trace(per.sum(0).reshape(k, k)) / per.sum()
    return {"kappa": round(float(base), 4), "ci95": [round(float(lo), 4), round(float(hi), 4)],
            "raw_agreement": round(float(raw), 4), "n": int(per.sum()), "weighted": weighted}


# ---------------------------------------------------------------- per-record endpoints
def per_record_endpoints(units, records_all):
    """records_all: list of (slug, cve). Endpoint per (record, tool): tool has >=1 top-3 finding with
    the property. Missing tool findings count as 0 (failure-as-miss)."""
    by = defaultdict(list)
    for u in units:
        by[(u["slug"], u["cve"], u["tool"])].append(u)
    props = {"prox5_s3": lambda u: u["within_5_changed_lines"],
             "classprox5_s3": lambda u: u["within_5_changed_lines"] and u["class_match"],
             "samedefect_s3": lambda u: u["agreed_same_defect"]}
    rows = []
    for slug, cve in records_all:
        for tool in TOOLS:
            fs = by.get((slug, cve, tool), [])
            rows.append({"slug": slug, "cve": cve, "tool": tool,
                         **{name: (any(fn(u) for u in fs) if fs else False) for name, fn in props.items()},
                         "answered": bool(fs)})
    return rows, list(props)


def endpoint_micro_macro(rows, tool, name):
    sub = [r for r in rows if r["tool"] == tool]
    micro = np.mean([r[name] for r in sub]) if sub else None
    byslug = defaultdict(list)
    for r in sub:
        byslug[r["slug"]].append(r[name])
    macro = np.mean([np.mean(v) for v in byslug.values()]) if byslug else None
    cov = np.mean([r["answered"] for r in sub]) if sub else None
    return {"record_micro": round(float(micro), 4), "plugin_macro": round(float(macro), 4),
            "coverage": round(float(cov), 4), "n_records": len(sub)}


def boot_record_diff(rows, name, tx, ty, reps, seed=SEED):
    """Slug-cluster bootstrap of a per-record endpoint rate difference tx-ty (failure-as-miss)."""
    slugs = sorted({r["slug"] for r in rows})
    idx = {s: i for i, s in enumerate(slugs)}
    kx = np.zeros(len(slugs)); ky = np.zeros(len(slugs)); nx = np.zeros(len(slugs))
    for r in rows:
        if r["tool"] == tx:
            i = idx[r["slug"]]; nx[i] += 1; kx[i] += 1 if r[name] else 0
        elif r["tool"] == ty:
            ky[idx[r["slug"]]] += 1 if r[name] else 0
    base = (kx.sum() - ky.sum()) / nx.sum() if nx.sum() else None
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, len(slugs), size=(reps, len(slugs)))
    Ns = nx[picks].sum(1)
    diffs = np.divide(kx[picks].sum(1) - ky[picks].sum(1), Ns, out=np.full(reps, np.nan), where=Ns > 0)
    lo, hi = np.nanpercentile(diffs, [2.5, 97.5])
    p = 2 * min(np.mean(diffs <= 0), np.mean(diffs >= 0))
    return {"pair": f"{tx}-{ty}", "diff": round(float(base), 4),
            "ci95": [round(float(lo), 4), round(float(hi), 4)], "boot_p": round(float(min(p, 1.0)), 4)}


def perm_signflip(rows, name, tx, ty, reps=10000, seed=SEED):
    """Plugin-level paired permutation (sign-flip) on records where both tools are answerable-paired.
    Per record the paired statistic is endpoint(tx)-endpoint(ty) in {-1,0,1}; sign-flip within slug
    cluster gives a two-sided p-value."""
    by = defaultdict(dict)
    for r in rows:
        by[(r["slug"], r["cve"])][r["tool"]] = r[name]
    slug_of = {}
    diffs = []
    for (slug, cve), d in by.items():
        if tx in d and ty in d:
            diffs.append((slug, int(d[tx]) - int(d[ty])))
    if not diffs:
        return {"pair": f"{tx}-{ty}", "n_pairs": 0, "perm_p": None, "obs": None}
    slugs = sorted({s for s, _ in diffs})
    sidx = {s: i for i, s in enumerate(slugs)}
    dv = np.array([d for _, d in diffs], float)
    sg = np.array([sidx[s] for s, _ in diffs])
    obs = dv.sum()
    rng = np.random.default_rng(seed)
    ge = 0
    for _ in range(reps):
        flip = rng.integers(0, 2, size=len(slugs)) * 2 - 1     # one sign per slug cluster
        stat = (dv * flip[sg]).sum()
        if abs(stat) >= abs(obs) - 1e-9:
            ge += 1
    return {"pair": f"{tx}-{ty}", "n_pairs": len(diffs), "obs_sum": float(obs),
            "perm_p": round((ge + 1) / (reps + 1), 4)}


# ---------------------------------------------------------------- Holm
def holm(pvals: dict) -> dict:
    items = sorted(pvals.items(), key=lambda kv: (kv[1] if kv[1] is not None else 1.0))
    m = len(items)
    out = {}
    running = 0.0
    for rank, (name, p) in enumerate(items):
        if p is None:
            out[name] = {"raw_p": None, "holm_p": None, "reject_0.05": None}
            continue
        adj = min(1.0, (m - rank) * p)
        running = max(running, adj)
        out[name] = {"raw_p": round(p, 4), "holm_p": round(running, 4), "reject_0.05": running < 0.05}
    return out


# ---------------------------------------------------------------- section builders
def geometric_ladder(units, n_records, reps):
    out = {"unit": "one top-3 finding", "n_records_matched": n_records, "pooled": {}, "per_tool": {},
           "primary_effect": {}, "conditional_transition": {}, "nested_ratio": {}}
    def block(us):
        ans = len({(u["slug"], u["cve"]) for u in us})
        b = {"n_findings": len(us), "n_answered_records": ans}
        for e in GEOM_EVENTS:
            b[e] = boot_rate(us, (lambda ev: (lambda u: u[ev]))(e), reps)
        return b
    out["pooled"] = block(units)
    for tool in TOOLS:
        us = [u for u in units if u["tool"] == tool]
        if not us:
            out["per_tool"][tool] = {"n_findings": 0, "note": "no findings on the matched sample"}
            continue
        out["per_tool"][tool] = block(us)
        infile = [u for u in us if u["in_patched_file"]]
        # conditional transitions among patched-file findings
        out["conditional_transition"][tool] = {
            f"P({e}|patched_file)": boot_rate(infile, (lambda ev: (lambda u: u[ev]))(e), reps)
            for e in ("same_callable_as_change", "on_exact_changed_line",
                      "within_5_changed_lines", "same_diff_hunk")}
        # primary effect: absolute drop patched_file -> changed region (exact, hunk, within5)
        out["primary_effect"][tool] = {
            "drop_to_exact_changed_line": boot_diff(us, lambda u: u["in_patched_file"],
                                                    lambda u: u["on_exact_changed_line"], reps),
            "drop_to_same_diff_hunk": boot_diff(us, lambda u: u["in_patched_file"],
                                                lambda u: u["same_diff_hunk"], reps),
            "drop_to_within_5": boot_diff(us, lambda u: u["in_patched_file"],
                                          lambda u: u["within_5_changed_lines"], reps)}
        # nested ratio (patched_file / exact), same rows, with counts + unbounded flag
        nfile = sum(u["in_patched_file"] for u in us)
        nexact = sum(u["on_exact_changed_line"] for u in us)
        out["nested_ratio"][tool] = {
            "events": "in_patched_file / on_exact_changed_line (nested, same findings)",
            "numerator_count": int(nfile), "denominator_count": int(nexact),
            "ratio": round(nfile / nexact, 2) if nexact else None,
            "unbounded": nexact == 0, "unstable_small_denominator": 0 < nexact < 10,
            "note": "ratio is secondary; risk difference (primary_effect) and conditional_transition are primary"}
    return out


def _reconciled_root(u, recon):
    """The reconciled root_cause for a unit: the agreed label when A and B agree, the human final
    label for a resolved dispute, or None for a dispute still unresolved."""
    if u["A_root"] == u["B_root"]:
        return u["A_root"]
    return (recon or {}).get(u["packet_id"])


def semantic(units, reps, recon=None):
    out = {"unit": "one adjudicated top-3 finding (packet)", "per_tool": {},
           "note": "class_match_geometric is from tool output; the *_human fields are agreed A&B labels"}
    for tool in TOOLS:
        us = [u for u in units if u["tool"] == tool]
        if not us:
            out["per_tool"][tool] = {"n": 0, "note": "no findings"}
            continue
        classmatched = [u for u in us if u["agreed_class_match"]]
        infile = [u for u in us if u["in_patched_file"]]
        out["per_tool"][tool] = {
            "n": len(us),
            "class_match_rate_geometric": boot_rate(us, lambda u: u["class_match"], reps),
            "class_match_rate_human_agreed": boot_rate(us, lambda u: u["agreed_class_match"], reps),
            "same_defect_rate": boot_rate(us, lambda u: u["agreed_same_defect"], reps),
            "same_defect_rate_reviewer_A": boot_rate(us, lambda u: u["A_root"] == "SAME_DEFECT", reps),
            "same_defect_rate_reviewer_B": boot_rate(us, lambda u: u["B_root"] == "SAME_DEFECT", reps),
            "same_defect_rate_either": boot_rate(
                us, lambda u: u["A_root"] == "SAME_DEFECT" or u["B_root"] == "SAME_DEFECT", reps),
            "same_defect_among_class_matched": boot_rate(classmatched, lambda u: u["agreed_same_defect"], reps),
            "same_defect_among_patched_file": boot_rate(infile, lambda u: u["agreed_same_defect"], reps),
            "insufficient_evidence_rate": boot_rate(us, lambda u: u["insufficient_either"], reps),
            "note": "same_defect_rate is the agreed (both reviewers) rate. A/B/either bracket it; the "
                    "root_cause disagreements should be reconciled before a single headline is fixed."}
        if recon is not None:
            det = [u for u in us if _reconciled_root(u, recon) is not None]
            out["per_tool"][tool]["same_defect_rate_reconciled"] = boot_rate(
                det, lambda u: _reconciled_root(u, recon) == "SAME_DEFECT", reps)
            out["per_tool"][tool]["n_reconcilable"] = len(det)
            out["per_tool"][tool]["n_unresolved_disputes"] = len(us) - len(det)
    return out


def agreement(units, reps):
    CATS = {"class_relation": C.CLASS_RELATION, "root_cause_relation": C.ROOT_CAUSE_RELATION,
            "evidence_quality": ORDERED["evidence_quality"], "confidence": ORDERED["confidence"],
            "reason_code": C.REASON_CODE}
    FA = {"class_relation": ("A_class", "B_class"), "root_cause_relation": ("A_root", "B_root"),
          "evidence_quality": ("A_ev", "B_ev"), "confidence": ("A_conf", "B_conf"),
          "reason_code": ("A_reason", "B_reason")}
    out = {"caveat": "High kappa shows the rubric was applied consistently. It is NOT evidence the "
                     "ground truth is correct.", "per_axis": {}, "confusion": {}, "subsets": {},
           "disagreements_needing_reconciliation": {}}
    for ax, cats in CATS.items():
        fa, fb = FA[ax]
        rec = {"cohen_kappa": boot_kappa(units, fa, fb, cats, reps)}
        if ax in ORDERED:
            rec["weighted_kappa_quadratic"] = boot_kappa(units, fa, fb, cats, reps, weighted=True)
        else:
            rec["weighted_kappa_quadratic"] = {"note": "categories not ordered; weighted kappa not reported"}
        out["per_axis"][ax] = rec
    for ax in ("class_relation", "root_cause_relation"):
        fa, fb = FA[ax]
        m = confusion(units, fa, fb, CATS[ax])
        out["confusion"][ax] = {"categories": CATS[ax], "matrix_A_rows_B_cols": m.astype(int).tolist()}
    # subsets
    subs = {"whole": units,
            "same_class_geometric": [u for u in units if u["class_match"]],
            "patched_file": [u for u in units if u["in_patched_file"]],
            "nontrivial_excl_both_unrelated": [u for u in units
                                               if not (u["A_root"] == "UNRELATED" and u["B_root"] == "UNRELATED")]}
    for name, us in subs.items():
        out["subsets"][name] = {"n": len(us),
            "class_relation_kappa": boot_kappa(us, "A_class", "B_class", C.CLASS_RELATION, reps) if us else None,
            "root_cause_kappa": boot_kappa(us, "A_root", "B_root", C.ROOT_CAUSE_RELATION, reps) if us else None}
    # per tool (after unblinding)
    out["subsets"]["by_tool_after_unblinding"] = {}
    for tool in TOOLS:
        us = [u for u in units if u["tool"] == tool]
        if len(us) < 2:
            continue
        out["subsets"]["by_tool_after_unblinding"][tool] = {"n": len(us),
            "class_relation_kappa": boot_kappa(us, "A_class", "B_class", C.CLASS_RELATION, reps),
            "root_cause_kappa": boot_kappa(us, "A_root", "B_root", C.ROOT_CAUSE_RELATION, reps)}
    out["disagreements_needing_reconciliation"] = {
        "class_relation": int(sum(u["A_class"] != u["B_class"] for u in units)),
        "root_cause_relation": int(sum(u["A_root"] != u["B_root"] for u in units)),
        "n_total": len(units)}
    return out


def matched100(units, records_all, reps):
    rows, endpoints = per_record_endpoints(units, records_all)
    out = {"n_records": len(records_all), "endpoints": endpoints, "per_tool": {},
           "tool_comparison": {}, "multiple_testing": {}}
    for tool in TOOLS:
        out["per_tool"][tool] = {name: endpoint_micro_macro(rows, tool, name) for name in endpoints}
    pairs = [("wisp", "wpt"), ("wisp", "semgrep"), ("wpt", "semgrep")]
    geometric_family = {}
    for name in endpoints:
        out["tool_comparison"][name] = {"slug_cluster_bootstrap": [], "plugin_permutation": []}
        for tx, ty in pairs:
            out["tool_comparison"][name]["slug_cluster_bootstrap"].append(boot_record_diff(rows, name, tx, ty, reps))
            perm = perm_signflip(rows, name, tx, ty, reps=min(reps, 10000))
            out["tool_comparison"][name]["plugin_permutation"].append(perm)
            if name in ("prox5_s3", "classprox5_s3"):
                geometric_family[f"{name}:{tx}-{ty}"] = perm["perm_p"]
    out["multiple_testing"] = {
        "primary_family": "geometric proximity@5 success@3 and class-and-proximity@5 success@3, "
                          "pairwise plugin-permutation tests",
        "holm": holm(geometric_family),
        "note": "same-defect success@3 is exploratory and excluded from the primary family"}
    return out


def sensitivity(units, reps):
    out = {"insufficient_set": "root_cause_relation==INSUFFICIENT_EVIDENCE (either reviewer)",
           "per_tool": {}}
    for tool in TOOLS + ["ALL"]:
        us = units if tool == "ALL" else [u for u in units if u["tool"] == tool]
        if not us:
            continue
        keep = [u for u in us if not u["insufficient_either"]]
        out["per_tool"][tool] = {
            "n": len(us), "n_insufficient": sum(u["insufficient_either"] for u in us),
            "treat_insufficient_as_failure": boot_rate(us, lambda u: u["agreed_same_defect"], reps),
            "exclude_insufficient": boot_rate(keep, lambda u: u["agreed_same_defect"], reps),
            "bound_all_insufficient_fail": boot_rate(us, lambda u: u["agreed_same_defect"], reps),
            "bound_all_insufficient_pass": boot_rate(
                us, lambda u: u["agreed_same_defect"] or u["insufficient_either"], reps)}
    return out


def _fmt_ci(d):
    if not d or d.get("rate") is None:
        return "n.a."
    return f"{d['rate']:.3f} [{d['ci95'][0]:.3f}, {d['ci95'][1]:.3f}]"


def latex_macros(geom, sem, agr, m100):
    def mac(name, val):
        return f"\\newcommand{{\\{name}}}{{{val}}}"
    L = ["% Auto-generated by eval/analyze_v3.py. Do not edit by hand.",
         "% Geometric ladder is the primary result. Same-defect is a semantic secondary."]
    for tool in ("wisp", "semgrep", "wpt"):
        t = tool.capitalize()
        pt = geom["per_tool"].get(tool, {})
        if pt.get("n_findings"):
            L.append(mac(f"{t}InPatchedFile", f"{pt['in_patched_file']['rate']:.3f}"))
            L.append(mac(f"{t}ExactChangedLine", f"{pt['on_exact_changed_line']['rate']:.3f}"))
            L.append(mac(f"{t}SameDiffHunk", f"{pt['same_diff_hunk']['rate']:.3f}"))
            L.append(mac(f"{t}Prox Five".replace(" ", ""), f"{pt['within_5_changed_lines']['rate']:.3f}"))
            de = geom["primary_effect"][tool]["drop_to_exact_changed_line"]
            L.append(mac(f"{t}DropToExact", f"{de['diff']:.3f}"))
            L.append(mac(f"{t}DropToExactCILo", f"{de['ci95'][0]:.3f}"))
            L.append(mac(f"{t}DropToExactCIHi", f"{de['ci95'][1]:.3f}"))
            st = sem["per_tool"].get(tool, {})
            L.append(mac(f"{t}SameDefect", f"{st['same_defect_rate']['rate']:.3f}"))
    ck = agr["per_axis"]["class_relation"]["cohen_kappa"]
    rk = agr["per_axis"]["root_cause_relation"]["cohen_kappa"]
    L.append(mac("KappaClassRelation", f"{ck['kappa']:.3f}"))
    L.append(mac("KappaRootCause", f"{rk['kappa']:.3f}"))
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10000)
    a = ap.parse_args()

    V, paths = validate_inputs()
    units = build_units(V)
    records_all = [tuple(k.split("|", 1)) for k in C.load_manifest_records()]
    n_records = len(records_all)
    prov = provenance(a.reps, {"population": paths["population"], "packets": paths["packets"],
                               "reviewerA": paths["reviewerA"], "reviewerB": paths["reviewerB"],
                               "blinding_key": paths["key"], "ladder": paths["ladder"]})

    recon = None
    recon_path = os.path.join(C.TIER2_DIR, "reconciliation.json")
    if os.path.isfile(recon_path):
        rc = C.read_json(recon_path)["payload"]["resolutions"]
        recon = {pid: v["final_root_cause_relation"] for pid, v in rc.items()}
        print(f"  reconciliation loaded: {len(recon)} resolved disputes -> same_defect_rate_reconciled added")

    print(f"analyzing {len(units)} adjudicated findings over {n_records} records, reps={a.reps} ...")
    geom = geometric_ladder(units, n_records, a.reps); print("  geometric ladder done")
    sem = semantic(units, a.reps, recon); print("  semantic done")
    agr = agreement(units, a.reps); print("  agreement done")
    m100 = matched100(units, records_all, a.reps); print("  matched-100 endpoints done")
    sens = sensitivity(units, a.reps); print("  sensitivity done")

    os.makedirs(OUT_DIR, exist_ok=True)
    def w(name, kind, payload):
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as fh:
            json.dump(stamped(prov, kind, payload), fh, indent=1)
    w("GEOMETRIC_LADDER_V3.json", "geometric_ladder", geom)
    w("SEMANTIC_ADJUDICATION_V3.json", "semantic_adjudication", sem)
    w("AGREEMENT_V3.json", "agreement", agr)
    w("MATCHED100_STATS_V3.json", "matched100_stats", m100)
    w("SENSITIVITY_V3.json", "sensitivity", sens)

    table_inputs = {"geometric_per_tool": {t: {e: geom["per_tool"][t][e] for e in GEOM_EVENTS}
                                           for t in TOOLS if geom["per_tool"].get(t, {}).get("n_findings")},
                    "primary_effect": geom["primary_effect"],
                    "conditional_transition": geom["conditional_transition"],
                    "same_defect_per_tool": {t: sem["per_tool"][t].get("same_defect_rate")
                                             for t in TOOLS if sem["per_tool"].get(t, {}).get("n")},
                    "kappa": {ax: agr["per_axis"][ax]["cohen_kappa"] for ax in agr["per_axis"]},
                    "endpoints": m100["per_tool"]}
    w("TABLE_INPUTS_V3.json", "table_inputs", table_inputs)
    with open(os.path.join(OUT_DIR, "LATEX_MACROS_V3.tex"), "w", encoding="utf-8") as fh:
        fh.write(latex_macros(geom, sem, agr, m100))

    # console headline
    print("\n== GEOMETRIC LADDER (primary), per tool, top-3 ==")
    print(f"{'tool':9}{'n':>5}  {'patched_file':>22}{'exact_line':>22}{'drop->exact [95% CI]':>28}")
    for tool in ("wisp", "semgrep", "wpt"):
        pt = geom["per_tool"].get(tool, {})
        if not pt.get("n_findings"):
            continue
        de = geom["primary_effect"][tool]["drop_to_exact_changed_line"]
        print(f"{tool:9}{pt['n_findings']:>5}  {_fmt_ci(pt['in_patched_file']):>22}"
              f"{_fmt_ci(pt['on_exact_changed_line']):>22}"
              f"   {de['diff']:.3f} [{de['ci95'][0]:.3f}, {de['ci95'][1]:.3f}]")
    print("\n== SEMANTIC (human), same-defect rate, per tool ==")
    for tool in ("wisp", "semgrep", "wpt"):
        st = sem["per_tool"].get(tool, {})
        if st.get("n"):
            print(f"  {tool:9} same_defect={_fmt_ci(st['same_defect_rate'])}  "
                  f"class_match(geom)={_fmt_ci(st['class_match_rate_geometric'])}")
    print("\n== AGREEMENT ==")
    for ax in ("class_relation", "root_cause_relation"):
        k = agr["per_axis"][ax]["cohen_kappa"]
        print(f"  {ax:22} kappa={k['kappa']} CI{k['ci95']} raw={k['raw_agreement']}")
    print(f"  disagreements needing reconciliation (root_cause): "
          f"{agr['disagreements_needing_reconciliation']['root_cause_relation']}/{len(units)}")
    print(f"\nwrote 7 outputs -> {OUT_DIR}")


if __name__ == "__main__":
    main()

