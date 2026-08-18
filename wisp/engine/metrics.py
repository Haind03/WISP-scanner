"""Metrics against known-CVE ground truth.

Ground-truth CSV columns (header required):
    plugin_slug, version, vuln_class, cve, file_hint
`file_hint` and `version` may be blank. Matching is at the
(plugin_slug, vuln_class) granularity for the MVP: a plugin known to have an
SQLi counts as a positive if the pipeline reports an SQLi in that plugin.

We compute precision/recall and the false-positive drop between the Semgrep-only
baseline and the AI-verified set.
"""
from __future__ import annotations
import csv
from collections import defaultdict


def load_ground_truth(path: str) -> dict[str, set[str]]:
    gt: dict[str, set[str]] = defaultdict(set)
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                slug = (row.get("plugin_slug") or "").strip()
                cls = (row.get("vuln_class") or "").strip().lower()
                if slug and cls:
                    gt[slug].add(cls)
    except FileNotFoundError:
        pass
    return gt


def _plugin_classes(findings) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        out[f["plugin_slug"]].add(f["vuln_class"])
    return out


def evaluate(baseline_findings, verified_findings, ground_truth) -> dict:
    """baseline = all Semgrep findings; verified = AI-confirmed subset.
    Both are lists of finding dicts. Returns a metrics report."""
    gt_plugins = set(ground_truth)

    def score(findings, label):
        by_plugin = _plugin_classes(findings)
        tp = fp = fn = 0
        matched = []
        for slug, gt_classes in ground_truth.items():
            found = by_plugin.get(slug, set())
            hit = gt_classes & found
            if hit:
                tp += 1
                matched.append(slug)
            else:
                fn += 1
        # Findings in GT plugins whose class is NOT a known class -> candidate FP.
        # (MVP proxy: extra classes in GT plugins beyond the known one.)
        fp_classes = 0
        for slug in gt_plugins:
            extra = by_plugin.get(slug, set()) - ground_truth.get(slug, set())
            fp_classes += len(extra)
        prec = tp / (tp + fp_classes) if (tp + fp_classes) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        return {
            "label": label,
            "plugins_with_gt": len(ground_truth),
            "detected_plugins": tp,
            "missed_plugins": fn,
            "extra_class_flags_in_gt_plugins": fp_classes,
            "precision_proxy": round(prec, 3),
            "recall": round(rec, 3),
            "f1_proxy": round(f1, 3),
            "total_findings": len(findings),
        }

    base = score(baseline_findings, "semgrep_only")
    ver = score(verified_findings, "semgrep+ai")
    fp_drop = base["total_findings"] - ver["total_findings"]
    fp_drop_pct = (fp_drop / base["total_findings"] * 100) if base["total_findings"] else 0.0
    return {
        "baseline": base,
        "ai_verified": ver,
        "false_positive_drop_count": fp_drop,
        "false_positive_drop_pct": round(fp_drop_pct, 1),
        "recall_retained": ver["recall"] >= base["recall"] - 1e-9,
    }
