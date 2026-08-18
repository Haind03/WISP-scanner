#!/usr/bin/env python3
"""Merge 8 recall shard JSONs into one full-1108 report (exact, from raw counts)."""
import json, glob, os
from collections import defaultdict

shards = sorted(glob.glob("out/shards/recall_*.json"))
assert shards, "no recall shard JSONs found"
per_class = defaultdict(lambda: [0, 0])   # cls -> [tp, total]
details, hits, n, total_findings = [], 0, 0, 0
for sp in shards:
    d = json.load(open(sp))
    for cls, v in d["per_class"].items():
        per_class[cls][0] += v["tp"]
        per_class[cls][1] += v["total"]
    hits += d["hits"]
    n += d["n_plugins"]
    for det in d["details"]:
        details.append(det)
        total_findings += det.get("n_findings", 0)

rep = {
    "n_plugins": n,
    "plugin_class_recall": round(hits / n, 4) if n else 0,
    "hits": hits,
    "findings_per_plugin": round(total_findings / n, 2) if n else 0,
    "per_class": {c: {"recall": round(tp / tot, 3) if tot else 0, "tp": tp, "total": tot}
                  for c, (tp, tot) in sorted(per_class.items())},
    "details": details,
    "_shards": len(shards),
}
json.dump(rep, open("out/recall_full.json", "w"), indent=2)
print(f"merged {len(shards)} shards -> {n} plugins")
print(f"plugin_class_recall = {rep['plugin_class_recall']}  (hits {hits})")
print(f"findings_per_plugin = {rep['findings_per_plugin']}")
print("per_class recall:")
for c, v in rep["per_class"].items():
    print(f"  {c:10} {v['recall']:.3f}  ({v['tp']}/{v['total']})")
