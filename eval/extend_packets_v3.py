#!/usr/bin/env python3
"""Build tier-2 packets for findings the population has and the packet set does not.

The 710 packets were built on 2026-08-03. The engine moved to v1.3 on 08-11 and the finding
population was regenerated on 08-13, so the two drifted: 14 packets point at findings the current
population no longer contains, and 5 current findings have no packet at all. `defect_study_v3`
draws from the current population and refuses to build a partial study, which is correct and is
also a dead end until the missing packets exist.

This closes that gap the only honest way, by building the missing packets from the same archives,
with the same slice geometry, the same claim normalization and the same blinding secret as the
originals, so a reviewer cannot tell an 08-03 packet from one written today. It writes no judgment.

Packets whose finding has left the population are not deleted here. They are simply never drawn,
because the sampling frame is the current population, and a packet nobody draws costs nothing. The
count is reported so the drift stays visible rather than silently absorbed.

    python3 -m eval.extend_packets_v3 --dry-run
    python3 -m eval.extend_packets_v3
"""
from __future__ import annotations
import argparse, json, os, sys, difflib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C
from eval.datasets.patchstack import load_rows
from eval.localize import _unzip, _php_map, _fn_ranges

SYS_ROOT = C.SYS_ROOT
POP = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
PACKETS = os.path.join(C.TIER2_DIR, "PACKETS.json")
KEY = os.path.join(C.TIER2_DIR, "BLINDING_KEY.json")
PKT_DIR = os.path.join(C.TIER2_DIR, "packets")
TOPK = 3
DIFF_CONTEXT = 2


def _population():
    out = []
    with open(POP, encoding="utf-8") as fh:
        for ln in fh:
            if ln.strip():
                r = json.loads(ln)
                if r["rank"] <= TOPK:
                    out.append(r)
    return out


def _relevant_diff(vroot, proot, relfile):
    """The vendor's change to the file the finding names, uncut except for context width."""
    vmap, pmap = _php_map(vroot), _php_map(proot)
    vp, pp = vmap.get(relfile), pmap.get(relfile)
    if vp is None and pp is None:
        return "(file not present in either archive)"
    v = open(vp, encoding="utf-8", errors="replace").read().split("\n") if vp else []
    p = open(pp, encoding="utf-8", errors="replace").read().split("\n") if pp else []
    body = [l for l in difflib.unified_diff(v, p, lineterm="", n=DIFF_CONTEXT)
            if not l.startswith(("---", "+++"))]
    return "\n".join(body) if body else "(no textual change in this file)"


def _claim(rec):
    """The finding's claim with every token that could name its producer removed."""
    sink, _ = C.normalize_sink(rec.get("sink", ""))
    trace = []
    for t in rec.get("trace") or []:
        trace.append(C.scrub(t if isinstance(t, str) else json.dumps(t)))
    return {
        "reported_classes": rec.get("reported_classes") or [],
        "message": C.scrub(rec.get("message", "")),
        "source": C.scrub(rec.get("source", "")),
        "sink": sink,
        "trace": trace,
    }


def _packet_md(p):
    t = p["normalized_claim"]
    trace = "\n".join(f"- {x}" for x in t["trace"]) or "- (none reported)"
    return f"""# Finding packet `{p['packet_id'][:16]}…`

- packet_id: `{p['packet_id']}`
- defect card (record_uid): `{p['defect_card_record_uid']}`  ({p['slug']} {p['cve']})
- advisory class: **{p['advisory_class']}**
- finding location: `{p['finding_file']}` line **{p['finding_line']}**
- vulnerable archive sha256: `{p['vulnerable_archive_sha256']}`
- patched archive sha256: `{p['patched_archive_sha256']}`
- inclusion probability: {p['inclusion_probability']}

## Finding's normalized claim
- reported class(es): {t['reported_classes']}
- message: {t['message']}
- source: {t['source']}
- sink / sensitive op: {t['sink']}

### Reported trace
{trace}

## Finding code context (wide)
```php
{p['finding_code_context']}
```

## Full relevant diff (uncut)
```diff
{p['relevant_diff']}
```

---
You do not know which tool produced this finding. Judge it against the defect card on the
five separate axes in the rubric. Do not guess a tool. Fill your own sheet.
"""


def _seed_label_slots(packets):
    """Every packet needs a slot in both tier-2 sheets, or the importer rejects its row.

    This is its own step, not a tail of the build step. It was written as a tail and the early
    return on "nothing to build" skipped it, so a packet set that was already complete kept two
    sheets that were not. Seeds EMPTY slots only, never a value, and only where none exists.
    """
    seeded = 0
    for tag in ("A", "B"):
        sp = os.path.join(C.TIER2_DIR, f"reviewer_{tag}_findings.json")
        env = C.read_json(sp)
        labels = env["payload"]["labels"]
        before = len(labels)
        for p in packets:
            if p["packet_id"] not in labels:
                labels[p["packet_id"]] = {ax: "" for ax in C.TIER2_LABEL_AXES}
                labels[p["packet_id"]]["notes"] = ""
                seeded += 1
        if len(labels) != before:
            C.write_json(sp, C.envelope("tier2_reviewer_findings", env["payload"]))
    if seeded:
        print(f"seeded {seeded} empty label slot(s) across the two tier-2 sheets")
    return seeded


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    pk_env = C.read_json(PACKETS)
    key_env = C.read_json(KEY)
    packets = pk_env["payload"]["packets"]
    key = key_env["payload"]
    secret = key["blinding_secret"]
    kmap = key["map"]

    have_uid = {e["finding_uid"] for e in kmap.values()}
    pop = _population()
    frame = {(r["slug"], r["cve"]) for r in
             [p for p in pop if (p["slug"], p["cve"]) in {(q["slug"], q["cve"]) for q in packets}]}
    missing = [r for r in pop if r["finding_uid"] not in have_uid and (r["slug"], r["cve"]) in frame]

    live = {(r["slug"], r["cve"], str(r["file"]), int(r["line"])) for r in pop}
    orphan = [p for p in packets
              if (p["slug"], p["cve"], str(p["finding_file"]), int(p["finding_line"])) not in live]

    print(f"packets on disk            : {len(packets)}")
    print(f"packets whose finding is gone from the population: {len(orphan)} (never drawn, kept)")
    print(f"current findings with no packet                  : {len(missing)}")
    _seed_label_slots(packets)
    if not missing:
        print("nothing to build.")
        return 0
    for r in missing:
        print(f"  {r['slug'][:34]:36} {r['cve']:16} rank{r['rank']} {r['file']}:{r['line']}")
    if args.dry_run:
        return 0

    rows = {(r["slug"], r["cve"]): r for r in load_rows()}
    rec_of = {}
    for p in packets:
        rec_of[(p["slug"], p["cve"])] = p["defect_card_record_uid"]

    built = 0
    by_record = {}
    for r in missing:
        by_record.setdefault((r["slug"], r["cve"]), []).append(r)

    for (slug, cve), group in sorted(by_record.items()):
        row = rows.get((slug, cve))
        if row is None:
            raise SystemExit(f"no dataset row for {slug} {cve}")
        vroot, proot = _unzip(row["vuln_zip"]), _unzip(row["patched_zip"])
        if not vroot or not proot:
            raise SystemExit(f"could not open archives for {slug} {cve}")
        vmap = _php_map(vroot)
        for r in group:
            relfile = str(r["file"])
            src = vmap.get(relfile)
            if src is None:
                ctx = "(file not present in the vulnerable archive)"
            else:
                text = open(src, encoding="utf-8", errors="replace").read()
                ctx = C.wide_slice(text, int(r["line"]), _fn_ranges(src))
            pid = C.packet_id(r["finding_uid"], secret)
            if pid in kmap:
                continue
            p = {
                "packet_id": pid,
                "defect_card_record_uid": rec_of.get((slug, cve), r["record_uid"]),
                "slug": slug,
                "cve": cve,
                "advisory_class": r["advisory_class"],
                "finding_file": relfile,
                "finding_line": int(r["line"]),
                "vulnerable_archive_sha256": r["archive_hashes"]["vulnerable"],
                "patched_archive_sha256": r["archive_hashes"]["patched"],
                "inclusion_probability": 1.0,
                "sampling_frame": "top3-current-population",
                "normalized_claim": _claim(r),
                "finding_code_context": ctx,
                "relevant_diff": _relevant_diff(vroot, proot, relfile),
            }
            packets.append(p)
            # The key entry has to carry every field the 08-03 entries carry. A short entry does not
            # fail at write time, it fails 200 lines later inside the workbook builder.
            kmap[pid] = {"finding_uid": r["finding_uid"], "record_uid": r["record_uid"],
                         "tool": r["tool"], "slug": slug, "cve": cve,
                         "advisory_class": r["advisory_class"], "rank": int(r["rank"])}
            with open(os.path.join(PKT_DIR, pid + ".md"), "w", encoding="utf-8") as fh:
                fh.write(_packet_md(p))
            built += 1

    # Every entry must look the same shape as every other, or a consumer joins on a field that is
    # present in 710 rows and absent in 6.
    fields = {frozenset(e) for e in kmap.values()}
    if len(fields) != 1:
        raise SystemExit("blinding key entries disagree on their fields: "
                         + " | ".join(",".join(sorted(f)) for f in fields))
    _seed_label_slots(packets)
    packets.sort(key=lambda p: p["packet_id"])
    pk_env["payload"]["n_packets"] = len(packets)
    C.write_json(PACKETS, C.envelope("tier2_packets", pk_env["payload"]))
    C.write_json(KEY, C.envelope("tier2_blinding_key", key))
    print(f"built {built} packet(s); packet set is now {len(packets)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
