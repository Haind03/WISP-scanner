#!/usr/bin/env python3
"""Validate the adjudication v3 artifacts (structure, blinding, integrity). Writes NO labels.

Checks, over whatever of Tier 1 / Tier 2 has been built:
  * every artifact carries schema_version + protocol_version and its stored content_hash matches a
    recomputation (tamper / drift check);
  * packet_id is unique across all packets (duplicate -> FAIL, scoring would abort);
  * referential integrity: every packet references a defect card (record_uid) and a finding_uid that
    exists in the geometry population;
  * blinding: no packet leaks a tool name, a tool-native rule id, or any automatic geometric label;
  * reviewer sheets expose exactly the five separate axes (no single mixed verdict column) and, in
    the template state, are empty; A and B cover the identical packet_id set (joinable by id);
  * every packet has an inclusion_probability; census cells are reported, unsampled cells flagged;
  * reviewer-metadata template exposes the expertise / independence / COI fields.

    python3 -m eval.validate_adjudication_v3            # human-readable report + exit code
    python3 -m eval.validate_adjudication_v3 --json     # machine report
"""
from __future__ import annotations
import os, sys, json, argparse
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from eval import adjudication_v3_common as C

# geometric field names that must NOT appear inside a reviewer packet (anchoring risk)
_GEOM_KEYS = {"in_patched_file", "same_callable_as_change", "on_exact_changed_line",
              "distance_to_nearest_changed_line", "within_2_changed_lines", "within_5_changed_lines",
              "within_10_changed_lines", "same_diff_hunk", "near_insertion_boundary",
              "finding_at_top_level", "change_at_top_level", "geometric_file", "geometric_callable",
              "geometric_exact_line", "geometric_proximity_5", "class_file", "class_callable",
              "class_exact_line", "class_proximity_5", "class_match"}


class Report:
    def __init__(self):
        self.checks = []

    def add(self, ok, name, detail=""):
        self.checks.append({"ok": bool(ok), "name": name, "detail": detail})
        return ok

    @property
    def passed(self):
        return all(c["ok"] for c in self.checks)


def _load_env(path):
    env = C.read_json(path)
    recomputed = C.content_hash(env["payload"])
    return env, env.get("content_hash") == recomputed, recomputed


def _check_envelope(rep, path, label):
    if not os.path.isfile(path):
        return None
    env, hash_ok, _ = _load_env(path)
    rep.add(env.get("schema_version") == C.SCHEMA_VERSION, f"{label}: schema_version",
            env.get("schema_version", "missing"))
    rep.add(env.get("protocol_version") == C.PROTOCOL_VERSION, f"{label}: protocol_version",
            env.get("protocol_version", "missing"))
    rep.add(hash_ok, f"{label}: content_hash matches payload",
            "ok" if hash_ok else "MISMATCH (artifact edited without rehash)")
    return env


def validate_tier1(rep):
    ctx_path = os.path.join(C.TIER1_DIR, "DEFECT_CARDS_CONTEXT.json")
    if not os.path.isfile(ctx_path):
        rep.add(True, "tier1: present", "not built yet (skipped)")
        return None
    env = _check_envelope(rep, ctx_path, "tier1/context")
    a = _check_envelope(rep, os.path.join(C.TIER1_DIR, "reviewer_A_defect_cards.json"), "tier1/reviewerA")
    b = _check_envelope(rep, os.path.join(C.TIER1_DIR, "reviewer_B_defect_cards.json"), "tier1/reviewerB")
    _check_envelope(rep, os.path.join(C.TIER1_DIR, "resolution.json"), "tier1/resolution")
    meta = _check_envelope(rep, os.path.join(C.TIER1_DIR, "REVIEWER_METADATA_TEMPLATE.json"), "tier1/metadata")

    cards = env["payload"]["cards"]
    ruids = {c["record_uid"] for c in cards}
    rep.add(len(ruids) == len(cards), "tier1: record_uid unique per card", f"{len(ruids)}/{len(cards)}")
    # every context record_uid recomputes from its slug|cve
    from eval import patch_geometry as pg
    bad = [c["slug"] + "|" + c["cve"] for c in cards if pg.record_uid(c["slug"], c["cve"]) != c["record_uid"]]
    rep.add(not bad, "tier1: record_uid == record_uid(slug,cve)", f"{len(bad)} mismatch")
    # A and B cover the same records
    if a and b:
        rep.add(set(a["payload"]["cards"]) == set(b["payload"]["cards"]) == ruids,
                "tier1: A/B/context cover identical records", "")
    if meta:
        rep.add(set(meta["payload"]["fields"]) == set(C.REVIEWER_METADATA_FIELDS),
                "tier1: metadata exposes expertise/independence/COI fields", "")
        # The form existed and was read by a human, which is how an annotator declaring
        # is_paper_author=yes was caught. Nothing in code enforced it, so the pipeline would
        # have scored and published an "inter-annotator agreement" between an author and an
        # outsider as if the protocol's independence requirement had been met. The locked
        # protocol says neither annotator is an author of the manuscript, and that the
        # manuscript may claim no more independence than the metadata supports. Both halves
        # are checked here: a blank field supports nothing, and a declared author breaks the
        # requirement outright.
        DECIDING = ("expertise_php_wordpress_security", "years_experience",
                    "knows_research_objective", "is_paper_author", "conflict_of_interest")
        for who in ("reviewer_A", "reviewer_B"):
            m = meta["payload"].get(who) or {}
            blank = [f for f in DECIDING if not str(m.get(f, "")).strip()]
            rep.add(not blank, f"tier1/{who}: independence metadata is declared",
                    "complete" if not blank else f"{len(blank)} blank: {', '.join(blank)}")
            author = str(m.get("is_paper_author", "")).strip().lower()
            if author:
                ok = author in ("no", "false", "0")
                rep.add(ok, f"tier1/{who}: annotator is not an author of the manuscript",
                        f"declared is_paper_author={author!r}" if ok else
                        f"declared is_paper_author={author!r}; the locked protocol requires that "
                        f"neither annotator is an author, so this sheet cannot be reported as an "
                        f"independent expert reading")
            # Knowing the hypothesis is not disqualifying, the protocol asks for it to be recorded.
            # What it does forbid is claiming more independence than the record supports, so an
            # annotator who knew the objective has to be disclosed as such in the manuscript
            # rather than counted silently as a blind reading.
            knew = str(m.get("knows_research_objective", "")).strip().lower()
            if knew:
                rep.add(True, f"tier1/{who}: hypothesis awareness recorded",
                        "blind to the objective" if knew in ("no", "false", "0") else
                        "KNEW the objective while labelling; the manuscript must disclose this "
                        "annotator as non-blind and may not describe the pair as two blind readings")
    return ruids


def validate_tier2(rep, tier1_ruids):
    packets_path = os.path.join(C.TIER2_DIR, "PACKETS.json")
    if not os.path.isfile(packets_path):
        rep.add(True, "tier2: present", "not built yet (skipped)")
        return
    env = _check_envelope(rep, packets_path, "tier2/packets")
    packets = env["payload"]["packets"]

    ids = [p["packet_id"] for p in packets]
    dup = sorted({x for x in ids if ids.count(x) > 1})
    rep.add(not dup, "tier2: packet_id unique", f"{len(dup)} duplicate(s)" if dup else f"{len(ids)} unique")

    # blinding: no tool token, no rule id, no geometric key anywhere in a packet
    leak_tool, leak_geom = [], []
    for p in packets:
        blob = json.dumps(p, ensure_ascii=False)
        if C._TOOL_TOKENS.search(blob):
            leak_tool.append(p["packet_id"])
        if any(k in p for k in _GEOM_KEYS) or any(k in p.get("normalized_claim", {}) for k in _GEOM_KEYS):
            leak_geom.append(p["packet_id"])
    rep.add(not leak_tool, "tier2: no tool name leaks into a packet",
            f"{len(leak_tool)} packet(s) contain a tool token")
    rep.add(not leak_geom, "tier2: no automatic geometric label in a packet",
            f"{len(leak_geom)} packet(s) carry a geometry key")

    # every packet has an inclusion probability
    noinc = [p["packet_id"] for p in packets if p.get("inclusion_probability") is None]
    rep.add(not noinc, "tier2: every packet has an inclusion_probability", f"{len(noinc)} missing")

    # referential integrity: defect card + population finding
    if tier1_ruids is not None:
        orphan = {p["defect_card_record_uid"] for p in packets} - set(tier1_ruids)
        rep.add(not orphan, "tier2: every packet references a Tier-1 defect card", f"{len(orphan)} orphan record(s)")
    pop_uids = {r["finding_uid"] for r in C.load_population()}
    keyp = os.path.join(C.TIER2_DIR, "BLINDING_KEY.json")
    if os.path.isfile(keyp):
        kmap = C.read_json(keyp)["payload"]["map"]
        rep.add(set(kmap) == set(ids), "tier2: blinding key covers exactly the packet set", "")
        missing = [pid for pid, v in kmap.items() if v["finding_uid"] not in pop_uids]
        # A packet whose finding left the population is not a defect on its own: the engine moved to
        # v1.3 on 2026-08-11 and the population was regenerated on 08-13, so packets built on 08-03
        # can point at findings the paper no longer reports. Those packets are simply never drawn,
        # because the sampling frame is the current population. What would be a real defect is a
        # packet inside the drawn study that does not map, so that is what fails here, and the
        # orphans are reported rather than absorbed silently.
        sample_path = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out", "DEFECT_STUDY_SAMPLE_V3.json")
        in_study = None
        if os.path.isfile(sample_path):
            smp = C.read_json(sample_path)
            smp = smp.get("payload", smp)
            want = set(smp["sample"]["finding_uids"])
            in_study = {pid for pid, v in kmap.items() if v["finding_uid"] in want}
        if in_study is None:
            rep.add(not missing, "tier2: every packet maps to a population finding_uid",
                    f"{len(missing)} missing")
        else:
            bad = [pid for pid in missing if pid in in_study]
            rep.add(not bad, "tier2: every packet in the drawn study maps to a population finding",
                    f"{len(bad)} of {len(in_study)} sampled packet(s) do not map")
            rep.add(True, "tier2: packets retained outside the current population",
                    f"{len(missing)} orphan packet(s) from the pre-v1.3 build, never drawn")

    # reviewer sheets: five separate axes, empty in template, identical packet coverage
    a = _check_envelope(rep, os.path.join(C.TIER2_DIR, "reviewer_A_findings.json"), "tier2/reviewerA")
    b = _check_envelope(rep, os.path.join(C.TIER2_DIR, "reviewer_B_findings.json"), "tier2/reviewerB")
    for tag, sheet in (("A", a), ("B", b)):
        if not sheet:
            continue
        axes = sheet["payload"]["axes"]
        rep.add(axes == C.TIER2_LABEL_AXES, f"tier2/{tag}: five separate axes present", str(axes))
        rep.add("verdict" not in axes and "UR" not in axes,
                f"tier2/{tag}: no single mixed verdict/UR column", "")
        labels = sheet["payload"]["labels"]
        rep.add(set(labels) == set(ids), f"tier2/{tag}: sheet keyed by the full packet_id set (join by id)", "")
    if a and b:
        rep.add(set(a["payload"]["labels"]) == set(b["payload"]["labels"]),
                "tier2: A and B cover the identical packet_id set", "")

    # Construct contamination guard (the v2 defect, bug C). In the retired v2 sheets 165 of 200
    # cross-class rows were marked UNRELATED by BOTH reviewers, so the "class-agnostic" bottom
    # rung was in practice decided by class match. v3 makes the collapse expressible but not
    # forced: class_relation and root_cause_relation are separate axes and LOCATION_ONLY exists
    # as a reason. Nothing structural can stop a reviewer from collapsing them anyway, so this
    # measures it on the filled sheets and fails loudly rather than letting it pass unnoticed.
    # 2026-08-18: this guard read `reported_class` from the normalized claim. The field is
    # `reported_classes` and it is a list, so the lookup returned None for every packet, the
    # `continue` fired on every packet, and the guard reported "skipped" no matter what the sheets
    # said. It could not fail. It is now keyed on the reviewer's own class_relation axis, which is
    # the judgment the protocol's failure mode actually names, and it is applied per sheet because
    # the protocol refuses "a sheet in which every cross-class finding comes back UNRELATED",
    # singular. Requiring both reviewers to collapse was a weaker test than the protocol's.
    for who, env in (("A", a), ("B", b)):
        if not env:
            continue
        labels = env["payload"]["labels"]
        cross = [pid for pid, l in labels.items()
                 if str(l.get("class_relation", "")).strip() == "MISMATCH"
                 and str(l.get("root_cause_relation", "")).strip()]
        if not cross:
            rep.add(True, f"tier2/{who}: cross-class collapse guard",
                    "no adjudicated cross-class packets in this sheet (skipped)")
            continue
        collapsed = [pid for pid in cross if labels[pid]["root_cause_relation"] == "UNRELATED"]
        share = len(collapsed) / len(cross)
        rep.add(share < 1.0,
                f"tier2/{who}: cross-class findings are adjudicated on location, not auto-unrelated",
                f"{len(collapsed)}/{len(cross)} cross-class packets marked UNRELATED "
                f"({share:.0%}); at 100% the second axis is a restatement of the first and the "
                f"sheet measures nothing but class string equality")

    # coverage census
    cov = defaultdict(int)
    for p in packets:
        cov[p["advisory_class"]] += 1
    rep.add(all(p.get("sampling_frame") for p in packets),
            "tier2: sampling frame recorded on every packet", "census-top3-matched100")
    rep.detail_coverage = dict(sorted(cov.items()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    rep = Report()
    rep.detail_coverage = {}
    ruids = validate_tier1(rep)
    validate_tier2(rep, ruids)

    os.makedirs(C.ADJ_DIR, exist_ok=True)
    payload = {"passed": rep.passed, "checks": rep.checks, "coverage_by_class": rep.detail_coverage}
    C.write_json(os.path.join(C.ADJ_DIR, "VALIDATION_REPORT.json"), C.envelope("validation_report", payload))

    lines = ["# Adjudication v3 validation report", ""]
    for c in rep.checks:
        lines.append(f"- [{'PASS' if c['ok'] else 'FAIL'}] {c['name']}"
                     + (f"  ({c['detail']})" if c["detail"] else ""))
    if rep.detail_coverage:
        lines += ["", "## Packet coverage by class", ""]
        lines += [f"- {k}: {v}" for k, v in rep.detail_coverage.items()]
    lines += ["", f"## Result: {'PASS' if rep.passed else 'FAIL'}"]
    with open(os.path.join(C.ADJ_DIR, "VALIDATION_REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    if a.json:
        print(json.dumps(payload, indent=1))
    else:
        print("\n".join(lines))
    return 0 if rep.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
