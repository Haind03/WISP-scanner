"""Acceptance tests for the adjudication protocol v3 (Prompt 3).

These verify the MACHINERY a human-labeled protocol needs, and that no program label is ever
produced. They build a small self-contained fixture (three blinded packets, a population, empty
sheets) under a temp dir, point the protocol modules at it, and exercise the real validator and
scorer. They are expected to PASS.

What they assert:
  1. defect-card and finding sheets ship EMPTY (no program-authored labels);
  2. a packet leaks no tool name, no tool-native rule id, no automatic geometric label;
  3. packet_id is unlinkable to the tool (HMAC under a secret) and stable given the secret;
  4. every packet maps to a defect card and to a population finding (referential integrity);
  5. a duplicate packet_id fails validation (scoring would abort);
  6. the five label axes are separate; there is no single mixed "UR"/verdict column;
  7. the scorer REFUSES to run on empty sheets (it will not synthesize a ground truth);
  8. with human labels it computes agreement + Cohen's kappa, and only opens the sealed key when
     both tiers are locked;
  9. the reviewer-metadata template exposes expertise / independence / COI fields.

    python3 -m eval.tests.revision_v2.test_adjudication_v3
"""
from __future__ import annotations
import os, sys, json, tempfile, shutil, importlib

from ._common import REPO, Evidence

from eval import adjudication_v3_common as C
from eval import validate_adjudication_v3 as V
from eval import score_adjudication_v3 as S
from eval import patch_geometry as pg

# (finding_uid, tool, slug, cve, class, file, line); record_uid is DERIVED via pg.record_uid so it
# satisfies the validator's record_uid == record_uid(slug, cve) check, like the real pipeline.
FINDINGS = [
    ("fuid-aaa", "wisp", "demo-a", "CVE-0000-1", "xss", "src/a.php", 10),
    ("fuid-bbb", "semgrep", "demo-a", "CVE-0000-1", "xss", "src/a.php", 22),
    ("fuid-ccc", "wpt", "demo-b", "CVE-0000-2", "sqli", "src/b.php", 5),
]
SECRET = "0" * 64


def _build_fixture(tmp, dup=False, labels=None, locks=False):
    """Write a minimal but real Tier-1 + Tier-2 artifact set under tmp and point C at it."""
    C.ADJ_DIR = tmp
    C.TIER1_DIR = os.path.join(tmp, "tier1")
    C.TIER2_DIR = os.path.join(tmp, "tier2")
    C.POPULATION = os.path.join(tmp, "pop.jsonl")
    os.makedirs(C.TIER1_DIR, exist_ok=True)
    os.makedirs(C.TIER2_DIR, exist_ok=True)

    ru = {(slug, cve): pg.record_uid(slug, cve) for (_, _, slug, cve, *_ ) in FINDINGS}

    # population: one line per finding
    with open(C.POPULATION, "w", encoding="utf-8") as fh:
        for fuid, tool, slug, cve, cls, f, ln in FINDINGS:
            fh.write(json.dumps({"finding_uid": fuid, "tool": tool, "record_uid": ru[(slug, cve)],
                                 "rank": 1, "slug": slug, "cve": cve}) + "\n")

    # Tier 1 context + empty sheets, one card per record (record_uid derived like the real pipeline)
    seen = {}
    for _, _, slug, cve, *_ in FINDINGS:
        seen[ru[(slug, cve)]] = {"record_uid": ru[(slug, cve)], "slug": slug, "cve": cve}
    cards = list(seen.values())
    C.write_json(os.path.join(C.TIER1_DIR, "DEFECT_CARDS_CONTEXT.json"),
                 C.envelope("tier1_defect_card_context", {"records": [], "cards": cards}))
    empty_card = {k: "" for k in C.DEFECT_CARD_REVIEWER_FIELDS}
    for who in ("A", "B"):
        C.write_json(os.path.join(C.TIER1_DIR, f"reviewer_{who}_defect_cards.json"),
                     C.envelope("tier1_reviewer_sheet",
                                {"reviewer": who, "fields": C.DEFECT_CARD_REVIEWER_FIELDS,
                                 "cards": {c["record_uid"]: dict(empty_card) for c in cards}}))
    C.write_json(os.path.join(C.TIER1_DIR, "REVIEWER_METADATA_TEMPLATE.json"),
                 C.envelope("reviewer_metadata",
                            {"fields": C.REVIEWER_METADATA_FIELDS,
                             "reviewer_A": {k: "" for k in C.REVIEWER_METADATA_FIELDS},
                             "reviewer_B": {k: "" for k in C.REVIEWER_METADATA_FIELDS}}))

    # Tier 2 packets (blinded, no tool, no geometry), key, sheets
    packets, kmap = [], {}
    for fuid, tool, slug, cve, cls, f, ln in FINDINGS:
        ruid = ru[(slug, cve)]
        pid = C.packet_id(fuid, SECRET)
        packets.append({"packet_id": pid, "defect_card_record_uid": ruid, "advisory_class": cls,
                        "slug": slug, "cve": cve, "finding_file": f, "finding_line": ln,
                        "finding_code_context": "echo $_GET['x'];",
                        "normalized_claim": {"reported_classes": [cls], "message": "user input echoed",
                                             "source": "", "sink": "(sink category: echo)",
                                             "source_normalized": False, "sink_normalized": True,
                                             "trace": []},
                        "relevant_diff": "- echo $_GET['x'];\n+ echo esc_html($_GET['x']);",
                        "vulnerable_archive_sha256": "v", "patched_archive_sha256": "p",
                        "inclusion_probability": 1.0, "sampling_frame": "census-top3-matched100"})
        kmap[pid] = {"finding_uid": fuid, "record_uid": ruid, "tool": tool, "rank": 1,
                     "slug": slug, "cve": cve, "advisory_class": cls}
    if dup:                                   # plant a duplicate packet_id
        packets.append(dict(packets[0]))
    C.write_json(os.path.join(C.TIER2_DIR, "PACKETS.json"),
                 C.envelope("tier2_packets", {"n_packets": len(packets), "packets": packets}))

    ids = [p["packet_id"] for p in packets]
    def _sheet(who):
        rows = {}
        for p in packets:
            base = {ax: "" for ax in C.TIER2_LABEL_AXES}
            base["notes"] = ""
            if labels:
                base.update(labels.get((who, p["packet_id"]), {}))
            rows[p["packet_id"]] = base
        return C.envelope("tier2_reviewer_sheet",
                          {"reviewer": who, "axes": C.TIER2_LABEL_AXES,
                           "domains": C.TIER2_LABEL_DOMAINS, "labels": rows})
    for who in ("A", "B"):
        C.write_json(os.path.join(C.TIER2_DIR, f"reviewer_{who}_findings.json"), _sheet(who))
    C.write_json(os.path.join(C.TIER2_DIR, "REVIEWER_METADATA_TEMPLATE.json"),
                 C.envelope("reviewer_metadata",
                            {"fields": C.REVIEWER_METADATA_FIELDS,
                             "reviewer_A": {k: "" for k in C.REVIEWER_METADATA_FIELDS},
                             "reviewer_B": {k: "" for k in C.REVIEWER_METADATA_FIELDS}}))
    C.write_json(os.path.join(C.TIER2_DIR, "BLINDING_KEY.json"),
                 C.envelope("tier2_blinding_key", {"SEALED": "x", "blinding_secret": SECRET, "map": kmap}))
    if locks:
        C.write_json(os.path.join(C.TIER1_DIR, "LOCK.json"), {"locked": True})
        C.write_json(os.path.join(C.TIER2_DIR, "LOCK.json"), {"locked": True})
    return packets


def _run_validate():
    argv = sys.argv
    sys.argv = ["validate", "--json"]
    try:
        code = V.main()
    finally:
        sys.argv = argv
    payload = C.read_json(os.path.join(C.ADJ_DIR, "VALIDATION_REPORT.json"))["payload"]
    return code, payload


def _run_score(extra=None):
    argv = sys.argv
    sys.argv = ["score"] + (extra or [])
    try:
        code = S.main()
    finally:
        sys.argv = argv
    return code


# --------------------------------------------------------------------------- tests
def test_defect_card_and_sheets_ship_empty():
    ev = Evidence("ADJ.1 templates ship empty (no program labels)")
    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp)
        a = C.read_json(os.path.join(C.TIER1_DIR, "reviewer_A_defect_cards.json"))["payload"]
        nonempty = [(r, k) for r, card in a["cards"].items() for k, v in card.items() if str(v).strip()]
        s = C.read_json(os.path.join(C.TIER2_DIR, "reviewer_A_findings.json"))["payload"]
        filled = [(pid, k) for pid, row in s["labels"].items()
                  for k in C.TIER2_LABEL_AXES if str(row.get(k, "")).strip()]
        ev.show(f"tier1 non-empty card fields = {len(nonempty)}; tier2 pre-filled labels = {len(filled)}")
        assert not nonempty, f"defect card ships with a non-empty field: {nonempty[:3]}"
        assert not filled, f"finding sheet ships with a pre-filled label: {filled[:3]}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_packet_hides_tool_rule_id_and_geometry():
    ev = Evidence("ADJ.2 no tool / rule-id / geometry leak")
    # scrub + sink normalization
    assert "[tool]" in C.scrub("this came from Semgrep and wp-taint-scan")
    disp, norm = C.normalize_sink("php.lang.security.injection.echoed-request.echoed-request")
    ev.show(f"rule-id sink -> {disp!r} normalized={norm}")
    assert norm and "php.lang" not in disp and "echoed" in disp
    disp2, norm2 = C.normalize_sink("mysqli_query")
    assert not norm2 and disp2 == "mysqli_query"        # a plain code symbol survives

    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp)
        code, rep = _run_validate()
        by = {c["name"]: c for c in rep["checks"]}
        ev.show(f"no-tool-leak check = {by['tier2: no tool name leaks into a packet']['ok']}; "
                f"no-geometry check = {by['tier2: no automatic geometric label in a packet']['ok']}")
        assert by["tier2: no tool name leaks into a packet"]["ok"]
        assert by["tier2: no automatic geometric label in a packet"]["ok"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_packet_id_is_unlinkable_and_stable():
    ev = Evidence("ADJ.3 packet_id unlinkable to tool, stable given secret")
    fuid = "fuid-aaa"
    id1 = C.packet_id(fuid, "secretone" * 8)
    id2 = C.packet_id(fuid, "secrettwo" * 8)
    id1b = C.packet_id(fuid, "secretone" * 8)
    ev.show(f"same finding, two secrets -> different id: {id1 != id2}; same secret stable: {id1 == id1b}")
    assert id1 != id2, "packet_id must change with the secret (not brute-forceable without it)"
    assert id1 == id1b, "packet_id must be stable given the secret"
    for tool in ("wisp", "semgrep", "wpt"):
        assert tool not in id1, "packet_id must not contain the tool name"


def test_referential_integrity():
    ev = Evidence("ADJ.4 every packet -> defect card + population finding")
    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp)
        code, rep = _run_validate()
        by = {c["name"]: c for c in rep["checks"]}
        ev.show(f"validation passed = {rep['passed']}")
        assert by["tier2: every packet references a Tier-1 defect card"]["ok"]
        assert by["tier2: every packet maps to a population finding_uid"]["ok"]
        assert rep["passed"], "clean fixture must validate cleanly"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_duplicate_packet_id_fails_validation():
    ev = Evidence("ADJ.5 duplicate packet_id fails validation")
    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp, dup=True)
        code, rep = _run_validate()
        by = {c["name"]: c for c in rep["checks"]}
        ev.show(f"packet_id-unique check ok = {by['tier2: packet_id unique']['ok']}; "
                f"overall passed = {rep['passed']}")
        assert not by["tier2: packet_id unique"]["ok"], "a duplicate packet_id must fail the check"
        assert code != 0 and not rep["passed"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_five_separate_axes_no_UR_column():
    ev = Evidence("ADJ.6 five separate axes, no mixed UR/verdict")
    ev.show(f"axes = {C.TIER2_LABEL_AXES}")
    assert C.TIER2_LABEL_AXES == ["class_relation", "root_cause_relation", "evidence_quality",
                                  "confidence", "reason_code"]
    assert "UR" not in C.ROOT_CAUSE_RELATION and "verdict" not in C.TIER2_LABEL_AXES
    # the old single mixed verdict is gone: wrong-class / wrong-location / no-evidence are separate
    assert "WRONG_CLASS" in C.REASON_CODE and "LOCATION_ONLY" in C.REASON_CODE
    assert "INSUFFICIENT_EVIDENCE" in C.ROOT_CAUSE_RELATION


def test_scorer_refuses_on_empty_sheets():
    ev = Evidence("ADJ.7 scorer refuses to fabricate labels")
    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp, locks=True)              # sheets empty even though locked
        code = _run_score()
        report = os.path.join(C.ADJ_DIR, "SCORE_REPORT.json")
        ev.show(f"score exit code on empty sheets = {code}; wrote report = {os.path.isfile(report)}")
        assert code == 2, "the scorer must STOP (code 2) when no human labels are present"
        assert not os.path.isfile(report), "no score report may be written from empty sheets"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_scorer_computes_agreement_and_gates_key_on_locks():
    ev = Evidence("ADJ.8 scorer computes kappa; opens key only when locked")
    labels = {
        ("A", C.packet_id("fuid-aaa", SECRET)): {"class_relation": "MATCH", "root_cause_relation": "SAME_DEFECT",
                                                 "evidence_quality": "SUFFICIENT", "confidence": "HIGH",
                                                 "reason_code": "SAME_SOURCE_SINK"},
        ("B", C.packet_id("fuid-aaa", SECRET)): {"class_relation": "MATCH", "root_cause_relation": "SAME_DEFECT",
                                                 "evidence_quality": "SUFFICIENT", "confidence": "HIGH",
                                                 "reason_code": "SAME_SOURCE_SINK"},
        ("A", C.packet_id("fuid-bbb", SECRET)): {"class_relation": "MATCH", "root_cause_relation": "LOCATION_ONLY" and "RELATED_AREA_DIFFERENT_DEFECT",
                                                 "evidence_quality": "PARTIAL", "confidence": "MEDIUM",
                                                 "reason_code": "LOCATION_ONLY"},
        ("B", C.packet_id("fuid-bbb", SECRET)): {"class_relation": "MISMATCH", "root_cause_relation": "UNRELATED",
                                                 "evidence_quality": "PARTIAL", "confidence": "LOW",
                                                 "reason_code": "WRONG_CLASS"},
        ("A", C.packet_id("fuid-ccc", SECRET)): {"class_relation": "MATCH", "root_cause_relation": "SAME_DEFECT",
                                                 "evidence_quality": "SUFFICIENT", "confidence": "HIGH",
                                                 "reason_code": "SAME_MISSING_GUARD"},
        ("B", C.packet_id("fuid-ccc", SECRET)): {"class_relation": "MATCH", "root_cause_relation": "SAME_DEFECT",
                                                 "evidence_quality": "SUFFICIENT", "confidence": "HIGH",
                                                 "reason_code": "SAME_MISSING_GUARD"},
    }
    # unlocked: key must NOT be opened, no per-tool rates
    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp, labels=labels, locks=False)
        code = _run_score()
        rep = C.read_json(os.path.join(C.ADJ_DIR, "SCORE_REPORT.json"))["payload"]
        ev.show(f"unlocked: exit={code}, per_tool={rep['per_tool']}, "
                f"class_relation kappa={rep['inter_annotator']['class_relation']['cohen_kappa']}")
        assert code == 0
        assert rep["per_tool"] is None, "per-tool rates must be withheld until both tiers are locked"
        assert rep["inter_annotator"]["root_cause_relation"]["n"] == 3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # locked: key opened, per-tool same_defect rates present
    tmp = tempfile.mkdtemp(prefix="adjv3_")
    try:
        _build_fixture(tmp, labels=labels, locks=True)
        code = _run_score()
        rep = C.read_json(os.path.join(C.ADJ_DIR, "SCORE_REPORT.json"))["payload"]
        ev.show(f"locked: per_tool={rep['per_tool']}")
        assert code == 0 and rep["per_tool"] is not None
        assert rep["per_tool"]["wisp"]["same_defect_rate"] == 1.0     # aaa agreed SAME_DEFECT
        assert rep["per_tool"]["semgrep"]["same_defect_rate"] == 0.0  # bbb not agreed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_reviewer_metadata_captures_independence():
    ev = Evidence("ADJ.9 reviewer metadata: expertise / independence / COI")
    ev.show(f"metadata fields = {C.REVIEWER_METADATA_FIELDS}")
    for need in ("expertise_php_wordpress_security", "years_experience", "is_paper_author",
                 "conflict_of_interest", "knows_research_objective", "protocol_version"):
        assert need in C.REVIEWER_METADATA_FIELDS, f"metadata missing {need}"


TESTS = [
    ("ADJ.1 templates empty", test_defect_card_and_sheets_ship_empty),
    ("ADJ.2 no tool/rule/geom leak", test_packet_hides_tool_rule_id_and_geometry),
    ("ADJ.3 packet_id unlinkable", test_packet_id_is_unlinkable_and_stable),
    ("ADJ.4 referential integrity", test_referential_integrity),
    ("ADJ.5 duplicate id fails", test_duplicate_packet_id_fails_validation),
    ("ADJ.6 five separate axes", test_five_separate_axes_no_UR_column),
    ("ADJ.7 scorer refuses empty", test_scorer_refuses_on_empty_sheets),
    ("ADJ.8 kappa + lock gate", test_scorer_computes_agreement_and_gates_key_on_locks),
    ("ADJ.9 reviewer metadata", test_reviewer_metadata_captures_independence),
]


def main() -> int:
    import traceback
    print("=" * 78)
    print("ADJUDICATION V3 ACCEPTANCE  (each test SHOULD PASS)")
    print("=" * 78)
    passed = 0
    for title, fn in TESTS:
        try:
            fn()
            passed += 1
            print(f"  [PASS  ] {title}")
        except AssertionError as e:
            msg = (str(e).splitlines() or ["(no message)"])[0]
            print(f"  [FAIL  ] {title}\n           -> {msg[:140]}")
        except Exception as e:
            traceback.print_exc()
            print(f"  [ERROR ] {title}\n           -> {type(e).__name__}: {e}")
    print("-" * 78)
    print(f"  {passed}/{len(TESTS)} acceptance tests passed.")
    print("=" * 78)
    return 0 if passed == len(TESTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
