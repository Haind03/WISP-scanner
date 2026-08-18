#!/usr/bin/env python3
"""Shared schema, blinding, and hygiene helpers for the adjudication protocol v3.

The v3 protocol is two-tier and human-labeled. NOTHING in this module or its callers may generate a
ground-truth label or simulate a reviewer. Every human field is emitted EMPTY. The only things a
program produces are: defect-card context, blinded finding packets, empty reviewer sheets, a sealed
blinding key, validation reports, and content hashes.

Design rules enforced here:
  * five SEPARATE label axes, never a single mixed "UR" label;
  * blinded packet ids are HMAC-SHA256 under a per-build random secret, so a packet id cannot be
    brute-forced back to a tool and packets are joined by id, never by row position;
  * a tool name or a tool-native rule id never reaches a reviewer packet;
  * automatic geometric labels never reach a reviewer packet (no anchoring);
  * every artifact carries a schema version, a protocol version, and a content hash.
"""
from __future__ import annotations
import os, re, sys, json, hmac, hashlib, secrets

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
SYS_ROOT = os.path.dirname(ROOT)

SCHEMA_VERSION = "adjv3.1"
PROTOCOL_VERSION = "adjudication-v3"

ADJ_DIR = os.path.join(SYS_ROOT, "revision-cns-v2", "adjudication")
TIER1_DIR = os.path.join(ADJ_DIR, "tier1")
TIER2_DIR = os.path.join(ADJ_DIR, "tier2")
POPULATION = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
LADDER = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "LADDER_V3.json")

# ---------------------------------------------------------------- label vocabularies (Tier 2)
# Five separate axes. A blank value is the only valid pre-human state; a program must never fill one.
CLASS_RELATION = ["MATCH", "MISMATCH", "UNCERTAIN"]
ROOT_CAUSE_RELATION = ["SAME_DEFECT", "RELATED_AREA_DIFFERENT_DEFECT", "UNRELATED", "INSUFFICIENT_EVIDENCE"]
EVIDENCE_QUALITY = ["SUFFICIENT", "PARTIAL", "INSUFFICIENT"]
CONFIDENCE = ["HIGH", "MEDIUM", "LOW"]
REASON_CODE = ["SAME_SOURCE_SINK", "SAME_MISSING_GUARD", "SAME_SENSITIVE_OPERATION",
               "LOCATION_ONLY", "WRONG_CLASS", "DIFFERENT_CALL_PATH", "PATCH_TOO_BROAD",
               "TOOL_REPORT_INCOMPLETE", "OTHER"]

TIER2_LABEL_AXES = ["class_relation", "root_cause_relation", "evidence_quality",
                    "confidence", "reason_code"]
TIER2_LABEL_DOMAINS = {"class_relation": CLASS_RELATION, "root_cause_relation": ROOT_CAUSE_RELATION,
                       "evidence_quality": EVIDENCE_QUALITY, "confidence": CONFIDENCE,
                       "reason_code": REASON_CODE}

# ---------------------------------------------------------------- defect-card human fields (Tier 1)
# Each independent expert fills these in their own file; resolution fields are filled in a third step.
DEFECT_CARD_REVIEWER_FIELDS = [
    "root_cause_summary", "security_relevant_files", "security_relevant_hunks",
    "vulnerable_statements", "source_if_known", "sink_or_sensitive_operation_if_known",
    "missing_guard_if_known", "required_privilege_if_known", "patch_mechanism", "confidence",
    "annotation",
]
DEFECT_CARD_RESOLUTION_FIELDS = ["resolution", "resolution_reason", "evidence_sources"]

REVIEWER_METADATA_FIELDS = [
    "reviewer_pseudonym", "expertise_php_wordpress_security", "years_experience",
    "start_date", "end_date", "knows_research_objective", "is_paper_author",
    "conflict_of_interest", "protocol_version",
]

# CWE derived from the advisory class label only. It is a HINT the reviewer confirms, never authority.
CLASS_TO_CWE = {
    "xss": "CWE-79", "sqli": "CWE-89", "csrf": "CWE-352", "deserial": "CWE-502",
    "rce": "CWE-94", "auth": "CWE-862", "lfi": "CWE-22", "ssrf": "CWE-918",
    "upload": "CWE-434", "other": "",
}

# Paths/files that are commonly build/vendor/asset noise. Emitted only as a mechanical HINT for the
# reviewer to consider; it is NOT a security judgment and the reviewer decides relevance.
_NON_SECURITY_HINT = re.compile(
    r"(^|/)(vendor|node_modules|assets|dist|build|languages|tests?|\.github)/|"
    r"\.(min\.js|min\.css|css|scss|map|po|mo|pot|md|txt|json|lock|svg|png|jpe?g|gif)$",
    re.I)

# tokens that would leak the producing tool if they reached a packet
_TOOL_TOKENS = re.compile(r"\b(wisp|nes|semgrep|progpilot|wp[-_ ]?taint|taint[-_ ]?scan|wpt)\b", re.I)
# a dotted rule identifier such as semgrep's "php.lang.security.injection.echoed-request"
_RULE_ID = re.compile(r"^[\w-]+(\.[\w-]+){2,}$")
_RULE_NAMESPACE = re.compile(r"\b(php\.lang|php\.security|generic\.|semgrep|progpilot)\b", re.I)


# ---------------------------------------------------------------- hashing / hygiene
def content_hash(payload) -> str:
    """Stable SHA-256 over any JSON-able payload (sorted keys, tight separators)."""
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def envelope(kind: str, payload, extra: dict | None = None) -> dict:
    """Wrap a payload with schema version, protocol version, and its content hash."""
    env = {"schema_version": SCHEMA_VERSION, "protocol_version": PROTOCOL_VERSION,
           "artifact_kind": kind, "content_hash": content_hash(payload), "payload": payload}
    if extra:
        env.update(extra)
    return env


def new_blinding_secret() -> str:
    return secrets.token_hex(32)


def packet_id(finding_uid: str, secret: str) -> str:
    """HMAC-SHA256 of the finding uid under the per-build secret. Not brute-forceable to a tool
    without the sealed secret; deterministic given the secret so a re-run reproduces the mapping."""
    return hmac.new(secret.encode(), finding_uid.encode(), hashlib.sha256).hexdigest()


def scrub(text: str) -> str:
    """Remove anything that would reveal the producing tool from reviewer-facing text."""
    if not text:
        return ""
    out = _TOOL_TOKENS.sub("[tool]", str(text))
    # drop bare dotted rule identifiers that survive as standalone tokens
    out = " ".join("[rule]" if _RULE_ID.match(tok) or _RULE_NAMESPACE.search(tok) else tok
                   for tok in out.split(" "))
    return out


def normalize_sink(sink: str):
    """Return (display_sink, was_normalized). A tool-native rule id is collapsed to a neutral sink
    category so it cannot fingerprint the tool; a plain code symbol is kept."""
    if not sink:
        return "", False
    s = str(sink).strip()
    if _RULE_ID.match(s) or _RULE_NAMESPACE.search(s):
        leaf = s.split(".")[-1].replace("-", " ").replace("_", " ").strip()
        return f"(sink category: {leaf})" if leaf else "(sink category: unspecified)", True
    return scrub(s), False


def non_security_hint(path: str) -> bool:
    return bool(_NON_SECURITY_HINT.search(path or ""))


# ---------------------------------------------------------------- population + record set
# The geometric fields contract v1 s4 rule 3 withholds credit for.
# Only the fields a rung is scored on. Descriptive fields (finding_at_top_level,
# near_insertion_boundary, distances used by the patch-shape census) are left alone: rule 3
# withholds CREDIT, it does not rewrite what the diff looks like.
GEOM_CREDIT_FIELDS = ("in_patched_file", "same_callable_as_change", "on_exact_changed_line",
                      "within_5_changed_lines", "same_diff_hunk", "class_match")


def load_population(topk: int | None = None, failure_policy: str = "contract") -> list[dict]:
    """The finding population, with contract v1 s4 rule 3 applied by default.

    Rule 3 says a record whose WISP analysis did not converge is a miss over the full
    denominator. The ladder used to ignore it, so on the matched sample 22 records that
    stopped at a bounded approximation were credited as clean successes, while the
    equal-budget matrix built from the same contract scored them as misses. One rule, applied
    in one place, is what stops two tables disagreeing about the same record.

    failure_policy:
      "contract" - rule 3 applied: a non-converged WISP record's findings stay in the
                   denominator and are credited at no geometric rung. This is the headline.
      "kept"     - rule 3 ignored, i.e. the pre-contract behaviour. This is the robustness
                   arm s4 also requires, and the only other value that may be passed.
    """
    if failure_policy not in ("contract", "kept"):
        raise ValueError(f"failure_policy must be 'contract' or 'kept', got {failure_policy!r}")
    with open(POPULATION, encoding="utf-8") as fh:
        pop = [json.loads(l) for l in fh if l.strip()]
    rows = [r for r in pop if topk is None or r["rank"] <= topk]
    if failure_policy == "kept":
        return rows
    out = []
    for r in rows:
        if r.get("tool") == "wisp" and r.get("wisp_converged") is False:
            r = dict(r)
            r["credit_withheld_non_convergence"] = True
            for f in GEOM_CREDIT_FIELDS:
                if f in r:
                    r[f] = False
        out.append(r)
    return out


def load_manifest_records() -> list[str]:
    """The authoritative record key list (slug|cve) the geometry run covered."""
    return list(json.load(open(LADDER, encoding="utf-8")).get("records", []))


def read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, ensure_ascii=False)


def wide_slice(text: str, line: int, ranges: list[tuple[int, int]],
               pad: int = 6, cap: int = 140) -> str:
    """Code context for a finding. Prefer the whole enclosing function; fall back to a generous
    window; never the +/-4 lines the old sheet used. Long functions are shown head + region around
    the line with an explicit omission marker, so inter-procedural flow stays legible."""
    lines = text.split("\n")
    n = len(lines)
    if not line or line < 1:
        line = 1
    enc = None
    for s, e in ranges:
        if s <= line <= e and (enc is None or (e - s) < (enc[1] - enc[0])):
            enc = (s, e)
    if enc:
        s, e = enc
    else:
        s, e = max(1, line - 25), min(n, line + 25)

    def fmt(a, b):
        return [f"{i:6}: {lines[i-1]}" for i in range(a, b + 1) if 1 <= i <= n]

    if (e - s) <= cap:
        body = fmt(s, e)
    else:
        head = fmt(s, min(e, s + 12))
        region = fmt(max(s, line - pad), min(e, line + pad))
        body = head + [f"       ... {max(0, (line - pad) - (s + 12) - 1)} lines omitted within the same function ..."] + region
    return "\n".join(body)
