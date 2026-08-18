"""Normalize and rank wp-taint-scan JSON findings for WISP evaluations.

All evaluation entry points must use this module.  wp-taint-scan reports the
finding location under ``start.line`` and may provide a more specific sink
location in ``extra.dataflow_trace.sink``.  Its JSON emission order is not its
access-tier ranking, so findings are sorted by the documented native access
signal before success@K is computed.
"""
from __future__ import annotations


RULE_CLASS = {
    "tainted-sql-string": {"sqli"},
    "wp-reflected-xss-direct-request-output": {"xss"},
    "wp-stored-xss-persistent-read-to-output": {"xss"},
    "stored-xss": {"xss"},
    "path-transversal": {"lfi"},
    "request-path-read-delete": {"lfi"},
    "unsafe-deserialization": {"deserial"},
    "unsafe-use": {"rce"},
    "render-callback-execution": {"rce"},
    "wp-open-redirect": {"other"},
    "wp-header-injection": {"other"},
    "wp-request-sensitive-action-without-cap-check": {"auth"},
    "wp-ajax-financial-action-without-cap-check": {"auth"},
    "wp-request-record-read-to-output-without-cap-check": {"auth"},
    "wp-request-file-delete-without-cap-check": {"auth"},
    "wp-request-tainted-privilege-mutation": {"auth"},
    "wp-request-file-upload-without-cap-check": {"upload", "auth"},
    "upload-api-surface": {"upload"},
    "wordpress-upload-helper-surface": {"upload"},
    "wp-rest-token-issuance-surface": {"auth"},
}

ACCESS_WEIGHT = {
    "unauthenticated": 1000,
    "permission_callback": 700,
    "nonce_only": 600,
    "authenticated": 400,
    "unknown": 200,
    "capability_checked": 50,
}


def _access_weight(access: str) -> int:
    return ACCESS_WEIGHT.get(access, 100)


def strip_top(path: str, source_root: str = "") -> str:
    """Return a slash-normalized path below the archive's top directory."""
    normalized = (path or "").replace("\\", "/")
    root = (source_root or "").replace("\\", "/").rstrip("/")
    if root and (normalized == root or normalized.startswith(root + "/")):
        normalized = normalized[len(root):].lstrip("/")
    parts = [p for p in normalized.split("/")
             if p and p != "."]
    return "/".join(parts[1:]) if len(parts) > 1 else (parts[0] if parts else "")


def classes_for_rule(rule: str) -> set[str]:
    """Map a native wp-taint-scan rule identifier to benchmark classes."""
    if rule in RULE_CLASS:
        return set(RULE_CLASS[rule])
    low = (rule or "").lower()
    if "sql" in low:
        return {"sqli"}
    if "xss" in low or "output" in low:
        return {"xss"}
    if "deserial" in low or "unserialize" in low:
        return {"deserial"}
    if "upload" in low:
        return {"upload"}
    if "cap" in low or "auth" in low or "privilege" in low:
        return {"auth"}
    if "path" in low or "file" in low or "include" in low:
        return {"lfi"}
    if "callback" in low or "unsafe-use" in low or "exec" in low:
        return {"rce"}
    return {"other"}


def exploitability_score(finding: dict) -> int:
    """Reproduce ``FindingExploitabilityScore`` from wp-taint-scan 6749f23."""
    extra = finding.get("extra") or {}
    context = extra.get("context") or {}
    stored = extra.get("stored_write_context") or {}
    access = context.get("access") or ""
    stored_access = stored.get("access") or ""
    if stored_access and _access_weight(stored_access) > _access_weight(access):
        access = stored_access
    score = _access_weight(access)
    rule = finding.get("check_id", "")
    if rule.endswith("-surface"):
        score -= 150
    trace = extra.get("dataflow_trace") or {}
    source = (trace.get("source") or {}).get("snippet") or ""
    sink = (trace.get("sink") or {}).get("snippet") or ""
    return score + _rule_specific_score(rule, source, sink, trace)


def _rule_specific_score(rule: str, source: str, sink: str, trace: dict) -> int:
    source_lower = source.lower()
    sink_lower = sink.lower()
    if rule == "render-callback-execution":
        score = 0
        if "apply_filters(" in source_lower or "apply_filters_ref_array(" in source_lower:
            score += 160
        elif "apply_filters_deprecated(" in source_lower:
            score += 80
        if ("prepare_post_data(" in source_lower
                or "stripslashes_deep($_post['data'])" in source_lower
                or "stripslashes_deep( $_post['data'] )" in source_lower):
            score += 48
        return score
    if rule == "wp-request-tainted-privilege-mutation":
        score = 0
        if ("json_decode(" in source_lower
                and ("$_post" in source_lower or "$_request" in source_lower)):
            score += 96
        if "new_role" in source_lower or "['role']" in source_lower or '"role"' in source_lower:
            score += 72
        if "file_get_contents(" in source_lower and "$_files" in source_lower:
            score -= 64
        return score
    if rule == "unsafe-deserialization":
        return -128 if source_lower.strip().startswith("function ") else 0
    if rule in {"wp-request-record-read-to-output-without-cap-check",
                "wp-stored-xss-persistent-read-to-output"}:
        score = 0
        if "preg_replace(" in sink_lower:
            score += 160
        if "call_user_func(" in sink_lower or "call_user_func_array(" in sink_lower:
            score += 144
        if any(token in sink_lower for token in
               ("<?php echo $", "echo $", "<?= $", "print $")):
            score += 112
        if any(token in sink_lower for token in
               ('href="<?php echo', 'src="<?php echo', 'title="<?php echo')):
            score += 48
        if "esc_url(" in sink_lower or "esc_attr(" in sink_lower:
            score += 24
        if "esc_html(" in sink_lower or "number_format_i18n(" in sink_lower:
            score -= 16
        return score
    if rule in {"wp-request-file-delete-without-cap-check", "request-path-read-delete",
                "path-transversal"}:
        score = 0
        if any(token in source_lower for token in ("file_path", "tmp_name", "filepath")):
            score += 96
        if "path" in source_lower or "file" in source_lower:
            score += 40
        if "text" in source_lower:
            score -= 24
        source_path = (trace.get("source") or {}).get("path") or ""
        sink_path = (trace.get("sink") or {}).get("path") or ""
        if rule == "path-transversal" and source_path and sink_path and source_path != sink_path:
            score += 32
        return score
    return 0


def compact_findings(payload: dict, source_root: str = "") -> list[dict]:
    """Convert native JSON to deterministic, ranked, tool-neutral findings."""
    out = []
    for finding in payload.get("results") or []:
        extra = finding.get("extra") or {}
        trace = extra.get("dataflow_trace") or {}
        sink = trace.get("sink") or {}
        source = trace.get("source") or {}
        rule = finding.get("check_id", "")
        sink_path = sink.get("path") or finding.get("path") or ""
        out.append({
            "rule": rule,
            "classes": sorted(classes_for_rule(rule)),
            "path": strip_top(sink_path, source_root),
            "line": sink.get("line") or (finding.get("start") or {}).get("line") or 0,
            "access": (extra.get("context") or {}).get("access") or "",
            "score": exploitability_score(finding),
            "message": extra.get("message") or "",
            "source": strip_top(source.get("path") or "", source_root),
            "source_line": source.get("line") or 0,
            "source_snippet": source.get("snippet") or "",
            "sink_snippet": sink.get("snippet") or "",
            "callable": trace.get("callable") or "",
            "stored_access": (extra.get("stored_write_context") or {}).get("access") or "",
        })
    # Native CLI uses a stable score-only sort over the path/line ordered JSON list.
    out.sort(key=lambda item: -item["score"])
    return out
