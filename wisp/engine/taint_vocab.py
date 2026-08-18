"""WISP taint vocabulary (rule-driven).

The constants below are DEFAULTS. If our declarative taint spec
(rules/wisp-rules.yaml) loads, it OVERRIDES them so detection is driven by the
editable rule file rather than hard-coded vocab — this is what replaces Semgrep
and what the Stage-4 rule-mining loop appends to. The taint engine imports
these names; they are set ONCE here at import and read thereafter (no runtime
reassignment), so a single source of truth lives in this module.
"""
from __future__ import annotations

# --- taint vocabulary ------------------------------------------------------
SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES",
                "$_SERVER", "$_ENV", "$HTTP_RAW_POST_DATA"}
# WP_REST_Request accessors: REST handlers read attacker input through these
# rather than through superglobals, so the guard-detector must see them to flag
# capability-less REST endpoints (a common broken-access-control pattern).
REST_READ_METHODS = {"get_param", "get_params", "get_json_params",
                     "get_body_params", "get_query_params", "get_url_params",
                     "get_file_params", "get_body", "get_header"}
# request-reading functions that return attacker-controlled data
SOURCE_FUNCS = {"file_get_contents", "stream_get_contents", "getenv",
                "wp_unslash", "apply_filters",  # wp_unslash keeps taint
                # [Paper05] WP option/meta can hold attacker-influenced data (second-order)
                "get_option", "get_post_meta", "get_user_meta", "get_term_meta",
                "get_transient", "get_site_option", "get_comment_meta"}

# sink callable -> vuln class
SINK_FUNCS = {
    "system": "rce", "exec": "rce", "shell_exec": "rce", "passthru": "rce",
    "popen": "rce", "proc_open": "rce", "eval": "rce", "assert": "rce",
    "call_user_func": "rce", "call_user_func_array": "rce", "create_function": "rce",
    # [Paper01/02] callback-via-array RCE sinks: dangerous when callback arg is tainted
    "array_map": "rce", "usort": "rce", "uasort": "rce", "uksort": "rce",
    "register_shutdown_function": "rce", "register_tick_function": "rce",
    "include": "lfi", "include_once": "lfi", "require": "lfi", "require_once": "lfi",
    "fopen": "lfi", "readfile": "lfi", "file_get_contents": "lfi",
    # [Paper01] WP-specific LFI sinks commonly missed
    "locate_template": "lfi", "load_template": "lfi",
    "get_template_part": "lfi", "virtual": "lfi",
    "unlink": "lfi", "file_put_contents": "upload", "move_uploaded_file": "upload",
    # [Paper01] missing upload sinks
    "wp_handle_sideload": "upload", "media_handle_sideload": "upload",
    "wp_handle_upload": "upload", "media_handle_upload": "upload",
    "unserialize": "deserial", "maybe_unserialize": "deserial",
    "header": "ssrf", "wp_remote_get": "ssrf", "wp_remote_post": "ssrf",
    # [Paper01] missing SSRF sinks
    "wp_remote_request": "ssrf",
    "curl_exec": "ssrf", "fsockopen": "ssrf",
    "echo": "xss", "print": "xss", "printf": "xss", "print_r": "xss",
}
# $wpdb method calls that execute SQL
WPDB_SQL_METHODS = {"query", "get_results", "get_row", "get_var", "get_col",
                    "prepare", "get_blog_prefix"}
# learned METHOD sinks ($obj->name(tainted) -> class), grown by the recall-growth
# rule-mining loop (empty by default; populated from rules learned_method_sinks).
METHOD_SINKS: dict = {}
DB_SINK_FUNCS = {"mysqli_query", "mysql_query", "mysqli_multi_query"}

# anything in here neutralizes taint flowing through it
SANITIZERS = {
    "esc_html", "esc_attr", "esc_url", "esc_url_raw", "esc_js", "esc_textarea",
    "esc_sql", "sanitize_text_field", "sanitize_textarea_field", "sanitize_email",
    "sanitize_key", "sanitize_file_name", "sanitize_title", "sanitize_user",
    "sanitize_html_class", "wp_kses", "wp_kses_post", "absint", "intval",
    "floatval", "boolval", "is_numeric", "ctype_digit", "wp_verify_nonce",
    "wpdb::prepare", "esc_like", "number_format", "filter_var", "basename",
    "wp_validate_boolean", "rawurlencode", "urlencode", "md5", "sha1", "hash",
    # [Paper03/05 YASA] HTML-context sanitizers — reduce XSS SFDR (80.6% FPs from missed sanitizers)
    "htmlspecialchars", "htmlentities", "wp_strip_all_tags", "strip_tags",
    "htmlspecialchars_decode",
    # [Paper05] additional WP sanitizers commonly missed
    "sanitize_hex_color", "sanitize_meta", "sanitize_option", "wp_check_filetype",
    "wp_check_filetype_and_ext", "tag_escape", "wp_encode_emoji",
    # nonce/CSRF guards that terminate execution on failure — effectively sanitize
    "check_admin_referer", "check_ajax_referer",
}

# framework-aware missing-guard detector vocab (empty = detector disabled)
STATE_CHANGE_FUNCS: set = set()
STATE_CHANGE_WPDB: set = set()
GUARD_NONCE: set = set()
GUARD_CAP: set = set()

# learned-from-verify (Stage-4) precision vocab:
#   SAFE_MEMBERS    : superglobal members that are server-controlled, not attacker
#                     data (e.g. $_FILES[*]['tmp_name']) -> never seed taint.
#   PREDICATE_FUNCS : functions returning a bool/int metadata answer, not the
#                     tainted string itself (isset/empty/count/...) -> drop taint.
#   PATTERN_ONLY_SINKS : sinks dangerous only when their PATTERN arg (index 0) is
#                     tainted; a tainted subject is harmless (preg_replace...).
SAFE_MEMBERS: dict = {"$_FILES": {"tmp_name", "size", "error"}}
PREDICATE_FUNCS: set = {"isset", "empty", "is_array", "is_string", "is_bool",
                        "array_key_exists", "in_array", "count", "sizeof",
                        "strlen", "gettype"}
PATTERN_ONLY_SINKS: set = {"preg_replace", "preg_replace_callback",
                           "preg_match", "preg_match_all", "ereg_replace",
                           "mb_ereg_replace"}

# --- rule-driven override --------------------------------------------------
try:
    from .rule_spec import load as _load_rules
except ImportError:  # pragma: no cover - support flat imports
    try:
        from rule_spec import load as _load_rules  # type: ignore
    except ImportError:
        _load_rules = None

RULES = _load_rules() if _load_rules else None
if RULES is not None:
    SUPERGLOBALS = RULES.superglobals or SUPERGLOBALS
    SOURCE_FUNCS = RULES.source_funcs or SOURCE_FUNCS
    SINK_FUNCS = RULES.sink_funcs or SINK_FUNCS
    WPDB_SQL_METHODS = RULES.wpdb_sql_methods or WPDB_SQL_METHODS
    DB_SINK_FUNCS = RULES.db_sink_funcs or DB_SINK_FUNCS
    SANITIZERS = RULES.sanitizers or SANITIZERS
    STATE_CHANGE_FUNCS = RULES.state_change_funcs
    STATE_CHANGE_WPDB = RULES.state_change_wpdb
    GUARD_NONCE = RULES.guard_nonce
    GUARD_CAP = RULES.guard_capability
    SAFE_MEMBERS = RULES.safe_members or SAFE_MEMBERS
    PREDICATE_FUNCS = RULES.predicate_funcs or PREDICATE_FUNCS
    PATTERN_ONLY_SINKS = RULES.pattern_only_sinks or PATTERN_ONLY_SINKS
    METHOD_SINKS = RULES.method_sinks or METHOD_SINKS

# --- context-aware sanitization -------------------------------------------
# A sanitizer only neutralizes taint for the sink CLASSES it actually protects.
# Treating every sanitizer as cleaning every context is a recall bug: e.g.
# `echo esc_sql($_GET['x'])` is still XSS (esc_sql is for SQL), and
# `$wpdb->query(esc_html($_GET['id']))` is still SQLi. We therefore split the
# context-specific sanitizers out; ANY sanitizer not listed here keeps the old
# behavior (neutralizes all contexts), so unknown/rule-added sanitizers never
# introduce new false positives.
SANITIZERS = {s for s in SANITIZERS if s != "htmlspecialchars_decode"}  # decode is NOT a sanitizer
_CLASS_SANITIZERS = {
    "xss":  {"esc_html", "esc_attr", "esc_textarea", "esc_js", "esc_url",
             "esc_url_raw", "wp_kses", "wp_kses_post", "htmlspecialchars",
             "htmlentities", "strip_tags", "wp_strip_all_tags", "tag_escape",
             "sanitize_text_field", "sanitize_textarea_field"},
    "sqli": {"esc_sql", "esc_like", "wpdb::prepare"},
    "lfi":  {"basename", "sanitize_file_name", "wp_check_filetype",
             "wp_check_filetype_and_ext"},
    "upload": {"sanitize_file_name", "wp_check_filetype", "wp_check_filetype_and_ext"},
}
# only keep names that are actually active sanitizers
SANITIZERS_BY_CLASS = {c: (s & SANITIZERS) for c, s in _CLASS_SANITIZERS.items()}
_class_specific = set().union(*_CLASS_SANITIZERS.values())
# everything else neutralizes all contexts (numeric casts, hashes, key/slug
# sanitizers, nonce guards, unknown rule-added names): conservative = no new FPs.
SANITIZERS_UNIVERSAL = SANITIZERS - _class_specific
