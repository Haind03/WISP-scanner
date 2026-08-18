#!/usr/bin/env python3
"""Generate a WordPress-aware Semgrep ruleset from the SAME vocabulary WISP uses
(wisp-rules.yaml), so a controlled experiment can ask the reviewer's question 3:
how much of WISP's advantage is the WordPress source/sink/guard vocabulary versus
the analysis engine?

Design principle: transplant WISP's vocabulary into Semgrep's own taint engine
as faithfully as Semgrep's rule language allows.
  * taint classes (xss, sqli, lfi, rce, ssrf, upload, deserial, other): one
    Semgrep taint-mode rule per class, with WISP's request sources, WISP's
    class-scoped sanitizers, and WISP's class sinks.
  * missing-guard classes (csrf, auth): Semgrep cannot express taint here, so we
    give it the same predicate logic WISP uses as a structural rule: a
    state-change call inside a function that reads a request superglobal and
    does NOT contain the relevant guard call. This is the fairest transplant of
    the missing-guard detector into Semgrep's pattern language.

Usage: python3 gen_semgrep_wp.py --rules ../WISP_Scan/wisp/rules/wisp-rules.yaml \
                                 --out semgrep_wp_rules.yaml
"""
import argparse
import os
import yaml

# request sources shared by every taint rule (superglobals + WISP source_funcs +
# WordPress REST/AJAX accessors that WISP seeds as sources).
WP_SOURCE_PATTERNS = [
    "$REQ->get_param(...)",
    "$REQ->get_params(...)",
    "$REQ->get_json_params(...)",
    "$REQ->get_body_params(...)",
    "$REQ->get_query_params(...)",
]

# class-scoped sanitizer split (mirrors WISP N[c] vs N_universal in Sec. V-B).
XSS_SANI = ["esc_html", "esc_html__", "esc_html_e", "esc_attr", "esc_attr__",
            "esc_attr_e", "esc_url", "esc_url_raw", "esc_js", "esc_textarea",
            "esc_xml", "wp_kses", "wp_kses_post", "wp_kses_data",
            "wp_strip_all_tags", "tag_escape", "htmlspecialchars", "htmlentities"]
SQLI_SANI = ["esc_sql", "esc_like", "sanitize_sql_orderby",
             "mysqli_real_escape_string", "mysql_real_escape_string",
             "real_escape_string", "addslashes"]
URL_SANI = ["esc_url", "esc_url_raw", "sanitize_url", "rawurlencode", "urlencode"]
FILE_SANI = ["basename", "sanitize_file_name", "validate_file", "realpath"]
UNIVERSAL_SANI = ["absint", "intval", "floatval", "boolval", "is_numeric",
                  "ctype_digit", "number_format", "zeroise", "sanitize_text_field",
                  "sanitize_key", "sanitize_email", "filter_var", "json_encode",
                  "md5", "sha1", "hash", "wp_hash", "preg_quote"]

# per-class sanitizer selection
CLASS_SANI = {
    "xss": XSS_SANI + UNIVERSAL_SANI,
    "sqli": SQLI_SANI + UNIVERSAL_SANI,
    "lfi": FILE_SANI + UNIVERSAL_SANI,
    "rce": UNIVERSAL_SANI,
    "ssrf": URL_SANI + UNIVERSAL_SANI + ["wp_http_validate_url"],
    "upload": FILE_SANI + UNIVERSAL_SANI,
    "deserial": UNIVERSAL_SANI,
    "other": URL_SANI + UNIVERSAL_SANI,
}

SEV = {"xss": "WARNING", "sqli": "ERROR", "lfi": "ERROR", "rce": "ERROR",
       "ssrf": "WARNING", "upload": "ERROR", "deserial": "ERROR", "other": "INFO",
       "csrf": "WARNING", "auth": "WARNING"}


# Semgrep parses "$UPPERCASE" as a metavariable that matches ANY expression, so
# a source pattern like $HTTP_RAW_POST_DATA silently taints everything. Semgrep
# special-cases the standard superglobals ($_GET, $_POST, ...) as literals, but
# not the removed-in-PHP7 $HTTP_RAW_POST_DATA. Skip any superglobal Semgrep would
# read as a metavariable.
_SEMGREP_LITERAL_SUPERGLOBALS = {
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER",
    "$_ENV", "$_SESSION", "$GLOBALS",
}


def source_block(superglobals):
    src = [{"pattern": sg} for sg in superglobals
           if sg in _SEMGREP_LITERAL_SUPERGLOBALS]
    src += [{"pattern": f} for f in WP_SOURCE_PATTERNS]
    return src


def sink_patterns_for_class(cls, sinks):
    """Return a list of Semgrep sink pattern dicts for the class."""
    pats = []
    if cls == "xss":
        pats += [{"pattern": "echo $SINK;", "focus-metavariable": "$SINK"},
                 {"pattern": "print($SINK)", "focus-metavariable": "$SINK"},
                 {"pattern": "printf(...)"}, {"pattern": "vprintf(...)"},
                 {"pattern": "print_r(...)"}]
    elif cls == "sqli":
        for m in sinks.get("sqli", {}).get("wpdb_methods", []):
            if m == "prepare":
                continue
            pats.append({"pattern": f"$WPDB->{m}(...)"})
        for f in sinks.get("sqli", {}).get("db_funcs", []):
            pats.append({"pattern": f"{f}(...)"})
    else:
        for f in sinks.get(cls, {}).get("funcs", []):
            if f in ("include", "include_once", "require", "require_once"):
                pats.append({"pattern": f"{f} $SINK;", "focus-metavariable": "$SINK"})
            else:
                pats.append({"pattern": f"{f}(...)"})
    return pats


def taint_rule(cls, superglobals, sinks):
    sink_pats = sink_patterns_for_class(cls, sinks)
    if not sink_pats:
        return None
    return {
        "id": f"wisp-wp-{cls}",
        "mode": "taint",
        "languages": ["php"],
        "severity": SEV[cls],
        "message": f"WordPress {cls}: request-tainted data reaches a {cls} sink "
                   f"(WISP vocabulary transplanted into Semgrep taint mode).",
        "metadata": {"wisp-class": cls},
        "pattern-sources": source_block(superglobals),
        "pattern-sanitizers": [{"pattern": f"{s}(...)"} for s in CLASS_SANI[cls]],
        "pattern-sinks": sink_pats,
    }


def guard_rule(cls, state_change, guards, superglobals):
    """Best-effort missing-guard structural rule: a state-change call inside a
    function whose body lacks the guard call. Semgrep's PHP grammar cannot
    faithfully express WISP's function-scope call-presence test for a guard that
    appears in an arbitrary syntactic position (e.g. inside an if-condition), so
    this rule only excludes the guard when it appears as a bare statement or a
    negated-if. It is therefore an OVER-report relative to WISP's own detector,
    and we report it as a lower bar, not a faithful transplant."""
    guard_names = guards["nonce"] if cls == "csrf" else guards["capability"]
    sc_funcs = state_change.get("funcs", [])
    sc_methods = state_change.get("wpdb_methods", [])
    sc_patterns = [{"pattern": f"{f}(...)"} for f in sc_funcs] + \
                  [{"pattern": f"$WPDB->{m}(...)"} for m in sc_methods]
    not_inside = []
    for g in guard_names:
        not_inside.append({"pattern-not-inside":
                           f"function $F(...) {{ ... {g}(...); ... }}"})
        not_inside.append({"pattern-not-inside":
                           f"function $F(...) {{ ... if (!{g}(...)) {{ ... }} ... }}"})
        not_inside.append({"pattern-not-inside":
                           f"function $F(...) {{ ... if (!{g}(...)) $S; ... }}"})
    return {
        "id": f"wisp-wp-{cls}",
        "languages": ["php"],
        "severity": SEV[cls],
        "message": f"WordPress {cls}: state change in a function with no "
                   f"{'nonce' if cls == 'csrf' else 'capability'} check "
                   f"(best-effort Semgrep transplant of WISP missing-guard).",
        "metadata": {"wisp-class": cls},
        "patterns": [
            {"pattern-either": sc_patterns},
            {"pattern-inside": "function $F(...) { ... }"},
            *not_inside,
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=os.path.join(
        os.path.dirname(__file__), "..", "wisp", "rules", "wisp-rules.yaml"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__),
                                                  "semgrep_wp_rules.yaml"))
    ap.add_argument("--no-guard", action="store_true",
                    help="emit only taint classes (drop csrf/auth structural rules)")
    a = ap.parse_args()
    spec = yaml.safe_load(open(a.rules))
    superglobals = spec["superglobals"]
    sinks = spec["sinks"]
    state_change = spec["state_change"]
    guards = spec["guards"]

    rules = []
    for cls in ("xss", "sqli", "lfi", "rce", "ssrf", "upload", "deserial", "other"):
        r = taint_rule(cls, superglobals, sinks)
        if r:
            rules.append(r)
    if not a.no_guard:
        rules.append(guard_rule("csrf", state_change, guards, superglobals))
        rules.append(guard_rule("auth", state_change, guards, superglobals))

    yaml.safe_dump({"rules": rules}, open(a.out, "w"), sort_keys=False, width=200)
    print(f"wrote {len(rules)} rules to {a.out}")
    for r in rules:
        print(f"  {r['id']:16s} "
              f"{len(r.get('pattern-sinks', r.get('patterns', [])))} sink/pattern blocks")


if __name__ == "__main__":
    main()
