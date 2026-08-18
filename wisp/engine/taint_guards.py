"""WISP framework-aware missing-guard detector (CSRF / broken access control).

This is the WISP novelty that source->sink taint analysis cannot express: a
function that reads request data and performs a WordPress state change with no
nonce check is a CSRF candidate, and with no capability check is a broken-
access-control (auth) candidate. Kept separate from the data-flow engine.
"""
from __future__ import annotations
import os

try:
    from .taint_ast import (Finding, _text, _call_name, _child, _descend_calls,
                            _fn_name)
    from .taint_vocab import (SUPERGLOBALS, REST_READ_METHODS, STATE_CHANGE_FUNCS,
                              STATE_CHANGE_WPDB, GUARD_NONCE, GUARD_CAP)
except ImportError:  # pragma: no cover - support flat imports
    from taint_ast import (Finding, _text, _call_name, _child, _descend_calls,
                           _fn_name)
    from taint_vocab import (SUPERGLOBALS, REST_READ_METHODS, STATE_CHANGE_FUNCS,
                             STATE_CHANGE_WPDB, GUARD_NONCE, GUARD_CAP)



# WISP_GUARD_ORDER=1 is a dominance-lite refinement: a nonce/capability call only
# counts as protecting the state change if it appears BEFORE the first mutation
# in the same function (source-line order). A guard that runs after the mutation
# cannot protect it. Off by default: the published numbers use call presence.
_GUARD_ORDER = os.environ.get("WISP_GUARD_ORDER", "0") == "1"


def _reads_request(node, src: bytes) -> bool:
    """True if any request superglobal is accessed under `node`."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "variable_name" and _text(n, src) in SUPERGLOBALS:
            return True
        stack.extend(n.children)
    return False


def _reads_rest(node, src: bytes) -> bool:
    """True if `node` reads request data via a WP_REST_Request accessor.

    REST handlers receive a `$request` object and read input through
    `$request->get_param(...)` etc. — invisible to superglobal-based detection.
    """
    for call in _descend_calls(node):
        if call.type == "member_call_expression":
            nm = _call_name(call, src).lstrip("\\").split("\\")[-1]
            if nm in REST_READ_METHODS:
                return True
    return False


def _detect_missing_guards(funcs, src: bytes, rel: str, abs_file: str) -> list:
    """Framework-aware CSRF / broken-access-control detector.

    A function that reads request data and performs a WordPress state change
    (option/meta/post/user write, $wpdb insert/update/delete) is a CSRF
    candidate if no nonce check is present, and a broken-access-control (auth)
    candidate if no capability check is present. This recovers exactly the
    cross-cutting classes that source->sink taint analysis cannot see.
    """
    if not (STATE_CHANGE_FUNCS or STATE_CHANGE_WPDB):
        return []
    out = []
    for fn in funcs:
        body = _child(fn, "compound_statement")
        if body is None:
            continue
        via_superglobal = _reads_request(body, src)
        via_rest = _reads_rest(body, src) if not via_superglobal else False
        if not (via_superglobal or via_rest):
            continue
        names = set()
        sc_line = None
        sc_desc = None
        first_nonce_line = None
        first_cap_line = None
        for call in _descend_calls(body):
            nm = _call_name(call, src).lstrip("\\").split("\\")[-1]
            names.add(nm)
            if nm in GUARD_NONCE and first_nonce_line is None:
                first_nonce_line = call.start_point[0] + 1
            if nm in GUARD_CAP and first_cap_line is None:
                first_cap_line = call.start_point[0] + 1
            if sc_line is None:
                if call.type == "member_call_expression":
                    obj = _text(call.children[0], src)
                    if "wpdb" in obj and nm in STATE_CHANGE_WPDB:
                        sc_line, sc_desc = call.start_point[0] + 1, f"$wpdb->{nm}"
                    elif "wpdb" in obj and nm == "query":
                        up = _text(call, src).upper()
                        if any(k in up for k in ("INSERT ", "UPDATE ", "DELETE ",
                                                 "REPLACE ", "DROP ", "ALTER ")):
                            sc_line, sc_desc = call.start_point[0] + 1, "$wpdb->query (write)"
                elif nm in STATE_CHANGE_FUNCS:
                    sc_line, sc_desc = call.start_point[0] + 1, nm
        if sc_line is None:
            continue
        fn_label = _fn_name(fn, src)
        nonce_guarded = bool(names & GUARD_NONCE)
        cap_guarded = bool(names & GUARD_CAP)
        if _GUARD_ORDER:
            nonce_guarded = first_nonce_line is not None and first_nonce_line <= sc_line
            cap_guarded = first_cap_line is not None and first_cap_line <= sc_line
        # REST endpoints carry their own cookie+nonce CSRF protection (X-WP-Nonce
        # via the REST infrastructure), so only flag CSRF for superglobal-based
        # handlers; capability (auth) is always the developer's responsibility.
        if via_superglobal and not nonce_guarded:
            out.append(Finding(
                file=rel, abs_file=abs_file, line=sc_line, vuln_class="csrf",
                message=f"State change ({sc_desc}) reachable from request with no nonce check (CSRF)",
                source="request", sink=sc_desc,
                trace=[f"request -> {sc_desc} in {fn_label}() with no nonce verification @ {rel}:{sc_line}"],
                confidence=0.5))
        if not cap_guarded:
            out.append(Finding(
                file=rel, abs_file=abs_file, line=sc_line, vuln_class="auth",
                message=f"State change ({sc_desc}) reachable from request with no capability check (broken access control)",
                source="request", sink=sc_desc,
                trace=[f"request -> {sc_desc} in {fn_label}() with no capability check @ {rel}:{sc_line}"],
                confidence=0.5))
    return out
