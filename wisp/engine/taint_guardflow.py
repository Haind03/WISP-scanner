"""Inter-procedural guard-dominance analysis (GDA) — WISP control-flow contribution.

The framework-aware missing-guard detector (``taint_guards``) fires whenever a
function reads request data and performs a WordPress state change with no
nonce/capability CALL anywhere in its own body. That test is intra-procedural and
presence-based, so it cannot separate a genuinely unprotected state change (the
real advisory) from one the developer protected by a guard placed

  * in the CALLER   — a dispatcher verifies ``current_user_can`` then calls the
    writer (the guard is absent from the writer's own body);
  * on the ROUTE    — ``register_rest_route(..., 'permission_callback' => cb)``;
  * at REGISTRATION — ``add_submenu_page($cap, ...)``: only $cap-holders reach it;
  * or by a guard that DOMINATES the sink on every path, versus one that sits in a
    sibling branch or runs after the mutation.

GDA computes, per state-change sink, a **guard deficit** in ``[0, 1]``: how
unprotected the sink is once intra-procedural dominance and caller-, route- and
registration-level guards are all accounted for. A deficit near 1 (reachable from
an unauthenticated entry point with no adequate guard on any path) is the signal
the real access-control advisories carry; a deficit near 0 means an adequate guard
dominates the sink.

The deficit is used as a **ranking** signal: it never drops a finding (recall is
preserved exactly), it reprioritises the missing-guard findings so the genuinely
unprotected one rises into the top-K an analyst reads. This is the control-flow
analysis the taint engine and the domain vocabulary cannot express.

Design notes:
  * Dominance is an AST approximation of a CFG dominator test. A guard G dominates
    a sink S iff G runs before S in source order and every conditional that
    encloses G also encloses S (G is not deeper in a branch than S). Two WP idioms
    are recognised explicitly: the *early-return guard*
    ``if (!current_user_can(...)) wp_die();`` (terminating branch dominates all
    following siblings) and the *wrapping guard*
    ``if (current_user_can(...)) { ...sink... }`` (condition dominates its body).
  * ``check_admin_referer`` / ``check_ajax_referer`` wp_die on failure, so a bare
    call to them is a terminating guard by contract.
  * Everything is a single pass over the already-parsed ASTs held in the engine's
    per-plugin cache; no file is re-read.
"""
from __future__ import annotations

try:
    from .taint_ast import (_text, _child, _call_name, _descend_calls, _fn_name)
    from .taint_vocab import (GUARD_NONCE, GUARD_CAP, STATE_CHANGE_FUNCS,
                              STATE_CHANGE_WPDB, SUPERGLOBALS, REST_READ_METHODS)
except ImportError:  # pragma: no cover - support flat imports
    from taint_ast import (_text, _child, _call_name, _descend_calls, _fn_name)
    from taint_vocab import (GUARD_NONCE, GUARD_CAP, STATE_CHANGE_FUNCS,
                             STATE_CHANGE_WPDB, SUPERGLOBALS, REST_READ_METHODS)

# statements that introduce a control branch: a guard nested in one of these but
# not shared by the sink is "deeper in a branch" and does not dominate the sink.
_CTRL = ("if_statement", "else_if_clause", "else_clause", "for_statement",
         "while_statement", "foreach_statement", "switch_statement",
         "do_statement", "try_statement", "catch_clause")
# calls that abort the request: an if-branch containing one is a terminating guard.
_TERMINATORS = {"wp_die", "die", "exit", "wp_send_json_error", "wp_send_json",
                "wp_nonce_ays", "auth_redirect", "wp_redirect"}
# bare guards that abort on failure by contract (no enclosing if needed).
_BARE_TERMINATING = {"check_admin_referer", "check_ajax_referer"}
# WP admin-menu registrars whose 1st capability arg gates who can reach the page.
_MENU_REGISTRARS = {"add_menu_page", "add_submenu_page", "add_options_page",
                    "add_management_page", "add_theme_page", "add_plugins_page",
                    "add_users_page", "add_dashboard_page", "add_posts_page",
                    "add_media_page", "add_comments_page", "add_pages_page"}


def _enclosing_conds(node, body):
    """Set of control-statement node ids strictly between `node` and `body`."""
    out = set()
    p = node.parent
    while p is not None and p is not body:
        if p.type in _CTRL:
            out.add(p.id)
        p = p.parent
    return out


def _controlling_if(guard_call):
    """Nearest ancestor if/elseif whose CONDITION contains the guard call."""
    p = guard_call.parent
    while p is not None:
        if p.type in ("if_statement", "else_if_clause"):
            cond = _child(p, "parenthesized_expression")
            if cond is not None and cond.start_byte <= guard_call.start_byte <= cond.end_byte:
                return p
        p = p.parent
    return None


def _branch_terminates(if_stmt, src):
    """True if the if's consequence unconditionally aborts (return/exit/throw or
    a terminating WP call), making it an early-return guard."""
    body = None
    for c in if_stmt.children:
        if c.type == "compound_statement":
            body = c
            break
        if c.type in ("return_statement", "expression_statement",
                      "exit_statement", "throw_statement", "goto_statement"):
            body = c
            break
    if body is None:
        return False
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type in ("return_statement", "exit_statement", "throw_statement"):
            return True
        if n.type in ("function_call_expression", "member_call_expression",
                      "scoped_call_expression"):
            nm = _call_name(n, src).lstrip("\\").split("\\")[-1]
            if nm in _TERMINATORS:
                return True
        # do not descend into nested function scopes
        if n.type not in ("function_definition", "method_declaration",
                          "anonymous_function_creation_expression", "arrow_function"):
            stack.extend(n.children)
    return False


def _dominates(guard_call, guard_name, sink_node, body, src):
    """AST dominator approximation: does `guard_call` dominate `sink_node`?

    Handles the two WordPress guard idioms plus branch/order sensitivity:
      * wrapping   — guard is the condition of an `if` whose body holds the sink;
      * terminating — guard's `if` aborts on failure (early return), or the guard
        is a bare check_*_referer(); it then dominates every later sibling sink;
      * order      — a guard after the sink cannot protect it;
      * branch     — a guard nested in a conditional the sink is outside of does
        not dominate (the branch-specific-guard false negative the flat test hides).
    """
    g_line, s_line = guard_call.start_point[0], sink_node.start_point[0]
    cif = _controlling_if(guard_call)
    if cif is not None:
        # wrapping guard: sink lives inside the guarded if and runs after the check
        if (cif.start_byte <= sink_node.start_byte <= cif.end_byte
                and guard_call.start_byte < sink_node.start_byte):
            return True
        # terminating guard: early-return/abort dominates following siblings
        if _branch_terminates(cif, src):
            if g_line <= s_line and _enclosing_conds(cif, body) <= _enclosing_conds(sink_node, body):
                return True
        return False
    # bare guard call (no enclosing condition)
    if guard_name in _BARE_TERMINATING:
        if g_line <= s_line and _enclosing_conds(guard_call, body) <= _enclosing_conds(sink_node, body):
            return True
    return False


def _is_state_change_call(call, src):
    """Return a short sink description if `call` is a WordPress state change."""
    nm = _call_name(call, src).lstrip("\\").split("\\")[-1]
    if call.type == "member_call_expression":
        obj = _text(call.children[0], src)
        if "wpdb" in obj and nm in STATE_CHANGE_WPDB:
            return f"$wpdb->{nm}"
        if "wpdb" in obj and nm == "query":
            up = _text(call, src).upper()
            if any(k in up for k in ("INSERT ", "UPDATE ", "DELETE ", "REPLACE ",
                                     "DROP ", "ALTER ")):
                return "$wpdb->query (write)"
        return None
    if nm in STATE_CHANGE_FUNCS:
        return nm
    return None


class _FnFacts:
    """Per-function guard facts used by the plugin-level deficit computation."""
    __slots__ = ("name", "abs_file", "rel", "sinks", "reads_request",
                 "via_superglobal", "via_rest", "nonce_calls", "cap_calls",
                 "guards_callsites")

    def __init__(self, name, abs_file):
        self.name = name
        self.abs_file = abs_file
        self.rel = abs_file
        self.sinks = []            # [(line, desc, nonce_dom, cap_dom)]
        self.reads_request = False
        self.via_superglobal = False
        self.via_rest = False
        self.nonce_calls = []      # [(node, name)]
        self.cap_calls = []        # [(node, name)]
        self.guards_callsites = {}  # callee_name -> (nonce_dom_bool, cap_dom_bool)


def _reads_request(body, src):
    """Return (via_superglobal, via_rest)."""
    sg = rest = False
    stack = [body]
    while stack:
        n = stack.pop()
        if n.type == "variable_name" and _text(n, src) in SUPERGLOBALS:
            sg = True
        elif n.type == "member_call_expression":
            nm = _call_name(n, src).lstrip("\\").split("\\")[-1]
            if nm in REST_READ_METHODS:
                rest = True
        stack.extend(n.children)
    return sg, rest


def _collect_fn_facts(fn, src, abs_file):
    """One AST pass over a function: guards, state-change sinks, and for each sink
    whether a nonce/capability guard dominates it. Also records, per outgoing call,
    whether guards dominate that call site (for caller-side propagation)."""
    from .taint_ast import _child as _c  # local alias; avoids shadowing at import
    body = _c(fn, "compound_statement")
    facts = _FnFacts(_fn_name(fn, src), abs_file)
    if body is None:
        return facts
    facts.via_superglobal, facts.via_rest = _reads_request(body, src)
    facts.reads_request = facts.via_superglobal or facts.via_rest
    nonce_calls, cap_calls, state_calls, out_calls = [], [], [], []
    for call in _descend_calls(body):
        nm = _call_name(call, src).lstrip("\\").split("\\")[-1]
        if nm in GUARD_NONCE:
            nonce_calls.append((call, nm))
        if nm in GUARD_CAP:
            cap_calls.append((call, nm))
        desc = _is_state_change_call(call, src)
        if desc:
            state_calls.append((call, desc))
        out_calls.append((call, nm))
    facts.nonce_calls = nonce_calls
    facts.cap_calls = cap_calls
    for scall, desc in state_calls:
        n_dom = any(_dominates(g, gn, scall, body, src) for g, gn in nonce_calls)
        c_dom = any(_dominates(g, gn, scall, body, src) for g, gn in cap_calls)
        facts.sinks.append((scall.start_point[0] + 1, desc, n_dom, c_dom))
    # caller-side: for each outgoing call, does a guard dominate that call site?
    for ocall, onm in out_calls:
        if not onm:
            continue
        n_dom = any(_dominates(g, gn, ocall, body, src) for g, gn in nonce_calls)
        c_dom = any(_dominates(g, gn, ocall, body, src) for g, gn in cap_calls)
        prev = facts.guards_callsites.get(onm, (True, True))
        # a callee is caller-guarded only if EVERY call site to it is guarded
        facts.guards_callsites[onm] = (prev[0] and n_dom, prev[1] and c_dom)
    return facts


def _rest_permission_callbacks(cache):
    """Set of REST callback function names whose route carries a real
    permission_callback (anything other than __return_true / empty / omitted)."""
    import re
    guarded = set()
    rest_re = re.compile(r"register_rest_route\s*\((.+?)\)\s*;", re.S)
    cb_re = re.compile(r"""['"]callback['"]\s*=>\s*(.+?)(?:,\s*['"]|\)|$)""", re.S)
    perm_re = re.compile(r"""['"]permission_callback['"]\s*=>\s*(.+?)(?:,\s*['"]|\)|\]|$)""", re.S)
    name_re = re.compile(r"""['"]([\w:\\]+)['"]|\[\s*\$this\s*,\s*['"](\w+)['"]""")

    def terminal(txt):
        m = name_re.search(txt or "")
        if not m:
            return None
        raw = m.group(1) or m.group(2) or ""
        raw = raw.split("::")[-1].split("\\")[-1]
        return raw or None

    for _abs, (src, _funcs) in cache.items():
        try:
            text = src.decode("utf-8", "ignore")
        except Exception:
            continue
        for m in rest_re.finditer(text):
            body = m.group(1)
            cbm = cb_re.search(body)
            pm = perm_re.search(body)
            if not cbm:
                continue
            cbname = terminal(cbm.group(1))
            if not cbname:
                continue
            if pm:
                perm = pm.group(1).strip()
                low = perm.lower()
                # __return_true / true / '__return_true' => public route (no guard)
                if "__return_true" not in low and low not in ("true", "'true'", '"true"'):
                    guarded.add(cbname)
    return guarded


def _admin_cap_registered(cache):
    """Set of callback function names registered ONLY behind an admin-menu
    capability (add_submenu_page($cap, ..., cb)). Such a handler is reachable only
    by users holding $cap, so its state changes are capability-gated by context."""
    import re
    registered = set()
    name_re = re.compile(r"""['"]([\w:\\]+)['"]|\[\s*\$this\s*,\s*['"](\w+)['"]""")
    for _abs, (src, _funcs) in cache.items():
        try:
            text = src.decode("utf-8", "ignore")
        except Exception:
            continue
        for reg in _MENU_REGISTRARS:
            for m in re.finditer(reg + r"\s*\((.+?)\)\s*;", text, re.S):
                args = m.group(1)
                nm = name_re.findall(args)
                # the callback is the last quoted string / [$this,'m'] in the arg list
                cb = None
                for a, b in nm:
                    cand = (a or b).split("::")[-1].split("\\")[-1]
                    if cand and not cand.startswith("add_"):
                        cb = cand
                if cb:
                    registered.add(cb)
    return registered


def _iter_sink_deficits(cache, ep_of=None, handler_names=frozenset()):
    """Yield (abs_file, fn_name, line, desc, kind, deficit, via_superglobal) for
    every state-change sink in a request-reading function. `kind` is "csrf" (nonce)
    or "auth" (capability). Shared core of compute_deficits (map) and
    emit_missing_guards (findings)."""
    fn_facts = []
    for abs_file, (src, funcs) in cache.items():
        for fn in funcs:
            f = _collect_fn_facts(fn, src, abs_file)
            fn_facts.append(f)

    rest_guarded = _rest_permission_callbacks(cache)
    admin_capped = _admin_cap_registered(cache)

    caller_nonce, caller_cap, seen_callee = {}, {}, set()
    for f in fn_facts:
        for callee, (n_dom, c_dom) in f.guards_callsites.items():
            seen_callee.add(callee)
            caller_nonce[callee] = caller_nonce.get(callee, True) and n_dom
            caller_cap[callee] = caller_cap.get(callee, True) and c_dom

    def _ep(name):
        return ep_of.get(name, ("unknown",))[0] if ep_of else "unknown"

    for f in fn_facts:
        if not f.sinks or not f.reads_request:
            continue
        ep = _ep(f.name)
        directly_registered = f.name in handler_names
        cn = (f.name in seen_callee) and caller_nonce.get(f.name, False) and not directly_registered
        cc = (f.name in seen_callee) and caller_cap.get(f.name, False) and not directly_registered
        rest_ok = f.name in rest_guarded
        admin_ok = (f.name in admin_capped) or ep == "admin"
        for (line, desc, n_dom, c_dom) in f.sinks:
            n_def = 0.0 if (n_dom or cn) else 1.0
            c_def = 0.0 if (c_dom or cc or rest_ok or admin_ok) else 1.0
            if ep == "admin":
                c_def *= 0.3
            elif ep == "unknown":
                n_def *= 0.85
                c_def *= 0.85
            yield (f.abs_file, f.name, line, desc, "csrf", n_def, f.via_superglobal)
            yield (f.abs_file, f.name, line, desc, "auth", c_def, f.via_superglobal)


def emit_missing_guards(cache, rel_of, ep_of=None, handler_names=frozenset()):
    """Dominance-based missing-guard emission (WISP_GDA_EMIT=1). Emits a CSRF/auth
    Finding for every state-change sink NOT protected by a dominating or
    inter-procedural guard - recovering the branch-specific and after-mutation
    guards the presence test suppresses, while dropping the caller/REST/admin
    over-reports it produces. Confidence and guard_deficit both carry the deficit."""
    from .taint_ast import Finding
    out = []
    seen = set()
    for abs_file, fn, line, desc, kind, deficit, via_sg in _iter_sink_deficits(
            cache, ep_of, handler_names):
        if deficit <= 0.0:
            continue
        # REST handlers carry cookie+nonce CSRF protection via the REST infra, so
        # only flag CSRF for superglobal-based handlers (matches taint_guards).
        if kind == "csrf" and not via_sg:
            continue
        key = (abs_file, line, kind)
        if key in seen:
            continue
        seen.add(key)
        rel = rel_of.get(abs_file, abs_file)
        conf = round(0.30 + 0.30 * deficit, 3)
        if kind == "csrf":
            msg = (f"State change ({desc}) reachable from request with no nonce "
                   f"check dominating it (CSRF)")
            trace = [f"request -> {desc} in {fn}() with no dominating nonce guard @ {rel}:{line}"]
        else:
            msg = (f"State change ({desc}) reachable from request with no capability "
                   f"check dominating it (broken access control)")
            trace = [f"request -> {desc} in {fn}() with no dominating capability guard @ {rel}:{line}"]
        f = Finding(file=rel, abs_file=abs_file, line=line, vuln_class=kind,
                    message=msg, source="request", sink=desc, trace=trace,
                    confidence=conf)
        f.guard_deficit = deficit
        out.append(f)
    return out


def compute_deficits(cache, ep_of=None, handler_names=frozenset()):
    """Plugin-level guard-deficit map.

    Returns ``{abs_file: {(sink_line, kind): deficit}}`` where kind is "csrf"
    (nonce) or "auth" (capability) and deficit is in ``[0, 1]``. Higher = less
    protected = rank sooner. ``ep_of`` (function name -> (entry_point, hook)) is the
    handler-level entry-point map; when present, an unauthenticated entry point
    keeps the deficit high and an admin-only entry point relaxes the capability
    deficit. ``handler_names`` is the set of functions registered DIRECTLY on a hook
    (as opposed to merely reachable from one) — only those forfeit caller-side guard
    credit, since they can be entered without passing through a guarding caller.
    """
    # pass 1: per-function facts + name->facts index (last def wins on name clash,
    # matching the engine's name-keyed summary table).
    fn_facts = []
    by_name = {}
    for abs_file, (src, funcs) in cache.items():
        for fn in funcs:
            f = _collect_fn_facts(fn, src, abs_file)
            fn_facts.append(f)
            by_name.setdefault(f.name, []).append(f)

    rest_guarded = _rest_permission_callbacks(cache)
    admin_capped = _admin_cap_registered(cache)

    # pass 2: caller-side guard aggregation. A function is caller-nonce/cap-guarded
    # iff it has >=1 caller and EVERY caller dominates its call site with that guard.
    caller_nonce, caller_cap = {}, {}
    seen_callee = set()
    for f in fn_facts:
        for callee, (n_dom, c_dom) in f.guards_callsites.items():
            seen_callee.add(callee)
            pn = caller_nonce.get(callee, True)
            pc = caller_cap.get(callee, True)
            caller_nonce[callee] = pn and n_dom
            caller_cap[callee] = pc and c_dom

    def _ep_of(name):
        if ep_of is None:
            return "unknown"
        return ep_of.get(name, ("unknown",))[0]

    out = {}
    for f in fn_facts:
        if not f.sinks:
            continue
        ep = _ep_of(f.name)
        # A handler registered DIRECTLY on a hook is reachable without passing
        # through a guarding caller, so it forfeits caller-side guard credit. A
        # function merely *reachable* from a handler (ep propagated through the call
        # graph) still gets credit when every caller guards the call site.
        directly_registered = f.name in handler_names
        cn = (f.name in seen_callee) and caller_nonce.get(f.name, False) and not directly_registered
        cc = (f.name in seen_callee) and caller_cap.get(f.name, False) and not directly_registered
        rest_ok = f.name in rest_guarded
        admin_ok = (f.name in admin_capped) or ep == "admin"
        for (line, desc, n_dom, c_dom) in f.sinks:
            # nonce (CSRF) deficit
            nonce_ok = n_dom or cn
            n_def = 0.0 if nonce_ok else 1.0
            # capability (auth) deficit
            cap_ok = c_dom or cc or rest_ok or admin_ok
            c_def = 0.0 if cap_ok else 1.0
            # entry-point reachability shaping: an unauthenticated reach with no
            # adequate guard is the maximal-exploit case; a purely admin context
            # discounts the capability deficit (privilege already required).
            if ep == "ajax_nopriv" or ep == "rest_api":
                pass                       # keep full deficit
            elif ep == "admin":
                c_def *= 0.3               # admin already needs a login/cap
            elif ep == "unknown":
                # not resolved to any entry point: mild discount (may be internal)
                n_def *= 0.85
                c_def *= 0.85
            fm = out.setdefault(f.abs_file, {})
            fm[(line, "csrf")] = max(fm.get((line, "csrf"), 0.0), n_def)
            fm[(line, "auth")] = max(fm.get((line, "auth"), 0.0), c_def)
    return out
