"""WISP taint engine — data types + pure tree-sitter AST helpers.

These have no dependency on the taint vocabulary or engine state: they only
read tree-sitter nodes and source bytes. Kept separate so the engine module is
the algorithm, not the boilerplate.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Finding:
    file: str
    abs_file: str
    line: int
    vuln_class: str
    message: str
    source: str           # e.g. "$_GET" or "param $id of foo()"
    sink: str             # e.g. "$wpdb->query" / "echo" / "include"
    trace: list = field(default_factory=list)   # ["source @ file:line", ...]
    interprocedural: bool = False
    confidence: float = 0.6
    entry_point: str = "unknown"   # [Paper13] ajax_nopriv|ajax_auth|rest_api|shortcode|admin|unknown
    entry_point_name: str = ""     # specific hook/route name e.g. "wp_ajax_nopriv_tutor_delete"
    function: str = ""             # function/method at the primary reported location
    # Inter-procedural findings retain the ultimate sink separately while keeping
    # file/line at the tainted callsite for backward-compatible triage semantics.
    sink_file: str = ""
    sink_abs_file: str = ""
    sink_line: int = 0
    sink_function: str = ""
    # inter-procedural guard-dominance deficit in [0,1] for missing-guard findings
    # (taint_guardflow.GDA): 1 = no adequate nonce/capability guard dominates the
    # sink on any path (incl. caller/route/registration); 0 = a guard dominates it.
    # -1 = not a missing-guard finding (deficit does not apply). Ranking signal only.
    guard_deficit: float = -1.0


@dataclass(frozen=True)
class _SinkEffect:
    """A parameter-to-sink effect retained in an inter-procedural summary."""
    vuln_class: str
    sink: str
    file: str
    abs_file: str
    line: int
    function: str


@dataclass
class _Summary:
    name: str
    param_names: list           # ordered param variable names ($id, ...)
    tainted_params_to_sink: dict   # param_index -> tuple[_SinkEffect, ...]
    returns_tainted_from: set      # set of param indices whose taint reaches return
    returns_source_tainted: bool   # function returns request data directly
    sanitizes_param: set           # params that are sanitized before any sink
    # Sink classes for which a returned parameter/source has been neutralized.
    # Keeps esc_html()/esc_sql() semantics across helper boundaries.
    return_safe_for: dict = field(default_factory=dict)  # param_index -> frozenset
    source_return_safe_for: frozenset = field(default_factory=frozenset)
    # Classes suppressed by source policy (e.g. persistent settings are scoped
    # to executable-data sinks), not by an encoding sanitizer. Decoders must not
    # invalidate this policy safety.
    source_return_scoped_for: frozenset = field(default_factory=frozenset)
    return_invalidates_for: dict = field(default_factory=dict)  # param -> frozenset
    # Parameter-to-property side effects, used for setter-style OO flows such as
    # set_raw($_GET['x']) -> $this->raw -> echo in another method.
    # param_index -> {canonical_property_key: taint-value template}
    tainted_params_to_props: dict = field(default_factory=dict)
    is_method: bool = False


# --------------------------------------------------------------------------- #
# AST helpers
# --------------------------------------------------------------------------- #
def _text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "ignore")


def _child(node, *types):
    for c in node.children:
        if c.type in types:
            return c
    return None


def _descend_calls(node):
    """Yield call expression nodes anywhere under node."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("function_call_expression", "member_call_expression",
                      "scoped_call_expression"):
            yield n
        stack.extend(n.children)


def _call_name(node, src: bytes) -> str:
    """Best-effort callee name for a call node."""
    if node.type == "function_call_expression":
        fn = node.children[0]
        return _text(fn, src)
    if node.type == "member_call_expression":
        nm = _child(node, "name")
        return _text(nm, src) if nm else ""
    if node.type == "scoped_call_expression":
        nm = _child(node, "name")
        return _text(nm, src) if nm else ""
    return ""


def _args(node):
    a = _child(node, "arguments")
    if not a:
        return []
    return [c for c in a.children if c.type not in ("(", ")", ",")]


def _iter_var_names(node, src: bytes):
    """Yield variable_name texts anywhere under `node` (foreach as-targets)."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "variable_name":
            yield _text(n, src)
        stack.extend(n.children)


def _collect_functions(root, src: bytes) -> list:
    funcs = []
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type in ("function_definition", "method_declaration"):
            funcs.append(n)
        stack.extend(n.children)
    return funcs


def _param_names(fn, src: bytes) -> list:
    out = []
    params = _child(fn, "formal_parameters", "parameters")
    if not params:
        return out
    for c in params.children:
        if c.type in ("simple_parameter", "property_promotion_parameter",
                      "variadic_parameter"):
            v = _child(c, "variable_name")
            if v:
                out.append(_text(v, src))
    return out


def _fn_name(fn, src: bytes) -> str:
    nm = _child(fn, "name")
    return _text(nm, src) if nm else "@anonymous"


_LITERAL_NODES = ("string", "encapsed_string", "integer", "float", "boolean",
                  "null", "heredoc")


def _is_literal(node) -> bool:
    if node.type == "argument":          # _args() returns argument wrappers
        named = [c for c in node.children if c.is_named]
        node = named[0] if named else node
    return node.type in _LITERAL_NODES
