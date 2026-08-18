"""Inter-procedural taint engine (AST-based) — WISP detector #2.

Semgrep is an intra-procedural pattern matcher: it sees a single function at a
time and misses vulnerabilities whose source and sink live in different
functions (the dominant miss class measured in the pilot: auth / object-injection
and cross-function SQLi/XSS). This module adds a real data-flow detector built
on a tree-sitter PHP AST:

  1. Parse every PHP file to an AST and collect function/method definitions.
  2. Compute a *taint summary* per function: for each parameter, does tainting
     it reach a dangerous sink with no effective sanitizer on the path? Does the
     function return tainted data (a pass-through)? Does it read a request
     superglobal that itself reaches a sink (a self-contained flaw)?
  3. Re-analyze each body with concrete taint state, and at every call site
     consult the callee summary to raise *inter-procedural* findings and to
     propagate taint through return values. Iterate summaries to a fixpoint so
     transitive A->B->C flows are caught.

Sanitizers (WordPress escapers/validators, `$wpdb->prepare`, integer casts)
clear taint, which is what keeps precision high. Each finding carries an
explicit source->sink trace, so the consensus layer and the LLM verifier get a
real data-flow story rather than a lone pattern hit.

Companion modules:
  * taint_vocab   — rule-driven source/sink/sanitizer/guard vocabulary
  * taint_ast     — Finding/_Summary data types + pure tree-sitter helpers
  * taint_guards  — framework-aware CSRF / access-control detector
"""
from __future__ import annotations
import os
import re
from collections import deque
from dataclasses import dataclass, field

# Vocab, AST helpers and the guard detector live in sibling modules so this file
# is the data-flow algorithm itself, not the boilerplate/config around it.
try:
    from .taint_vocab import (SUPERGLOBALS, REST_READ_METHODS, SOURCE_FUNCS,
        SINK_FUNCS, WPDB_SQL_METHODS, DB_SINK_FUNCS, SANITIZERS, METHOD_SINKS,
        SANITIZERS_BY_CLASS, SANITIZERS_UNIVERSAL,
        STATE_CHANGE_FUNCS, STATE_CHANGE_WPDB, GUARD_NONCE, GUARD_CAP,
        SAFE_MEMBERS, PREDICATE_FUNCS, PATTERN_ONLY_SINKS, RULES)
    from .taint_ast import (Finding, _SinkEffect, _Summary, _text, _child, _descend_calls,
        _call_name, _args, _iter_var_names, _collect_functions, _param_names,
        _fn_name, _is_literal)
    from .taint_guards import _detect_missing_guards
except ImportError:  # pragma: no cover - support flat imports
    from taint_vocab import (SUPERGLOBALS, REST_READ_METHODS, SOURCE_FUNCS,
        SINK_FUNCS, WPDB_SQL_METHODS, DB_SINK_FUNCS, SANITIZERS, METHOD_SINKS,
        SANITIZERS_BY_CLASS, SANITIZERS_UNIVERSAL,
        STATE_CHANGE_FUNCS, STATE_CHANGE_WPDB, GUARD_NONCE, GUARD_CAP,
        SAFE_MEMBERS, PREDICATE_FUNCS, PATTERN_ONLY_SINKS, RULES)
    from taint_ast import (Finding, _SinkEffect, _Summary, _text, _child, _descend_calls,
        _call_name, _args, _iter_var_names, _collect_functions, _param_names,
        _fn_name, _is_literal)
    from taint_guards import _detect_missing_guards

_PARSER = None


def _parser():
    global _PARSER
    if _PARSER is None:
        import tree_sitter_php as tsphp
        from tree_sitter import Language, Parser
        _PARSER = Parser(Language(tsphp.language_php()))
    return _PARSER


# Object/static properties found to receive attacker-tainted data anywhere in the
# plugin (e.g. `$this->raw = $_POST[...]`). Reset per plugin in detect(); a read of
# such a property is then treated as tainted across methods/files. This recovers the
# very common WordPress OO pattern where one method stashes request data on a
# property and another method sinks it. Conservative (field-/object-insensitive).
TAINTED_PROPS: dict = {}

# SOURCE_FUNCS contains both transforms (wp_unslash/apply_filters) and APIs that
# create attacker-influenced data without a tainted argument. Keep those
# semantics explicit: treating get_option('literal_key') as clean made the
# declared second-order source vocabulary dead code.
_DIRECT_REQUEST_SOURCES = {
    "filter_input", "filter_input_array", "getallheaders",
    "apache_request_headers",
}
_REQUEST_ENV_KEYS = frozenset({
    "QUERY_STRING", "REQUEST_URI", "REMOTE_ADDR", "HTTP_HOST",
    "HTTP_USER_AGENT", "HTTP_REFERER", "CONTENT_TYPE", "CONTENT_LENGTH",
})
_FILTER_VALUE_VALIDATORS = frozenset({
    "FILTER_VALIDATE_INT", "FILTER_VALIDATE_FLOAT", "FILTER_VALIDATE_BOOLEAN",
    "FILTER_SANITIZE_NUMBER_INT", "FILTER_SANITIZE_NUMBER_FLOAT",
})
_PERSISTENT_SOURCES = {
    "get_option", "get_post_meta", "get_user_meta", "get_term_meta",
    "get_transient", "get_site_option", "get_comment_meta",
}
# Treat persistent configuration as attacker-influenced only at high-risk
# executable-data boundaries. Marking every get_option()/get_meta() result as a
# universal source floods ordinary settings rendering and SQL lookups; the
# benchmark ablation increased E2PDF findings 3->81 without improving its target
# flow. Code evaluation, deserialization and filesystem paths remain meaningful
# second-order risks.
_PERSISTENT_RISK_CLASSES = frozenset({"rce", "deserial", "lfi"})
_TRACKED_SINK_CLASSES = frozenset({
    "xss", "sqli", "lfi", "upload", "ssrf", "rce", "deserial", "other",
})
_SANITIZER_INVALIDATORS = {
    "htmlspecialchars_decode": frozenset({"xss"}),
    "html_entity_decode": frozenset({"xss"}),
}

# Namespace/class-qualified identities are the safe default.  Explicit
# WISP_QUALIFIED_SUMMARIES=0 retains the old terminal-name ablation.
_QUALIFIED = os.environ.get("WISP_QUALIFIED_SUMMARIES", "1") != "0"

_CLASSLIKE = ("class_declaration", "trait_declaration",
              "interface_declaration", "enum_declaration")
_NAMESPACE_CACHE: dict = {}
# Canonical (case-insensitive) PHP class hierarchy for the plugin currently
# being analysed.  Method names/classes are case-insensitive in PHP; property
# names are not, so property-key construction deliberately handles them
# separately below.
_CLASS_PARENTS: dict[str, str] = {}
_CLASS_CHILDREN: dict[str, set[str]] = {}
_MERGED_SUMMARY_CACHE: dict[tuple, _Summary] = {}
_RECEIVER_TYPE_CACHE: dict[tuple, tuple] = {}


def _enclosing_class_name(node, src) -> str | None:
    p = node.parent
    while p is not None:
        if p.type in _CLASSLIKE:
            nm = _child(p, "name")
            return _text(nm, src) if nm else None
        p = p.parent
    return None


def _lexical_namespace(node, src) -> str:
    """Return the PHP namespace active at ``node`` (without leading slash).

    Braced namespaces are ancestors. Semicolon namespaces are preceding
    top-level namespace_definition siblings, so they require a small lexical
    scan from the program root.
    """
    cache_key = (id(src), node.start_byte, node.end_byte, node.type)
    cached = _NAMESPACE_CACHE.get(cache_key)
    if cached is not None and cached[0] is src:
        return cached[1]

    p = node.parent
    while p is not None:
        if p.type == "namespace_definition":
            ns = _child(p, "namespace_name")
            if _child(p, "compound_statement") is not None:
                result = _text(ns, src).strip("\\") if ns else ""
                _NAMESPACE_CACHE[cache_key] = (src, result)
                return result
        p = p.parent

    top = node
    while top.parent is not None and top.parent.type != "program":
        top = top.parent
    program = top.parent if top.parent is not None else None
    current = ""
    if program is not None:
        for sibling in program.children:
            if sibling is top:
                break
            if (sibling.type == "namespace_definition"
                    and _child(sibling, "compound_statement") is None):
                ns = _child(sibling, "namespace_name")
                current = _text(ns, src).strip("\\") if ns else ""
    _NAMESPACE_CACHE[cache_key] = (src, current)
    return current


def _resolve_code_name(raw: str, namespace: str) -> str:
    """Resolve a PHP code identifier to an absolute name (no leading slash).

    Import aliases are intentionally outside this lightweight resolver; explicit
    root names and ordinary namespace-relative names are handled exactly.
    """
    raw = (raw or "").strip()
    if raw.startswith("\\"):
        return raw.lstrip("\\")
    if raw.lower().startswith("namespace\\"):
        raw = raw.split("\\", 1)[1]
    return "\\".join(part for part in (namespace.strip("\\"), raw) if part)


def _free_key(fq_name: str) -> str:
    return "F:\\" + fq_name.strip("\\").casefold()


def _method_key(fq_class: str, method: str) -> str:
    return "M:\\" + fq_class.strip("\\").casefold() + "::" + method.casefold()


def _class_id(fq_class: str) -> str:
    return (fq_class or "").strip("\\").casefold()


def _reset_class_hierarchy() -> None:
    _CLASS_PARENTS.clear()
    _CLASS_CHILDREN.clear()
    _MERGED_SUMMARY_CACHE.clear()
    _RECEIVER_TYPE_CACHE.clear()


def _collect_class_hierarchy(root, src) -> None:
    """Collect exact ``class Child extends Parent`` relationships.

    This intentionally resolves ordinary namespace-relative and root-qualified
    names only. PHP import aliases remain unresolved instead of being guessed.
    """
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "class_declaration":
            name_node = _child(node, "name")
            base = _child(node, "base_clause")
            if name_node is not None and base is not None:
                namespace = _lexical_namespace(node, src)
                child = _class_id(_resolve_code_name(
                    _text(name_node, src), namespace))
                raw_base = re.sub(r"^\s*extends\s+", "", _text(base, src),
                                  flags=re.IGNORECASE).strip()
                parent = _class_id(_resolve_code_name(raw_base, namespace))
                if child and parent and child != parent:
                    _CLASS_PARENTS[child] = parent
        stack.extend(node.children)


def _finish_class_hierarchy() -> None:
    _CLASS_CHILDREN.clear()
    for child, parent in _CLASS_PARENTS.items():
        _CLASS_CHILDREN.setdefault(parent, set()).add(child)
    _MERGED_SUMMARY_CACHE.clear()


def _method_impl_key(fq_class: str, method: str, summaries: dict) -> str | None:
    """Nearest implementation of ``method`` visible from ``fq_class``."""
    current = _class_id(fq_class)
    seen = set()
    while current and current not in seen:
        seen.add(current)
        key = _method_key(current, method)
        if key in summaries:
            return key
        current = _CLASS_PARENTS.get(current, "")
    return None


def _class_inherits(fq_class: str, expected_parent: str) -> bool:
    current = _class_id(fq_class)
    target = _class_id(expected_parent)
    seen = set()
    while current and current not in seen:
        seen.add(current)
        current = _CLASS_PARENTS.get(current, "")
        if current == target:
            return True
    return False


def _virtual_method_keys(fq_class: str, method: str, summaries: dict) -> list[str]:
    """All implementations reachable by a virtual ``$this``/``static`` call.

    A call in a base method can dispatch to an override in any known subclass.
    Each runtime class contributes its nearest implementation; duplicate
    inherited implementations are collapsed.
    """
    root = _class_id(fq_class)
    runtime_classes = [root]
    pending = list(_CLASS_CHILDREN.get(root, ()))
    while pending:
        child = pending.pop()
        runtime_classes.append(child)
        pending.extend(_CLASS_CHILDREN.get(child, ()))
    keys = []
    for runtime_class in runtime_classes:
        key = _method_impl_key(runtime_class, method, summaries)
        if key is not None and key not in keys:
            keys.append(key)
    return keys


def _merge_method_summaries(keys: list[str], summaries: dict) -> _Summary | None:
    """Conservatively union possible virtual-dispatch outcomes."""
    available = [(key, summaries[key]) for key in keys if key in summaries]
    if not available:
        return None
    if len(available) == 1:
        return available[0][1]
    cache_key = tuple((key, id(summary)) for key, summary in available)
    cached = _MERGED_SUMMARY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    candidates = [summary for _key, summary in available]
    template = max(candidates, key=lambda summary: len(summary.param_names))
    merged = _Summary(
        template.name, list(template.param_names), {}, set(), False, set(),
        is_method=True)
    all_indices = set()
    for summary in candidates:
        all_indices.update(summary.tainted_params_to_sink)
        all_indices.update(summary.returns_tainted_from)
        all_indices.update(summary.tainted_params_to_props)
    for index in all_indices:
        effects = []
        for summary in candidates:
            for effect in summary.tainted_params_to_sink.get(index, ()):
                if effect not in effects:
                    effects.append(effect)
        if effects:
            merged.tainted_params_to_sink[index] = tuple(effects)

        prop_effects = {}
        for summary in candidates:
            for prop_key, value in summary.tainted_params_to_props.get(
                    index, {}).items():
                prop_effects[prop_key] = _tv_join(
                    prop_effects.get(prop_key), value)
        if prop_effects:
            merged.tainted_params_to_props[index] = prop_effects

        returning = [summary for summary in candidates
                     if index in summary.returns_tainted_from]
        if returning:
            merged.returns_tainted_from.add(index)
            safety = set(_TRACKED_SINK_CLASSES)
            for summary in returning:
                safety.intersection_update(summary.return_safe_for.get(index, ()))
            if safety:
                merged.return_safe_for[index] = frozenset(safety)
            invalidates = set()
            for summary in returning:
                invalidates.update(summary.return_invalidates_for.get(index, ()))
            if invalidates:
                merged.return_invalidates_for[index] = frozenset(invalidates)

    source_returning = [summary for summary in candidates
                        if summary.returns_source_tainted]
    if source_returning:
        merged.returns_source_tainted = True
        safety = set(_TRACKED_SINK_CLASSES)
        scoped = set(_TRACKED_SINK_CLASSES)
        for summary in source_returning:
            safety.intersection_update(summary.source_return_safe_for)
            scoped.intersection_update(summary.source_return_scoped_for)
        merged.source_return_safe_for = frozenset(safety)
        merged.source_return_scoped_for = frozenset(scoped)
    _MERGED_SUMMARY_CACHE[cache_key] = merged
    return merged


def _unwrap_expression(node):
    current = node
    while current is not None and current.type in (
            "parenthesized_expression", "argument"):
        named = [child for child in current.children if child.is_named]
        current = named[-1] if named else None
    return current


def _new_expression_class(node, src) -> str | None:
    current = _unwrap_expression(node)
    if current is None or current.type != "object_creation_expression":
        return None
    named = [child for child in current.children if child.is_named
             and child.type != "arguments"]
    if not named:
        return None
    raw = _text(named[0], src)
    if raw.casefold() in ("self", "static"):
        return _enclosing_class_fq(node, src)
    if raw.casefold() == "parent":
        current_class = _enclosing_class_fq(node, src)
        return _CLASS_PARENTS.get(_class_id(current_class or ""))
    return _resolve_code_name(raw, _lexical_namespace(node, src))


def _typed_receiver_classes(call, obj, src) -> tuple[tuple[str, bool], ...]:
    """Infer safe local receiver types for a member call.

    The bool marks a declared type (runtime subclasses possible) versus an exact
    ``new Class`` assignment. Unknown/reassigned variables remain unresolved.
    """
    direct = _new_expression_class(obj, src)
    if direct:
        return ((direct, False),)
    if obj.type != "variable_name":
        return ()
    variable = _text(obj, src)
    scope = call
    while scope is not None and scope.type not in (
            "function_definition", "method_declaration", "program"):
        scope = scope.parent
    if scope is None:
        return ()
    cache_key = (id(src), scope.start_byte, scope.end_byte,
                 call.start_byte, variable)
    cached = _RECEIVER_TYPE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    assignments = []
    stack = [scope]
    while stack:
        current = stack.pop()
        if current is not scope and current.type in _SKIP_SUBTREE:
            continue
        if (current.type == "assignment_expression"
                and current.start_byte < call.start_byte
                and current.children
                and current.children[0].type == "variable_name"
                and _text(current.children[0], src) == variable):
            rhs = current.children[-1]
            assignments.append((current.start_byte,
                                _new_expression_class(rhs, src)))
        stack.extend(current.children)
    if assignments:
        assignments.sort()
        # Resolve only when every observed write has a concrete object type.
        # A later arbitrary reassignment makes the runtime receiver unknown.
        classes = []
        for _position, cls in assignments:
            if not cls:
                _RECEIVER_TYPE_CACHE[cache_key] = ()
                return ()
            if cls not in classes:
                classes.append(cls)
        result = tuple((cls, False) for cls in classes)
        _RECEIVER_TYPE_CACHE[cache_key] = result
        return result

    params = _child(scope, "formal_parameters", "parameters")
    if params is not None:
        for param in params.children:
            var_node = _child(param, "variable_name")
            type_node = _child(param, "named_type", "optional_type",
                               "union_type", "intersection_type")
            if (var_node is None or type_node is None
                    or _text(var_node, src) != variable):
                continue
            # Only a single named class is unambiguous; union/intersection types
            # require richer PHP type semantics and therefore fail closed.
            if type_node.type != "named_type":
                break
            cls = _resolve_code_name(
                _text(type_node, src), _lexical_namespace(param, src))
            result = ((cls, True),) if cls else ()
            _RECEIVER_TYPE_CACHE[cache_key] = result
            return result
    _RECEIVER_TYPE_CACHE[cache_key] = ()
    return ()


def _enclosing_class_fq(node, src) -> str | None:
    cls = _enclosing_class_name(node, src)
    return _resolve_code_name(cls, _lexical_namespace(node, src)) if cls else None


def _property_summary_key(node, src) -> str:
    """Class-qualify properties without changing case-sensitive field names."""
    raw = _text(node, src)
    if node.type in ("member_access_expression",
                     "nullsafe_member_access_expression"):
        receiver = _text(node.children[0], src) if node.children else ""
        if receiver != "$this":
            return raw
        cls = _enclosing_class_fq(node, src)
        if cls:
            prop = _text(node.children[-1], src)
            return "P:\\" + cls.casefold() + "->" + prop
        return raw
    if node.type == "scoped_property_access_expression" and node.children:
        receiver = _text(node.children[0], src).strip()
        prop = _text(node.children[-1], src)
        current = _enclosing_class_fq(node, src)
        lowered = receiver.casefold()
        if lowered in ("self", "static"):
            cls = current
        elif lowered == "parent":
            cls = _CLASS_PARENTS.get(_class_id(current or ""))
        else:
            cls = _resolve_code_name(
                receiver, _lexical_namespace(node, src))
        if cls:
            return "P:\\" + _class_id(cls) + "::" + prop
    return raw


def _summary_key(fn, src) -> str:
    name = _fn_name(fn, src)
    if not _QUALIFIED:
        return name
    if fn.type == "method_declaration":
        cls = _enclosing_class_fq(fn, src)
        if cls:
            return _method_key(cls, name)
    return _free_key(_resolve_code_name(name, _lexical_namespace(fn, src)))


def _lookup_summary_keys(node, name, summaries, src) -> list[str]:
    """Resolve a call node to all soundly reachable summary keys.

    Qualified mode follows PHP lexical namespaces for free/static calls and
    class inheritance for methods. Dynamic receivers fail closed rather than
    borrowing an unrelated same-named method from elsewhere in the plugin.
    """
    if not _QUALIFIED:
        return [name] if name in summaries else []
    if node.type == "function_call_expression":
        raw = _call_name(node, src)
        namespace = _lexical_namespace(node, src)
        if raw.startswith("\\"):
            candidates = [_free_key(raw)]
        elif raw.lower().startswith("namespace\\") or "\\" in raw:
            candidates = [_free_key(_resolve_code_name(raw, namespace))]
        else:
            candidates = []
            if namespace:
                candidates.append(_free_key(_resolve_code_name(raw, namespace)))
            candidates.append(_free_key(raw))       # PHP global fallback
        for key in candidates:
            if key in summaries:
                return [key]
        return []
    if node.type == "scoped_call_expression":
        raw_recv = _text(node.children[0], src)
        recv = raw_recv.lstrip("\\").casefold()
        cls = _enclosing_class_fq(node, src)
        if recv == "static" and cls:
            return _virtual_method_keys(cls, name, summaries)
        if recv == "parent" and cls:
            parent = _CLASS_PARENTS.get(_class_id(cls))
            key = _method_impl_key(parent or "", name, summaries)
            return [key] if key else []
        if recv == "self" and cls:
            key = _method_impl_key(cls, name, summaries)
            return [key] if key else []
        cls = _resolve_code_name(raw_recv, _lexical_namespace(node, src))
        key = _method_impl_key(cls, name, summaries)
        return [key] if key else []
    elif node.type == "member_call_expression":
        obj = node.children[0]
        if obj.type == "variable_name" and _text(obj, src) == "$this":
            cls = _enclosing_class_fq(node, src)
            if cls:
                return _virtual_method_keys(cls, name, summaries)
            return []
        typed_keys = []
        for cls, is_declared_type in _typed_receiver_classes(
                node, obj, src):
            candidates = (_virtual_method_keys(cls, name, summaries)
                          if is_declared_type
                          else [_method_impl_key(cls, name, summaries)])
            for key in candidates:
                if key and key not in typed_keys:
                    typed_keys.append(key)
        if typed_keys:
            return typed_keys
        # Runtime type is unknown. Binding it to the only same-named method
        # declared anywhere in the plugin can import an unrelated sanitizer or
        # sink and is less sound than ordinary unknown-call pass-through.
        return []
    return []


def _lookup_summary(node, name, summaries, src):
    keys = _lookup_summary_keys(node, name, summaries, src)
    return _merge_method_summaries(keys, summaries) if keys else None


def _is_global_vocab_call(node, src, summaries) -> bool:
    """Whether a call may use PHP/WordPress global source/sink vocabulary.

    A concrete plugin summary shadows an unqualified core-like name. Qualified
    vendor names never inherit semantics merely from their terminal basename.
    """
    if node.type != "function_call_expression":
        return False
    raw = _call_name(node, src)
    short = raw.lstrip("\\").split("\\")[-1]
    summ = _lookup_summary(node, short, summaries, src)
    if summ is not None and not summ.is_method:
        return False
    if raw.startswith("\\"):
        return "\\" not in raw[1:]
    return "\\" not in raw


# --- class-scoped sanitizer propagation (reviewer 2.6; default ON) ----------- #
_CLASS_SANITIZER_NAMES = frozenset(
    name for names in SANITIZERS_BY_CLASS.values() for name in names)
_CLASS_SENSITIVE_CALL_RE = re.compile(
    r"(?:^|[^\w])(?:"
    + "|".join(re.escape(name) for name in sorted(
        _CLASS_SANITIZER_NAMES.union(_PERSISTENT_SOURCES), key=len, reverse=True))
    + r")\s*\("
)


def _tv_label(v):
    """Taint-map values are either a source-label string or a
    (label, frozenset-of-sanitized-classes) tuple. Return the label."""
    return v[0] if isinstance(v, tuple) else v


def _tv_sani(v):
    """Return the set of classes a taint value has been sanitized for."""
    return v[1] if isinstance(v, tuple) else frozenset()


_RAW_CLASS_PROBE = "__taint_raw_class__:"


def _effective_sink_class(sink_class):
    if isinstance(sink_class, str) and sink_class.startswith(_RAW_CLASS_PROBE):
        return sink_class[len(_RAW_CLASS_PROBE):]
    return sink_class


def _ignores_class_safety(sink_class) -> bool:
    return (sink_class == "__taint_probe__"
            or (isinstance(sink_class, str)
                and sink_class.startswith(_RAW_CLASS_PROBE)))


def _tv_read(v, sink_class):
    """Read a taint value against a sink class: clean iff the value was
    sanitized for exactly this class. Returns (tainted?, label)."""
    effective = _effective_sink_class(sink_class)
    if (not _ignores_class_safety(sink_class) and effective is not None
            and effective in _tv_sani(v)):
        return False, ""
    return True, _tv_label(v)


def _tv_join(left, right):
    """Join two taint values used in concatenation / augmented assignment.

    A composed value is safe for a sink class only when *every* tainted part is
    safe for that class, hence intersection of the sanitizer-class sets.
    """
    if left is None:
        return right
    if right is None:
        return left
    safe_for = _tv_sani(left).intersection(_tv_sani(right))
    label = _tv_label(left) or _tv_label(right)
    return (label, frozenset(safe_for)) if safe_for else label


def _sani_class_enabled() -> bool:
    """Context-specific sanitizer propagation; WISP_SANI_CLASS=0 is ablation."""
    return os.environ.get("WISP_SANI_CLASS", "1") != "0"


def _param_prop_enabled() -> bool:
    """Setter parameter-to-property summaries; env switch is benchmark ablation."""
    return os.environ.get("WISP_PARAM_PROP", "1") != "0"


# --------------------------------------------------------------------------- #
# Expression taint
# --------------------------------------------------------------------------- #
class _Analyzer:
    def __init__(self, src: bytes, rel: str, abs_file: str, summaries: dict,
                 extra_sources=None, return_xss_context: str = "",
                 render_return_vars=frozenset(), render_seed_vars=frozenset(),
                 framework_contexts=frozenset(), acf_field_param: str = ""):
        self.src = src
        self.rel = rel
        self.abs = abs_file
        self.summaries = summaries
        self.findings: list[Finding] = []
        # context-seeded sources (e.g. $attributes in a block render template,
        # $atts in a shortcode handler) — attacker-influenced like a superglobal.
        self.extra_sources = dict(extra_sources or {})
        # WordPress shortcode/block render callbacks produce HTML by returning a
        # string rather than echoing it.  Restrict this sink to callbacks proven
        # by a registration site; a generic PHP return is not an output sink.
        self.return_xss_context = return_xss_context
        self.render_return_vars = frozenset(render_return_vars)
        self.render_seed_vars = frozenset(render_seed_vars)
        self.framework_contexts = frozenset(framework_contexts)
        self.acf_field_param = acf_field_param
        self.render_candidates: dict[str, list[Finding]] = {}
        self.render_flushed: set[int] = set()
        self.branch_depth = 0
        # Summary-only return probe. It deliberately reuses the concrete
        # statement walker so branch joins and unreachable-code handling stay
        # identical between summary construction and final emission.
        self.probe_returns = False
        self.return_probe_class = None
        self.return_tainted = False
        self.collected_props = None

    def _summary_taint(self, summ, args, taint, sink_class):
        """Apply a callee's class-aware return summary."""
        effective_class = _effective_sink_class(sink_class)
        ignore_safety = _ignores_class_safety(sink_class)
        if (summ.returns_source_tainted
                and (effective_class not in summ.source_return_safe_for
                     or (ignore_safety
                         and effective_class not in summ.source_return_scoped_for))):
            return True, f"return of {summ.name}()"
        for i, arg in enumerate(args):
            safe_for = summ.return_safe_for.get(i, ())
            if not ignore_safety and effective_class in safe_for:
                continue
            probe_class = sink_class
            if effective_class in summ.return_invalidates_for.get(i, ()):
                probe_class = _RAW_CLASS_PROBE + str(effective_class)
            tt, lbl = self.expr_taint(arg, taint, probe_class)
            if tt and i in summ.returns_tainted_from:
                return True, lbl
        return False, ""

    # Does this expression carry taint given current `taint` var set?
    # Returns (tainted, source_label). Sanitizer wrapping clears taint.
    def expr_taint(self, node, taint: dict, sink_class=None) -> tuple[bool, str]:
        """Is `node` tainted? `sink_class` is the vuln class of the sink we are
        evaluating against (xss/sqli/lfi/...). A context-specific sanitizer only
        neutralizes taint when it protects that class — so `esc_sql(...)` does NOT
        clean an XSS sink and `esc_html(...)` does NOT clean a SQL sink. When
        sink_class is None (propagation/assignment), any sanitizer cleans, which
        preserves the previous precision on assigned-then-sanitized values."""
        if node is None:
            return False, ""
        t = node.type

        if t in ("variable_name",):
            name = _text(node, self.src)
            if name in SUPERGLOBALS:
                return True, name
            if name in self.extra_sources:
                return True, self.extra_sources[name]
            if name in taint:
                return _tv_read(taint[name], sink_class)
            # Variable variable ($$x): $$_GET is tainted; $$key where $key is
            # tainted means attacker controls which variable is accessed.
            if name.startswith("$$"):
                inner = name[1:]
                if inner in SUPERGLOBALS or inner in taint:
                    return True, f"variable_variable({name})"
            return False, ""

        if t == "subscript_expression":
            base = node.children[0]
            bt = _text(base, self.src)
            # learned (Stage-4): server-controlled superglobal members are not
            # attacker data, e.g. $_FILES['f']['tmp_name']. Match by the taint
            # LABEL of the base so it also works after `$f = $_FILES['x']`, then
            # `$f['tmp_name']` (the var carries the "$_FILES" origin label).
            named = [c for c in node.children if c.is_named]
            if len(named) > 1 and SAFE_MEMBERS:
                idx_key = _text(named[1], self.src).strip().strip("'\"")
                for sg, members in SAFE_MEMBERS.items():
                    if idx_key in members:
                        _, base_lbl = self.expr_taint(base, taint, sink_class)
                        if base_lbl == sg:
                            return False, ""
            if bt in SUPERGLOBALS:
                return True, bt
            # array element of a tainted array variable -> tainted (key lookup too)
            key = _text(node, self.src)
            if key in taint:
                return _tv_read(taint[key], sink_class)
            return self.expr_taint(base, taint, sink_class)

        if t in ("member_access_expression", "nullsafe_member_access_expression",
                 "scoped_property_access_expression"):
            # object/static property taint, e.g. $this->data, $obj->val, self::$x.
            # WordPress plugins are heavily OO, so request data is routinely stashed
            # on a property and later reaches a sink; tracked by exact text key plus
            # the plugin-wide TAINTED_PROPS summary (cross-method/-file).
            key = _text(node, self.src)
            if key in taint:
                return _tv_read(taint[key], sink_class)
            prop_key = _property_summary_key(node, self.src)
            if prop_key in TAINTED_PROPS:
                return _tv_read(TAINTED_PROPS[prop_key], sink_class)
            # Field reads from an already-tainted decoded/object value preserve
            # the object's origin (e.g. json_decode($request)->label).
            return self.expr_taint(node.children[0], taint, sink_class)

        if t in ("encapsed_string",):          # "...$x..." interpolation
            for c in node.children:
                tt, lbl = self.expr_taint(c, taint, sink_class)
                if tt:
                    return True, lbl
            return False, ""

        if t == "binary_expression":            # concatenation etc.
            for c in (node.children[0], node.children[-1]):
                tt, lbl = self.expr_taint(c, taint, sink_class)
                if tt:
                    return True, lbl
            return False, ""

        if t in ("function_call_expression", "member_call_expression",
                 "scoped_call_expression"):
            name = _call_name(node, self.src).lstrip("\\")
            short = name.split("\\")[-1]
            args = _args(node)
            summ = _lookup_summary(node, short, self.summaries, self.src)
            global_vocab = _is_global_vocab_call(node, self.src, self.summaries)
            if (node.type == "member_call_expression" and short == "prepare"
                    and "wpdb" in _text(node.children[0], self.src)):
                return False, ""                # $wpdb->prepare(...) parameterizes -> safe
            # WP REST input: `$request->get_param('x')` (and siblings) are
            # attacker-controlled request reads — the REST analogue of superglobals.
            # The guard detector already treats REST_READ_METHODS as request reads;
            # the data-flow engine must seed taint from them too, otherwise every
            # REST-handler CVE (register_rest_route callbacks) is missed since the
            # input never enters a superglobal. Method names are distinctive to
            # WP_REST_Request (no overlap with $wpdb SQL methods).
            if (node.type == "member_call_expression"
                    and short in REST_READ_METHODS):
                return True, f"WP_REST_Request->{short}()"
            # apply_filters($hook, $value, ...$context) returns the filtered VALUE
            # (argument 1), not arbitrary context arguments. Treating every arg as
            # pass-through invents taint from metadata supplied only to listeners.
            if short == "apply_filters" and global_vocab:
                return (self.expr_taint(args[1], taint, sink_class)
                        if len(args) >= 2 else (False, ""))
            if global_vocab and short in SANITIZERS:
                # context-aware: a class-specific sanitizer only cleans its own
                # sink class. Universal sanitizers (numeric casts, key/slug, etc.)
                # and the propagation context (sink_class=None) clean everything.
                if short in SANITIZERS_UNIVERSAL or sink_class is None:
                    return False, ""            # sanitized -> clean
                allowed = SANITIZERS_BY_CLASS.get(sink_class, ())
                if short in allowed:
                    return False, ""            # sanitized for THIS sink -> clean
                # wrong-context sanitizer (e.g. esc_sql before an echo): the value
                # is still dangerous here — keep taint flowing from its arguments.
                for a in _args(node):
                    tt, lbl = self.expr_taint(a, taint, sink_class)
                    if tt:
                        return True, lbl
                return False, ""
            effective_class = _effective_sink_class(sink_class)
            invalidated = (_SANITIZER_INVALIDATORS.get(short)
                           if global_vocab else None)
            if invalidated and (effective_class in invalidated
                                or sink_class == "__taint_probe__"):
                # A decoder reverses the corresponding output encoding. Probe
                # its argument while ignoring class-specific safety annotations;
                # universal validators/casts still remain clean.
                raw_probe = ("__taint_probe__" if sink_class == "__taint_probe__"
                             else _RAW_CLASS_PROBE + str(effective_class))
                for a in _args(node):
                    tt, lbl = self.expr_taint(a, taint, raw_probe)
                    if tt:
                        return True, lbl
                return False, ""
            if global_vocab and short in PREDICATE_FUNCS:
                return False, ""                # returns bool/int metadata, not data
            # pass-through / source functions keep or create taint
            if global_vocab and (short in SOURCE_FUNCS or short == "wp_unslash"):
                for a in args:
                    tt, lbl = self.expr_taint(a, taint, sink_class)
                    if tt:
                        return True, lbl
                # Source-creating APIs are global PHP/WP functions. A plugin
                # method coincidentally named get_option()/getenv() must fall
                # through to its own summary instead of becoming a source.
                if short in _DIRECT_REQUEST_SOURCES:
                    if short == "filter_input" and len(args) >= 3:
                        validator = _text(args[2], self.src)
                        if any(token in validator for token in _FILTER_VALUE_VALIDATORS):
                            return False, ""
                    return True, f"request source {short}()"
                if short == "getenv" and args:
                    env_key = _text(args[0], self.src).strip().strip("'\"")
                    if env_key.startswith("HTTP_") or env_key in _REQUEST_ENV_KEYS:
                        return True, f"request environment {env_key}"
                if short in _PERSISTENT_SOURCES:
                    effective_class = _effective_sink_class(sink_class)
                    if (effective_class in _PERSISTENT_RISK_CLASSES
                            or sink_class == "__taint_probe__"):
                        return True, f"persistent source {short}()"
                    return False, ""
                if short in ("file_get_contents", "stream_get_contents"):
                    raw = args and "php://input" in _text(args[0], self.src)
                    if raw:
                        return True, "php://input"
                return False, ""
            # user function returning tainted data (summary pass-through)
            if summ:
                return self._summary_taint(summ, args, taint, sink_class)
            # Unknown / builtin call WITHOUT a summary (sprintf, str_replace,
            # trim, implode, ...): propagate taint from its arguments. The old
            # behavior dropped taint here, which lost most real flows that pass
            # through a helper. Known sanitizers already returned clean above.
            for a in args:
                tt, lbl = self.expr_taint(a, taint, sink_class)
                if tt:
                    return True, lbl
            return False, ""

        if t in ("parenthesized_expression", "cast_expression"):
            # (int)$x etc. -> integer cast sanitizes
            if t == "cast_expression":
                cast = _text(node, self.src).split(")")[0]
                if any(k in cast for k in ("int", "float", "bool")):
                    return False, ""
            # use the last NAMED child, not children[-1]: for a parenthesized
            # expression children[-1] is the ")" token, which silently dropped the
            # taint of everything inside parentheses, e.g. include($_GET[...]).
            named = [c for c in node.children if c.is_named]
            return self.expr_taint(named[-1], taint, sink_class) if named else (False, "")

        if t == "conditional_expression":
            # $cond ? $a : $b  -> only the value branches carry the result taint,
            # NOT the condition. Without this, `isset($_GET['x']) ? (int)$x : 0`
            # is wrongly tainted by the isset() condition.
            named = [c for c in node.children if c.is_named]
            branches = named[1:] if len(named) >= 3 else named  # skip condition
            for b in branches:
                tt, lbl = self.expr_taint(b, taint, sink_class)
                if tt:
                    return True, lbl
            return False, ""

        # default: scan children
        for c in node.children:
            tt, lbl = self.expr_taint(c, taint, sink_class)
            if tt:
                return True, lbl
        return False, ""

    def expr_taint_value(self, node, taint):
        """The taint-map VALUE to store for an assignment RHS (reviewer 2.6):
        either None (clean), a source-label string, or a (label, sanitized-set)
        tuple. Class-specific sanitizers annotate rather than fully clean, so a
        wrong-class sink downstream still fires. This evaluates the complete RHS,
        not just an outer sanitizer, so nested concatenation such as
        ``'...' . sanitize_text_field($_GET['q'])`` retains SQL taint while being
        marked safe for XSS. WISP_SANI_CLASS=0 restores the old ablation."""
        if node is None:
            return None
        # Fast path for the overwhelming majority of assignments: if the RHS
        # neither invokes a class-specific sanitizer nor reads an already
        # annotated value, the original single taint evaluation is sufficient.
        rhs_text = _text(node, self.src)
        has_class_sensitive_call = bool(_CLASS_SENSITIVE_CALL_RE.search(rhs_text))
        has_summary_class_effect = False
        call_names = set()
        if "(" in rhs_text:
            for call in _descend_calls(node):
                call_name = _call_name(call, self.src).lstrip("\\").split("\\")[-1]
                call_names.add(call_name)
                summ = _lookup_summary(call, call_name, self.summaries, self.src)
                if (summ is not None
                        and (summ.return_safe_for
                             or summ.source_return_safe_for
                             or summ.return_invalidates_for)):
                    has_summary_class_effect = True
        input_names = tuple(_iter_var_names(node, self.src))
        has_annotated_input = any(
            isinstance(taint.get(var_name), tuple) for var_name in input_names)
        has_tainted_input = any(var_name in taint for var_name in input_names)
        if (not has_class_sensitive_call and not has_summary_class_effect
                and not has_annotated_input):
            tt, lbl = self.expr_taint(node, taint, None)
            return lbl if tt else None
        # A synthetic sink class treats every class-specific sanitizer as the
        # wrong context, exposing underlying taint anywhere in the expression;
        # universal sanitizers still correctly clear it.
        tt, lbl = self.expr_taint(node, taint, "__taint_probe__")
        if not tt:
            return None
        has_persistent_call = not call_names.isdisjoint(_PERSISTENT_SOURCES)
        other_source_call = not call_names.isdisjoint(
            _DIRECT_REQUEST_SOURCES.union({
                "getenv", "file_get_contents", "stream_get_contents",
            }).union(REST_READ_METHODS))
        has_superglobal = any(name in rhs_text for name in SUPERGLOBALS)
        if (has_persistent_call and not has_tainted_input
                and not other_source_call and not has_superglobal):
            # Persistent reads are safe for all classes outside the narrow
            # high-impact code/object/filesystem policy by
            # policy. Universal sanitizers were already honored by the probe;
            # avoid seven extra recursive scans for ubiquitous literal option
            # assignments that do not mix another source.
            safe_for = _TRACKED_SINK_CLASSES - _PERSISTENT_RISK_CLASSES
            return (lbl, frozenset(safe_for))
        safe_for = set()
        for vuln_class in _TRACKED_SINK_CLASSES:
            class_tainted, _ = self.expr_taint(node, taint, vuln_class)
            if not class_tainted:
                safe_for.add(vuln_class)
        return (lbl, frozenset(safe_for)) if safe_for else lbl


# --------------------------------------------------------------------------- #
# Detection driver
# --------------------------------------------------------------------------- #
# Object-injection risk detector (deserial): flag unserialize on non-literal args.
DESERIAL_RISK = True
_DESERIAL_RISK_FUNCS = {"unserialize", "maybe_unserialize"}

# callback-injection RCE sinks -> the argument index that must be tainted (the
# CALLBACK). A tainted data argument at any other position is not code execution.
# array_map(cb, arr...) / call_user_func(cb, ...) take the callback first; the
# u*sort / array_walk family take it second. This is a precision refinement: it
# suppresses the array_map/usort-over-tainted-data speculative RCE that dominates
# WISP's finding noise, keeping only genuinely callback-controlled RCE.
_CALLBACK_SINKS = {
    "array_map": 0, "call_user_func": 0, "call_user_func_array": 0,
    "register_shutdown_function": 0, "register_tick_function": 0,
    "usort": 1, "uasort": 1, "uksort": 1, "array_walk": 1, "create_function": 1,
}

# wpdb-signature method names: distinctive enough to trust on ANY receiver (the
# taint gate is the real filter). Generic "query" needs a DB-handle hint.
_DB_DISTINCT = {"get_results", "get_row", "get_var", "get_col"}
_DB_HINTS = ("wpdb", "->db", "$db", "database", "mysqli", "->dbh", "$dbh",
             "pdo", "->conn", "dbal", "->wpdb")


# receiver guard for learned SQL method sinks (P6). Off by default so the
# published corpus numbers stay reproducible; WISP_RECEIVER_GUARD=1 turns it on.
_RECEIVER_GUARD = os.environ.get("WISP_RECEIVER_GUARD", "0") == "1"
# generic learned method names that need a DB-handle receiver to count as SQL.
_GENERIC_SQL_METHODS = {"insert", "update", "replace", "delete"}


def _is_sql_receiver(objtxt: str, method: str) -> bool:
    """True if a wpdb-style SQL method call should be treated as a SQL sink even
    when the receiver is a custom DB handle (e.g. $this->db->get_col(...)), the
    very common wrapper pattern that the wpdb-only match used to miss."""
    o = objtxt.lower()
    if "wpdb" in o or method in _DB_DISTINCT:
        return True
    return any(h in o for h in _DB_HINTS)


def _sink_for_call(node, src: bytes, ana: _Analyzer, taint: dict):
    """If `node` is a tainted sink, return (vuln_class, sink_desc, source_label)."""
    if node.type == "member_call_expression":
        obj = node.children[0]
        method = _call_name(node, src)
        objtxt = _text(obj, src)
        if method in WPDB_SQL_METHODS and method != "prepare" and _is_sql_receiver(objtxt, method):
            for a in _args(node):
                # prepare() wrapping the arg means it's parameterized -> safe
                if a.type.endswith("call_expression") and _call_name(a, src) == "prepare":
                    continue
                tt, lbl = ana.expr_taint(a, taint, "sqli")
                if tt:
                    recv = objtxt if "wpdb" not in objtxt else "$wpdb"
                    return "sqli", f"{recv}->{method}", lbl
        # learned METHOD sink ($obj->insert/put_contents/loadHTML(...)) — grown by
        # the recall-growth self-learning loop, vetted + recall-gated before commit.
        mcls = METHOD_SINKS.get(method)
        if mcls:
            # receiver guard (WISP_RECEIVER_GUARD=1): a learned SQL method sink with
            # a generic name (insert/update) only counts when its receiver resembles
            # a DB handle ($wpdb / a db wrapper / query builder). This confines the
            # rule to the object family it was mined from and cuts learned-rule FPs.
            if (_RECEIVER_GUARD and mcls == "sqli"
                    and method in _GENERIC_SQL_METHODS
                    and not _is_sql_receiver(objtxt, method)):
                return None
            for a in _args(node):
                tt, lbl = ana.expr_taint(a, taint, mcls)
                if tt:
                    return mcls, f"->{method}", lbl
        return None

    name = _call_name(node, src).lstrip("\\").split("\\")[-1]
    if not _is_global_vocab_call(node, src, ana.summaries):
        return None
    if name in DB_SINK_FUNCS:
        for a in _args(node):
            tt, lbl = ana.expr_taint(a, taint, "sqli")
            if tt:
                return "sqli", name, lbl
    cls = SINK_FUNCS.get(name)
    if cls:
        args = _args(node)
        # parse_str/mb_parse_str with 2 args writes into the result array (no
        # local-scope pollution) -> safe; only the 1-arg form is dangerous.
        if name in ("parse_str", "mb_parse_str") and len(args) >= 2:
            return None
        # pattern-injection sinks are only dangerous if the PATTERN (arg 0) is
        # tainted; a tainted subject is harmless (e.g. preg_replace('#/+#','/',$x)).
        if name in PATTERN_ONLY_SINKS:
            args = args[:1]
        # callback-injection sinks are RCE only when the CALLBACK argument is
        # tainted; a tainted DATA argument is harmless (array_map('trim',$_POST['x'])
        # runs the literal 'trim', not attacker code). Restricting to the callback
        # position removes the dominant speculative-RCE false-positive class
        # (array_map/usort over tainted DATA). A literal callback cannot be code
        # injection even when its data argument is attacker controlled.
        # WISP_LEGACY_CALLBACK_DATA=1 exists only to reproduce the old ablation.
        elif (name in _CALLBACK_SINKS
              and os.environ.get("WISP_LEGACY_CALLBACK_DATA") != "1"):
            idx = _CALLBACK_SINKS[name]
            args = [args[idx]] if idx < len(args) else []
        for a in args:
            tt, lbl = ana.expr_taint(a, taint, cls)
            if tt:
                return cls, name, lbl

    # PHP Object Injection risk-pattern: unserialize()/maybe_unserialize() on a
    # NON-literal argument WITHOUT the allowed_classes=>false guard. Real object-
    # injection sources are overwhelmingly second-order (post/user meta, options,
    # cookies, files) which single-pass request-taint cannot reach, so a proven
    # flow is too strict here. This matches how the field (Psalm/RIPS) treats the
    # API. Lower confidence; downstream LLM-verify filters the safe ones.
    if DESERIAL_RISK and name in _DESERIAL_RISK_FUNCS:
        args = _args(node)
        if args and not _is_literal(args[0]) and "allowed_classes" not in _text(node, src):
            tt, lbl = ana.expr_taint(args[0], taint, "deserial")
            return "deserial", name, (lbl if tt else "unserialize(untrusted)")
    return None


# NOTE: unset_statement removed — unset($_COOKIE[$k]) is not an output sink;
# it was producing false XSS findings.
_ECHO_NODES = ("echo_statement", "print_intrinsic", "exit_statement")
_INCLUDE_NODES = ("include_expression", "require_expression",
                  "include_once_expression", "require_once_expression")
_CALL_NODES = ("function_call_expression", "member_call_expression",
               "scoped_call_expression")
_SKIP_SUBTREE = ("function_definition", "method_declaration",
                 "anonymous_function_creation_expression", "arrow_function")

# Pure text-building helpers whose result preserves attacker-controlled text.
# Do not apply the engine's general "unknown calls pass taint through arguments"
# rule at a terminal render return: framework/filter APIs may consume context
# arguments without putting them in the returned HTML (a major callback FP source).
_RENDER_VALUE_PASSTHROUGH = {
    "sprintf", "vsprintf", "wp_sprintf", "str_replace", "str_ireplace",
    "trim", "ltrim", "rtrim", "implode", "join", "apply_filters",
    "do_shortcode", "wpautop", "shortcode_unautop",
}


def _render_return_taint(node, ana, taint):
    """Conservative taint check for a registered HTML callback's return value.

    Direct variables/compositions retain normal taint. A direct opaque call does
    not: ``return apply_filters('hook', '', $attributes)`` does not prove that the
    attributes enter the returned HTML. Known text builders, sanitizers, and
    summarized user helpers retain their established semantics.
    """
    if node is None:
        return False, ""
    t = node.type
    if t == "argument":
        named = [c for c in node.children if c.is_named]
        return _render_return_taint(named[-1], ana, taint) if named else (False, "")
    if t in ("variable_name", "subscript_expression", "member_access_expression",
             "nullsafe_member_access_expression", "scoped_property_access_expression"):
        return ana.expr_taint(node, taint, "xss")
    if t in ("encapsed_string", "binary_expression"):
        for child in node.children:
            tt, lbl = _render_return_taint(child, ana, taint)
            if tt:
                return True, lbl
        return False, ""
    if t in ("parenthesized_expression", "cast_expression"):
        if t == "cast_expression":
            cast = _text(node, ana.src).split(")", 1)[0]
            if any(kind in cast for kind in ("int", "float", "bool")):
                return False, ""
        named = [c for c in node.children if c.is_named]
        return _render_return_taint(named[-1], ana, taint) if named else (False, "")
    if t == "conditional_expression":
        named = [c for c in node.children if c.is_named]
        branches = named[1:] if len(named) >= 3 else named
        for branch in branches:
            tt, lbl = _render_return_taint(branch, ana, taint)
            if tt:
                return True, lbl
        return False, ""
    if t in _CALL_NODES:
        short = _call_name(node, ana.src).lstrip("\\").split("\\")[-1]
        summ = _lookup_summary(node, short, ana.summaries, ana.src)
        known_global_builder = (_is_global_vocab_call(
            node, ana.src, ana.summaries)
            and (short in _RENDER_VALUE_PASSTHROUGH or short in SANITIZERS))
        if known_global_builder or summ is not None:
            return ana.expr_taint(node, taint, "xss")
        return False, ""
    return False, ""


def _returned_variable_names(body, src) -> set[str]:
    """Variables returned by a function body, excluding nested functions."""
    returned = set()
    stack = [body] if body is not None else []
    while stack:
        node = stack.pop()
        if node is not body and node.type in _SKIP_SUBTREE:
            continue
        if node.type == "return_statement":
            named = [c for c in node.children if c.is_named]
            if named and named[-1].type == "variable_name":
                returned.add(_text(named[-1], src))
        stack.extend(node.children)
    return returned


def _definitely_terminates(node) -> bool:
    """Does every path through ``node`` terminate the current function/script?

    Keep this deliberately structural.  Recursing into the last descendant of
    an arbitrary node makes ``if ($a) { return; }`` look unconditional merely
    because the deepest/last statement is a return.
    """
    if node is None:
        return False
    if node.type in ("return_statement", "throw_expression", "throw_statement",
                     "exit_statement"):
        return True
    if node.type == "expression_statement":
        # tree-sitter represents ``throw $e`` as a throw_expression wrapped in
        # an expression_statement.  Some tolerated PHP forms of die/exit can be
        # parsed as a bare name, so retain a narrow textual fallback for those.
        named = [c for c in node.children if c.is_named]
        if len(named) == 1 and _definitely_terminates(named[0]):
            return True
        return bool(re.match(rb"\s*(?:die|exit)\b", node.text or b""))
    if node.type in ("compound_statement", "colon_block"):
        # Once a direct statement definitely terminates, later siblings are
        # unreachable even if malformed/tolerated source leaves them in the AST.
        return any(_definitely_terminates(c)
                   for c in node.children if c.is_named)
    if node.type in ("else_clause", "else_if_clause"):
        named = [c for c in node.children if c.is_named]
        return _definitely_terminates(named[-1]) if named else False
    if node.type == "if_statement":
        body = node.child_by_field_name("body")
        branches = [c for c in node.children
                    if c.type in ("else_if_clause", "else_clause")]
        # Without a final else, the all-conditions-false path continues.
        if not any(c.type == "else_clause" for c in branches):
            return False
        return (body is not None and _definitely_terminates(body)
                and all(_definitely_terminates(c) for c in branches))
    if node.type == "do_statement":
        return _definitely_terminates(node.child_by_field_name("body"))
    return False


def _join_taint_state(target: dict, incoming: dict) -> None:
    """May-path union of a branch/loop state into ``target``."""
    for key, value in incoming.items():
        if _sani_class_enabled():
            target[key] = _tv_join(target.get(key), value)
        else:
            target.setdefault(key, value)


def _copy_render_candidates(candidates: dict) -> dict:
    return {key: list(values) for key, values in candidates.items()}


def _join_render_candidates(states) -> dict:
    joined = {}
    seen = {}
    for state in states:
        for key, values in state.items():
            bucket = joined.setdefault(key, [])
            markers = seen.setdefault(key, set())
            for candidate in values:
                marker = id(candidate)
                if marker not in markers:
                    bucket.append(candidate)
                    markers.add(marker)
    return joined


def _record_render_composition(node, right, key, src, ana, taint,
                               fn_label, rel, abs_file, replace=False):
    """Retain a candidate HTML composition for a variable later returned.

    Candidates are flushed only when a tainted value is actually returned. A
    definite linear whole-variable overwrite replaces prior candidates; writes
    inside a branch are unioned because another path can retain the old value.
    """
    if not ana.return_xss_context or key in (None, ""):
        return
    inherited = (list(ana.render_candidates.get(_text(right, src), ()))
                 if right.type == "variable_name" else [])
    if replace:
        ana.render_candidates.pop(key, None)
    if right.type == "variable_name":
        # A plain alias is not itself proof of HTML composition. Preserve an
        # already-proven composition's original location; opaque tainted values
        # remain opaque through `$out = $tmp`.
        if inherited:
            ana.render_candidates[key] = inherited
        return
    tt, lbl = _render_return_taint(right, ana, taint)
    if not tt:
        return
    line = node.start_point[0] + 1
    candidate = Finding(
        file=rel, abs_file=abs_file, line=line,
        vuln_class="xss",
        message=("Tainted callback input is composed into rendered HTML "
                 f"({ana.return_xss_context})"),
        source=lbl, sink="render callback composition",
        trace=[f"{lbl} -> rendered composition in {fn_label}() @ {rel}:{line}"],
        confidence=0.68, function=fn_label)
    ana.render_candidates.setdefault(key, []).append(candidate)


def _walk_stmts(body, src, ana, taint, fn_label, rel, abs_file, summaries,
                record=True):
    """In-order DFS over a function body. Tracks variable taint as assignments
    are encountered and fires on tainted sinks (calls, echo/print, include)."""
    if body is None:
        return
    for c in body.children:
        _visit(c, src, ana, taint, fn_label, rel, abs_file, summaries, record)
        if _definitely_terminates(c):
            break


_MEMBER_LHS = ("member_access_expression", "nullsafe_member_access_expression",
               "scoped_property_access_expression")


def _assign_key(left, src):
    """Taint-map key for an assignment target, or (None, False).

    Returns (key, is_array_element). For `$v` -> "$v"; for `$this->p` -> "$this->p"
    (exact text); for `$arr['k']` -> the base array var (conservative whole-array
    taint), flagged so callers do not CLEAR it on an untainted element write."""
    if left.type == "variable_name":
        return _text(left, src), False
    if left.type in _MEMBER_LHS:
        return _text(left, src), False
    if left.type == "subscript_expression":
        return _text(left.children[0], src), True
    return None, False


def _visit(node, src, ana, taint, fn_label, rel, abs_file, summaries, record):
    t = node.type
    if t in _SKIP_SUBTREE:
        return                              # nested scopes analyzed separately

    if t == "return_statement" and ana.probe_returns:
        named = [c for c in node.children if c.is_named]
        if named:
            tt, _ = ana.expr_taint(named[-1], taint, ana.return_probe_class)
            if tt:
                ana.return_tainted = True

    # Dynamic block and shortcode callbacks render by returning HTML.  Only an
    # explicitly registered render callback receives this treatment, and only
    # its first framework-controlled input parameter is seeded below in
    # detect_file().  This avoids turning ordinary helper returns into XSS sinks.
    if t == "return_statement" and record and ana.return_xss_context:
        named = [c for c in node.children if c.is_named]
        if named:
            returned = named[-1]
            returned_key = (_text(returned, src)
                            if returned.type == "variable_name" else "")
            tt, lbl = _render_return_taint(returned, ana, taint)
            candidates = ana.render_candidates.get(returned_key, ())
            if returned_key and tt and candidates:
                for candidate in candidates:
                    marker = id(candidate)
                    if marker not in ana.render_flushed:
                        ana.findings.append(candidate)
                        ana.render_flushed.add(marker)
                tt = False                  # composition sites are better locations
            elif returned_key and returned_key not in ana.render_seed_vars:
                # A variable tainted only through an opaque assignment has no
                # proven HTML-producing operation. Direct callback params remain
                # valid terminal outputs; other variables require a candidate.
                tt = False
            if tt:
                line = node.start_point[0] + 1
                ana.findings.append(Finding(
                    file=rel, abs_file=abs_file, line=line,
                    vuln_class="xss",
                    message=("Tainted callback input reaches rendered HTML "
                             f"return ({ana.return_xss_context})"),
                    source=lbl, sink="render callback return",
                    trace=[f"{lbl} -> rendered return in {fn_label}() @ {rel}:{line}"],
                    confidence=0.66, function=fn_label))

    if t == "assignment_expression":
        left, right = node.children[0], node.children[-1]
        _visit(right, src, ana, taint, fn_label, rel, abs_file, summaries, record)
        key, is_elem = _assign_key(left, src)
        if key:
            assigned_value = None
            if _sani_class_enabled():
                v = ana.expr_taint_value(right, taint)
                if v is not None:
                    # Whole-array approximation: an element write joins with
                    # existing elements. A later safe element must not overwrite
                    # an earlier raw one (safe-for sets intersect in _tv_join).
                    taint[key] = _tv_join(taint.get(key), v) if is_elem else v
                    assigned_value = taint[key]
                elif not is_elem:
                    taint.pop(key, None)
            else:
                tt, lbl = ana.expr_taint(right, taint)
                if tt:
                    taint[key] = lbl
                    assigned_value = lbl
                elif not is_elem:             # array-element write never clears base
                    taint.pop(key, None)
            if (ana.collected_props is not None and left.type in _MEMBER_LHS
                    and assigned_value is not None):
                prop_key = _property_summary_key(left, src)
                ana.collected_props[prop_key] = _tv_join(
                    ana.collected_props.get(prop_key), assigned_value)
            if record:
                _record_render_composition(
                    node, right, key, src, ana, taint, fn_label, rel, abs_file,
                    replace=not is_elem)
                left_text = _text(left, src)
                if ("acf_field_render" in ana.framework_contexts
                        and ana.acf_field_param
                        and left_text.startswith(ana.acf_field_param + "[")
                        and re.search(r"\[['\"]choices['\"]\]", left_text)):
                    tt, lbl = ana.expr_taint(right, taint, "xss")
                    if tt:
                        line = node.start_point[0] + 1
                        ana.findings.append(Finding(
                            file=rel, abs_file=abs_file, line=line,
                            vuln_class="xss",
                            message=("Tainted ACF field choice reaches rendered "
                                     "field markup"),
                            source=lbl, sink="acf_render_field choices",
                            trace=[f"{lbl} -> ACF rendered choice in "
                                   f"{fn_label}() @ {rel}:{line}"],
                            confidence=0.68, function=fn_label))
        return

    if t == "augmented_assignment_expression":   # $x .= $tainted, $x += ...
        left, right = node.children[0], node.children[-1]
        _visit(right, src, ana, taint, fn_label, rel, abs_file, summaries, record)
        key, _ = _assign_key(left, src)
        if key:
            if _sani_class_enabled():
                joined = _tv_join(taint.get(key), ana.expr_taint_value(right, taint))
                if joined is not None:             # union: never clear existing taint
                    taint[key] = joined
            else:
                tt, lbl = ana.expr_taint(right, taint)
                if tt:                             # union: stays tainted, never cleared
                    taint[key] = lbl
            if (ana.collected_props is not None and left.type in _MEMBER_LHS
                    and key in taint):
                prop_key = _property_summary_key(left, src)
                ana.collected_props[prop_key] = _tv_join(
                    ana.collected_props.get(prop_key), taint[key])
            if record:
                _record_render_composition(
                    node, right, key, src, ana, taint, fn_label, rel, abs_file)
        return

    if t == "if_statement":
        if os.environ.get("WISP_NO_BRANCH_JOIN") == "1":
            # ABLATION: linear fall-through (pre-branch-join behaviour) — all
            # children share ONE taint map, so an `else { $x=""; }` clears taint.
            for c in node.children:
                _visit(c, src, ana, taint, fn_label, rel, abs_file, summaries, record)
            return
        # Branch JOIN, not linear fall-through. Processing an if and its else in
        # ONE taint map lets a reassignment in one branch (e.g. `else { $x=""; }`)
        # wipe taint the other branch / the fall-through keeps — losing the flow.
        # Correct dataflow unions the branches: a var is tainted after the block if
        # it is tainted on ANY path (including not entering the if at all). We run
        # each branch body on a COPY of the pre-state (so sinks inside still fire
        # into the shared ana.findings) and union the end-states back with pre.
        # Evaluate the condition first: assignments/calls inside it occur on
        # every path before a branch is chosen.
        condition = _child(node, "parenthesized_expression")
        if condition is not None:
            _visit(condition, src, ana, taint, fn_label, rel, abs_file,
                   summaries, record)
        pre = dict(taint)
        pre_candidates = _copy_render_candidates(ana.render_candidates)
        direct_named = [c for c in node.children if c.is_named]
        consequence = None
        if condition in direct_named:
            start = direct_named.index(condition) + 1
            consequence = next(
                (c for c in direct_named[start:]
                 if c.type not in ("else_clause", "else_if_clause")), None)
        clauses = [c for c in direct_named
                   if c.type in ("else_clause", "else_if_clause")]
        branches = ([consequence] if consequence is not None else []) + clauses
        exhaustive = any(c.type == "else_clause" for c in branches)
        ends = []
        candidate_ends = []
        # Conditions in elseif clauses execute sequentially on the all-previous-
        # conditions-false path. Keep that fallthrough state so assignments in an
        # elseif condition also reach later elseif/else alternatives.
        fallthrough = dict(pre)
        fallthrough_candidates = _copy_render_candidates(pre_candidates)
        for c in branches:
            if c is consequence:                              # the `if` consequence
                body = c
                br = dict(fallthrough)
                ana.render_candidates = _copy_render_candidates(
                    fallthrough_candidates)
                ana.branch_depth += 1
                try:
                    _visit(body, src, ana, br, fn_label, rel, abs_file,
                           summaries, record)
                finally:
                    ana.branch_depth -= 1
                if not _definitely_terminates(body):
                    ends.append(br)
                    candidate_ends.append(_copy_render_candidates(
                        ana.render_candidates))
            elif c.type == "else_if_clause":
                condition = _child(c, "parenthesized_expression")
                if condition is not None:
                    ana.render_candidates = _copy_render_candidates(
                        fallthrough_candidates)
                    ana.branch_depth += 1
                    try:
                        _visit(condition, src, ana, fallthrough, fn_label, rel,
                               abs_file, summaries, record)
                    finally:
                        ana.branch_depth -= 1
                    fallthrough_candidates = _copy_render_candidates(
                        ana.render_candidates)
                clause_named = [n for n in c.children if n.is_named]
                body = next((n for n in reversed(clause_named)
                             if n is not condition), None)
                br = dict(fallthrough)
                ana.render_candidates = _copy_render_candidates(
                    fallthrough_candidates)
                ana.branch_depth += 1
                try:
                    _visit(body, src, ana, br, fn_label, rel, abs_file,
                           summaries, record)
                finally:
                    ana.branch_depth -= 1
                if not _definitely_terminates(body):
                    ends.append(br)
                    candidate_ends.append(_copy_render_candidates(
                        ana.render_candidates))
            else:                                               # final else
                clause_named = [n for n in c.children if n.is_named]
                body = clause_named[-1] if clause_named else None
                br = dict(fallthrough)
                ana.render_candidates = _copy_render_candidates(
                    fallthrough_candidates)
                ana.branch_depth += 1
                try:
                    _visit(body, src, ana, br, fn_label, rel, abs_file,
                           summaries, record)
                finally:
                    ana.branch_depth -= 1
                if not _definitely_terminates(body):
                    ends.append(br)
                    candidate_ends.append(_copy_render_candidates(
                        ana.render_candidates))
        if not exhaustive:
            ends.append(fallthrough)            # all conditions were false
            candidate_ends.append(fallthrough_candidates)
        # Replace the incoming state with exactly the continuing paths.  Starting
        # the join from ``pre`` would keep a value tainted even when both sides of
        # an exhaustive if/else definitely sanitize or overwrite it.
        taint.clear()
        for br in ends:
            _join_taint_state(taint, br)
        ana.render_candidates = _join_render_candidates(candidate_ends)
        return

    if t == "foreach_statement":                 # foreach ($tainted as $k => $v)
        pre = dict(taint)
        pre_candidates = _copy_render_candidates(ana.render_candidates)
        loop_state = dict(pre)
        ana.render_candidates = _copy_render_candidates(pre_candidates)
        named = [c for c in node.children if c.is_named]
        if named:
            value = (ana.expr_taint_value(named[0], loop_state)
                     if _sani_class_enabled() else None)
            tt, lbl = ana.expr_taint(named[0], loop_state)  # iterated collection
            if value is not None or tt:
                inherited = value if value is not None else lbl
                for tgt in named[1:]:                   # key / value bindings
                    if tgt.type == "compound_statement":
                        break
                    for v in _iter_var_names(tgt, src):
                        loop_state[v] = inherited
        ana.branch_depth += 1
        try:
            for c in node.children:
                _visit(c, src, ana, loop_state, fn_label, rel, abs_file,
                       summaries, record)
        finally:
            ana.branch_depth -= 1
        loop_candidates = _copy_render_candidates(ana.render_candidates)
        _join_taint_state(taint, loop_state)       # loop may execute zero times
        ana.render_candidates = _join_render_candidates(
            (pre_candidates, loop_candidates))
        return

    if t == "do_statement":
        # Unlike while/for, the body executes at least once. Its sanitizers,
        # writes and termination therefore cannot be joined with a zero-pass
        # pre-state.
        body = node.child_by_field_name("body")
        condition = node.child_by_field_name("condition")
        if body is not None:
            _visit(body, src, ana, taint, fn_label, rel, abs_file,
                   summaries, record)
        if not _definitely_terminates(body) and condition is not None:
            _visit(condition, src, ana, taint, fn_label, rel, abs_file,
                   summaries, record)
        return

    if t == "while_statement":
        # The first condition evaluation is guaranteed even when the body runs
        # zero times, so assignments/sanitizers in it update the continuing
        # state before the optional body path is joined.
        condition = node.child_by_field_name("condition")
        body = node.child_by_field_name("body")
        if condition is not None:
            _visit(condition, src, ana, taint, fn_label, rel, abs_file,
                   summaries, record)
        condition_candidates = _copy_render_candidates(ana.render_candidates)
        loop_state = dict(taint)
        ana.render_candidates = _copy_render_candidates(condition_candidates)
        ana.branch_depth += 1
        try:
            if body is not None:
                _visit(body, src, ana, loop_state, fn_label, rel, abs_file,
                       summaries, record)
        finally:
            ana.branch_depth -= 1
        if body is None or not _definitely_terminates(body):
            _join_taint_state(taint, loop_state)
            ana.render_candidates = _join_render_candidates((
                condition_candidates,
                _copy_render_candidates(ana.render_candidates)))
        else:
            ana.render_candidates = condition_candidates
        return

    if t == "for_statement":
        pre_candidates = _copy_render_candidates(ana.render_candidates)
        loop_state = dict(taint)
        ana.render_candidates = _copy_render_candidates(pre_candidates)
        ana.branch_depth += 1
        try:
            for c in node.children:
                _visit(c, src, ana, loop_state, fn_label, rel, abs_file,
                       summaries, record)
        finally:
            ana.branch_depth -= 1
        loop_candidates = _copy_render_candidates(ana.render_candidates)
        _join_taint_state(taint, loop_state)       # conservative zero-iteration path
        ana.render_candidates = _join_render_candidates(
            (pre_candidates, loop_candidates))
        return

    if t in _ECHO_NODES and record:
        for c in node.children:
            if c.type in (";", "echo", "print", "exit", "(", ")"):
                continue
            tt, lbl = ana.expr_taint(c, taint, "xss")
            if tt:
                ana.findings.append(Finding(
                    file=rel, abs_file=abs_file, line=node.start_point[0] + 1,
                    vuln_class="xss", message="Tainted data reaches echo/print (XSS)",
                    source=lbl, sink="echo",
                    trace=[f"{lbl} -> echo in {fn_label}() @ {rel}:{node.start_point[0]+1}"],
                    confidence=0.6, function=fn_label))
                break

    # short-echo tag `<?= $x ?>`: an expression_statement immediately preceded by
    # a `<?=` open tag is echoed output (very common XSS sink in WP templates).
    if t == "expression_statement" and record:
        prev = node.prev_sibling
        if (prev is not None and prev.type == "text_interpolation"
                and any(ch.type == "php_tag" and _text(ch, src).strip().startswith("<?=")
                        for ch in prev.children)):
            for c in node.children:
                if c.type == ";":
                    continue
                tt, lbl = ana.expr_taint(c, taint, "xss")
                if tt:
                    ana.findings.append(Finding(
                        file=rel, abs_file=abs_file, line=node.start_point[0] + 1,
                        vuln_class="xss", message="Tainted data reaches short-echo <?= (XSS)",
                        source=lbl, sink="<?= echo",
                        trace=[f"{lbl} -> <?= in {fn_label}() @ {rel}:{node.start_point[0]+1}"],
                        confidence=0.6, function=fn_label))
                    break

    if t in _INCLUDE_NODES and record:
        named = [c for c in node.children if c.is_named]
        tt, lbl = ana.expr_taint(named[-1], taint, "lfi") if named else (False, "")
        if tt:
            ana.findings.append(Finding(
                file=rel, abs_file=abs_file, line=node.start_point[0] + 1,
                vuln_class="lfi", message="Tainted path reaches include/require (LFI/RFI)",
                source=lbl, sink="include",
                trace=[f"{lbl} -> include in {fn_label}() @ {rel}:{node.start_point[0]+1}"],
                confidence=0.66, function=fn_label))

    if t in _CALL_NODES:
        hit = _sink_for_call(node, src, ana, taint)
        if hit and record:
            cls, sink, srclbl = hit
            # risk-pattern findings (object-injection on untrusted-but-unproven
            # data) carry lower confidence so the LLM-verify gate can rank them.
            if srclbl == "unserialize(untrusted)":
                conf = 0.45
            elif srclbl.startswith("persistent source "):
                conf = 0.52                 # second-order source; control is indirect
            else:
                conf = 0.66
            ana.findings.append(Finding(
                file=rel, abs_file=abs_file, line=node.start_point[0] + 1,
                vuln_class=cls, message=f"Tainted data reaches {sink}",
                source=srclbl, sink=sink,
                trace=[f"{srclbl} -> {sink} in {fn_label}() @ {rel}:{node.start_point[0]+1}"],
                confidence=conf, function=fn_label))
        name = _call_name(node, src).lstrip("\\").split("\\")[-1]
        summ = _lookup_summary(node, name, summaries, src)
        if (_param_prop_enabled() and summ and ana.collected_props is not None
                and summ.tainted_params_to_props):
            call_args = _args(node)
            for index, effects in summ.tainted_params_to_props.items():
                if index >= len(call_args):
                    continue
                incoming = ana.expr_taint_value(call_args[index], taint)
                if incoming is None:
                    continue
                label = _tv_label(incoming)
                for prop_key, template in effects.items():
                    safe_for = _tv_sani(template)
                    derived = ((label, frozenset(safe_for))
                               if safe_for else label)
                    ana.collected_props[prop_key] = _tv_join(
                        ana.collected_props.get(prop_key), derived)
        if summ and record:
            for i, a in enumerate(_args(node)):
                for effect in summ.tainted_params_to_sink.get(i, ()):
                    cls, sink = effect.vuln_class, effect.sink
                    tt, lbl = ana.expr_taint(a, taint, cls)  # sanitizer context = sink class
                    if not tt:
                        continue
                    pn = summ.param_names[i] if i < len(summ.param_names) else f"#{i}"
                    sink_file = effect.file or rel
                    sink_abs = effect.abs_file or abs_file
                    sink_line = effect.line or (node.start_point[0] + 1)
                    sink_fn = effect.function or name
                    ana.findings.append(Finding(
                        file=rel, abs_file=abs_file, line=node.start_point[0] + 1,
                        vuln_class=cls,
                        message=f"Tainted data flows into {name}() and reaches {sink}",
                        source=lbl, sink=f"{sink} (via {name}())",
                        trace=[f"{lbl} @ {rel}:{node.start_point[0]+1}",
                               f"-> param {pn} of {name}()",
                               f"-> {sink} in {sink_fn}() @ {sink_file}:{sink_line}"],
                        interprocedural=True, confidence=0.72, function=fn_label,
                        sink_file=sink_file, sink_abs_file=sink_abs,
                        sink_line=sink_line, sink_function=sink_fn))

    for c in node.children:
        _visit(c, src, ana, taint, fn_label, rel, abs_file, summaries, record)
        if _definitely_terminates(c):
            break


def _build_summary(fn, src, summaries, rel="", abs_file="") -> _Summary:
    name = _fn_name(fn, src)
    params = _param_names(fn, src)
    body = _child(fn, "compound_statement")
    summ = _Summary(name, params, {}, set(), False, set())
    summ.is_method = fn.type == "method_declaration"
    body_calls = list(_descend_calls(body)) if body is not None else []
    called_names = {
        _call_name(call, src).lstrip("\\").split("\\")[-1]
        for call in body_calls
    }

    def _calls_any(names) -> bool:
        return not called_names.isdisjoint(names)

    body_bytes = src[body.start_byte:body.end_byte] if body is not None else b""
    has_nonpersistent_source = any(
        superglobal.encode() in body_bytes for superglobal in SUPERGLOBALS)
    has_nonpersistent_source = has_nonpersistent_source or _calls_any(
        _DIRECT_REQUEST_SOURCES.union({
            "getenv", "file_get_contents", "stream_get_contents",
        }).union(REST_READ_METHODS))

    # Classes whose safety/invalidator effect can change in this function,
    # directly or through a summarized callee. This propagates esc_html/get_option
    # effects through wrapper chains during the normal summary fixpoint without
    # rescanning every class for every ordinary helper.
    effect_classes = set()
    invalidator_classes = set()
    scoped_source_classes = set()
    for vuln_class, sanitizer_names in SANITIZERS_BY_CLASS.items():
        if _calls_any(sanitizer_names):
            effect_classes.add(vuln_class)
    for invalidator, affected in _SANITIZER_INVALIDATORS.items():
        if _calls_any((invalidator,)):
            effect_classes.update(affected)
            invalidator_classes.update(affected)
    has_persistent_source = _calls_any(_PERSISTENT_SOURCES)
    # Persistent configuration is intentionally tainted only for high-impact
    # code/object/filesystem sinks. Probe those risk classes; safety for the
    # remaining classes is populated below without
    # six redundant full-body walks per parameter/source.
    if has_persistent_source:
        effect_classes.update(_PERSISTENT_RISK_CLASSES)
    if body is not None:
        for call in body_calls:
            callee_name = _call_name(call, src).lstrip("\\").split("\\")[-1]
            callee = _lookup_summary(call, callee_name, summaries, src)
            if callee is None:
                continue
            scoped_source_classes.update(callee.source_return_scoped_for)
            if (callee.returns_source_tainted
                    and not (_TRACKED_SINK_CLASSES - _PERSISTENT_RISK_CLASSES)
                    .issubset(callee.source_return_safe_for)):
                has_nonpersistent_source = True
            effect_classes.update(callee.source_return_safe_for)
            for classes in callee.return_safe_for.values():
                effect_classes.update(classes)
            for classes in callee.return_invalidates_for.values():
                effect_classes.update(classes)
                invalidator_classes.update(classes)
        # Preserve sanitizer annotations carried by plugin-wide properties when
        # a getter/helper returns them across a method boundary.
        stack = [body]
        while stack:
            current = stack.pop()
            if current is not body and current.type in _SKIP_SUBTREE:
                continue
            if current.type in _MEMBER_LHS:
                prop_value = TAINTED_PROPS.get(
                    _property_summary_key(current, src))
                if prop_value is not None:
                    effect_classes.update(_tv_sani(prop_value))
                    if not (_TRACKED_SINK_CLASSES - _PERSISTENT_RISK_CLASSES).issubset(
                            _tv_sani(prop_value)):
                        has_nonpersistent_source = True
            stack.extend(current.children)
    if has_persistent_source and has_nonpersistent_source:
        effect_classes.update(_TRACKED_SINK_CLASSES)
    body_has_class_effect = bool(effect_classes)

    # treat each param as tainted; record which reach a sink and which reach return
    for i, pname in enumerate(params):
        seed = {pname: f"param {pname}"}
        probe = _Analyzer(src, rel, abs_file, summaries)
        if _param_prop_enabled():
            probe.collected_props = {}
        _walk_stmts(body, src, probe, dict(seed), name, rel, abs_file, summaries, record=True)
        if probe.collected_props is not None:
            property_effects = {
                prop_key: value
                for prop_key, value in probe.collected_props.items()
                if _tv_label(value).startswith("param ")
            }
            if property_effects:
                summ.tainted_params_to_props[i] = property_effects
        for f in probe.findings:
            if not f.source.startswith("param "):
                continue
            # A transitive finding's presentation sink includes "(via helper())".
            # Summary effects retain only the canonical ultimate sink; otherwise
            # each fixpoint nests another suffix and the effect set grows by path.
            canonical_sink = f.sink.split(" (via ", 1)[0]
            effect = _SinkEffect(
                f.vuln_class,
                canonical_sink,
                f.sink_file or f.file,
                f.sink_abs_file or f.abs_file,
                f.sink_line or f.line,
                f.sink_function or f.function or name,
            )
            effects = list(summ.tainted_params_to_sink.get(i, ()))
            if effect not in effects:
                effects.append(effect)
                summ.tainted_params_to_sink[i] = tuple(effects)
        probe_class = "__taint_probe__" if body_has_class_effect else None
        if _return_tainted_with(body, src, summaries, dict(seed), probe_class):
            summ.returns_tainted_from.add(i)
            if body_has_class_effect:
                safe_for = {
                    vuln_class for vuln_class in effect_classes
                    if not _return_tainted_with(
                        body, src, summaries, dict(seed), vuln_class)
                }
                if safe_for:
                    summ.return_safe_for[i] = frozenset(safe_for)
                invalidates = {
                    vuln_class for vuln_class in effect_classes
                    if vuln_class in invalidator_classes
                    if _return_tainted_with(
                        body, src, summaries,
                        {pname: (f"param {pname}", frozenset({vuln_class}))},
                        vuln_class)
                }
                if invalidates:
                    summ.return_invalidates_for[i] = frozenset(invalidates)

    # does the function return request data read from a superglobal directly?
    source_probe = "__taint_probe__" if body_has_class_effect else None
    summ.returns_source_tainted = _return_tainted_with(
        body, src, summaries, {}, source_probe)
    if summ.returns_source_tainted and body_has_class_effect:
        source_safe_for = {
            vuln_class for vuln_class in effect_classes
            if not _return_tainted_with(body, src, summaries, {}, vuln_class)
        }
        if has_persistent_source and not has_nonpersistent_source:
            persistent_scoped = _TRACKED_SINK_CLASSES - _PERSISTENT_RISK_CLASSES
            source_safe_for.update(persistent_scoped)
            scoped_source_classes.update(persistent_scoped)
        summ.source_return_safe_for = frozenset(source_safe_for)
        summ.source_return_scoped_for = frozenset(
            source_safe_for.intersection(scoped_source_classes))
    return summ


def _build_summary_callers(definitions: dict, summaries: dict) -> dict:
    """Build the static inverse call graph once all definition keys exist."""
    callers = {key: set() for key in definitions}
    for caller_key, (fn, src, _rel, _abs_file) in definitions.items():
        body = _child(fn, "compound_statement")
        if body is None:
            continue
        for call in _descend_calls(body):
            name = _call_name(call, src).lstrip("\\").split("\\")[-1]
            for callee_key in _lookup_summary_keys(
                    call, name, summaries, src):
                if callee_key in callers:
                    callers[callee_key].add(caller_key)
    return callers


# v1.3 raises this from 4 to 32. Four was never a measured choice, and with the property table made
# monotone below, 32 takes corpus non-convergence from 272 of 1108 to 8 while leaving every record
# that already converged byte-identical. Set WISP_PER_KEY_CAP=4 to recover v1.2 behaviour for the
# sensitivity analysis the contract asks for.
_PER_KEY_UPDATE_CAP = int(os.environ.get("WISP_PER_KEY_CAP", "32"))  # per-definition rebuild cap

# --------------------------------------------------------------------------- convergence probes
# Fields that only ever grow as the summary table fills in. Everything not listed here is either
# metadata or a safety fact derived from a negative test.
#
# Two hypotheses about the 272-of-1108 non-convergence were tested against the 12 records that fail
# at every cap, and BOTH were wrong, so they are recorded here rather than left as dead code:
#   1. Safety-field churn. Comparing summaries on the danger fields alone changed nothing: still
#      12 of 12 non-converged, with global-cap failures rising from 7 to 9.
#   2. Sink-effect position churn. _SinkEffect carries file/line/function and a transitive effect is
#      stamped `f.sink_file or f.file`, so it can be restamped once the callee resolves. Comparing
#      effects on (class, sink) alone also changed nothing: identical counts to hypothesis 1.
# What was actually wrong was the OUTER loop, not this one. See _MONOTONE_PROPS below.
_DANGER_FIELDS = ("tainted_params_to_sink", "returns_tainted_from", "returns_source_tainted",
                  "return_invalidates_for", "tainted_params_to_props")


# WISP_STABILIZE_TRACE=<path> dumps, per plugin analysis, which definitions were rebuilt how often
# and WHICH field differed each time. Two guesses at the cause of non-convergence (safety-field
# churn, then sink-effect position churn) both failed to move the 12 oscillating records at all, so
# the next step is measurement rather than a third guess. Off unless the variable is set.
_STABILIZE_TRACE = os.environ.get("WISP_STABILIZE_TRACE", "")
# Stops _collect_tainted_props from clearing the plugin-wide property table on every outer round, so
# the outer summary/property alternation can reach the driver's own exit test instead of exhausting
# its round cap. See the comment at the reset site for what this does and does not prove.
#
# ON by default from v1.3. The evidence is a 1108-record census against the v1.2 census, in
# revision-cns-v2/out/MONOTONE_PROPS_DIFF_V3.json: 264 records rescued and none lost, and on the 836
# records that converge under BOTH configurations the finding totals are 39,033 and 39,033, a delta
# of exactly zero. Set WISP_MONOTONE_PROPS=0 to recover v1.2 behaviour.
_MONOTONE_PROPS = os.environ.get("WISP_MONOTONE_PROPS", "1") == "1"


def _field_delta(old, new):
    """Names of the danger fields that differ between two summaries, under logical identity."""
    if old is None:
        return ["<new>"]
    out = []
    for f in _DANGER_FIELDS:
        a, b = getattr(old, f, None), getattr(new, f, None)
        if f == "tainted_params_to_sink":
            a = {k: sorted({_effect_identity(e) for e in (v or ())}) for k, v in (a or {}).items()}
            b = {k: sorted({_effect_identity(e) for e in (v or ())}) for k, v in (b or {}).items()}
        if repr(a) != repr(b):
            out.append(f)
    if not out:
        # The danger projection saw no change, so whatever moved is a safety field or metadata.
        for f in ("return_safe_for", "source_return_safe_for", "source_return_scoped_for"):
            if repr(getattr(old, f, None)) != repr(getattr(new, f, None)):
                out.append(f)
    return out or ["<none: equal under both projections>"]


def _effect_identity(effect):
    """A sink effect's LOGICAL identity: which class, which sink. Position is presentation.

    _SinkEffect also carries file, abs_file, line and function. Those are not stable during the
    fixpoint. A transitive effect is built as `f.sink_file or f.file`, so while the callee's summary
    is still incomplete the effect is stamped with the CALL SITE, and once the callee resolves it is
    restamped with the real sink. The same logical fact therefore changes identity mid-iteration,
    counts as new danger, and re-queues every caller again. Comparing on class and sink alone stops
    a fact from being rediscovered under a new address."""
    return (getattr(effect, "vuln_class", None), getattr(effect, "sink", None))


def _danger_projection(summary):
    """The monotone part of a summary, as a comparable value. None stays None."""
    if summary is None:
        return None
    out = []
    for f in _DANGER_FIELDS:
        v = getattr(summary, f, None)
        if f == "tainted_params_to_sink" and isinstance(v, dict):
            v = {k: sorted({_effect_identity(e) for e in (effs or ())})
                 for k, effs in v.items()}
        out.append(repr(v))
    return tuple(out)


@dataclass
class _StabilizeStatus:
    """Outcome of one bounded iterative stabilization pass.

    This is NOT a guaranteed least fixed point. The set-union join over sink
    effects is monotone, but per-key and global update caps stop the iteration
    on cyclic or oscillating call graphs, so the pass may return an
    approximation. ``converged`` is True only when the worklist drained with no
    cap applied. When a cap fired, the summary table is a sound conservative
    approximation, not the least fixed point, and downstream results built from
    it are marked incomplete.
    """
    converged: bool          # worklist drained AND no per-key/global cap fired
    updates: int             # summaries actually changed
    rounds: int              # worklist pops (iterations)
    capped_keys: tuple       # keys a caller re-queued after the per-key cap
    pending_count: int       # items still queued when the pass stopped
    max_updates: int         # the global update cap for this pass
    hit_global_cap: bool     # stopped because updates reached max_updates

    def merge(self, other: "_StabilizeStatus") -> "_StabilizeStatus":
        """Combine two passes over the same plugin (worst case wins)."""
        return _StabilizeStatus(
            converged=self.converged and other.converged,
            updates=self.updates + other.updates,
            rounds=self.rounds + other.rounds,
            capped_keys=tuple(sorted(set(self.capped_keys) | set(other.capped_keys))),
            pending_count=self.pending_count + other.pending_count,
            max_updates=max(self.max_updates, other.max_updates),
            hit_global_cap=self.hit_global_cap or other.hit_global_cap)

    def to_dict(self) -> dict:
        return {"converged": self.converged, "updates": self.updates,
                "rounds": self.rounds, "capped_keys": list(self.capped_keys),
                "n_capped_keys": len(self.capped_keys),
                "pending_count": self.pending_count,
                "max_updates": self.max_updates,
                "hit_global_cap": self.hit_global_cap}


_EMPTY_STATUS = _StabilizeStatus(True, 0, 0, (), 0, 0, False)


class _FindingList(list):
    """A plain list of findings that also carries the analysis status.

    detect() returns this so callers that treat it as a list are unchanged,
    while an evaluation harness can read ``.analysis_status`` to tell a record
    whose summary table converged from one that stopped at a capped
    approximation. A capped record must not be reported as a clean success.
    """
    analysis_status: dict = {}


# The status of the most recent detect() call, for callers that only keep the
# plain findings list. detect() also attaches it to the returned _FindingList.
LAST_ANALYSIS_STATUS: dict = {}


def _stabilize_summaries(definitions: dict, summaries: dict,
                         initial_keys=None, changed_out: set | None = None,
                         callers: dict | None = None) -> _StabilizeStatus:
    """Dependency-driven bounded iterative stabilization of the summary table.

    Rebuild each requested definition once, then only rebuild its callers when
    the callee actually changes. This reaches chains of arbitrary declaration
    order without rescanning every unrelated function for a hard-coded number
    of global rounds. Recursive or cyclic call graphs can oscillate between
    equivalent conservative approximations, so a per-key cap
    (``_PER_KEY_UPDATE_CAP`` changes per definition) and a global cap
    (``max(64, 4|D|)`` total updates) bound the work. Returns a
    ``_StabilizeStatus`` recording whether a true fixpoint was reached or a cap
    forced an approximation. Callers that discard the status silently downgrade
    a capped approximation into a claimed success, so they must not.
    """
    callers = (callers if callers is not None
               else _build_summary_callers(definitions, summaries))

    pending = deque(initial_keys if initial_keys is not None else definitions)
    queued = set(pending)
    updates = 0
    rounds = 0
    updates_by_key = {}
    capped_keys: set = set()
    trace_fields: dict = {}          # field name -> how many updates it was responsible for
    trace_keys: dict = {}            # definition key -> update count (trace mode only)
    # Global cap scales with the per-key cap. At the contract default (4) this is
    # exactly max(64, len(definitions) * 4), i.e. byte-for-byte the wisp-scanner-v1.1
    # behaviour; only a raised WISP_PER_KEY_CAP moves it. An earlier version of this
    # line added a further +64, which was NOT identical at the default and would have
    # silently put the sensitivity runs on a different engine from the main tables.
    max_updates = max(64, len(definitions) * _PER_KEY_UPDATE_CAP)
    while pending and updates < max_updates:
        key = pending.popleft()
        queued.discard(key)
        rounds += 1
        if updates_by_key.get(key, 0) >= _PER_KEY_UPDATE_CAP:
            # A caller re-queued this definition after it already changed the
            # capped number of times. Refusing the rebuild is the approximation:
            # record it so the result is not reported as a clean fixpoint.
            capped_keys.add(key)
            continue
        item = definitions.get(key)
        if item is None:
            continue
        fn, src, rel, abs_file = item
        new_summary = _build_summary(fn, src, summaries, rel, abs_file)
        old_summary = summaries.get(key)
        if old_summary == new_summary:
            continue
        summaries[key] = new_summary
        if _STABILIZE_TRACE:
            for f in _field_delta(old_summary, new_summary):
                trace_fields[f] = trace_fields.get(f, 0) + 1
            trace_keys[key] = trace_keys.get(key, 0) + 1
        # Composite virtual-dispatch summaries may include the replaced object.
        # Clearing prevents CPython id reuse from returning a stale merge.
        _MERGED_SUMMARY_CACHE.clear()
        if changed_out is not None:
            changed_out.add(key)
        updates += 1
        updates_by_key[key] = updates_by_key.get(key, 0) + 1
        for caller_key in callers.get(key, ()):
            if caller_key not in queued:
                pending.append(caller_key)
                queued.add(caller_key)
    hit_global_cap = updates >= max_updates and bool(pending)
    if _STABILIZE_TRACE:
        try:
            import json                      # local: the engine does not import json otherwise
            with open(_STABILIZE_TRACE, "a", encoding="utf-8") as fh:
                top = sorted(trace_keys.items(), key=lambda kv: -kv[1])[:15]
                fh.write(json.dumps({
                    "definitions": len(definitions), "updates": updates, "rounds": rounds,
                    "max_updates": max_updates, "pending_left": len(pending),
                    "hit_global_cap": hit_global_cap, "n_capped_keys": len(capped_keys),
                    "updates_by_field": trace_fields,
                    "distinct_keys_updated": len(trace_keys),
                    "top_keys": [{"key": k[-90:], "updates": n} for k, n in top],
                }) + "\n")
        except OSError:
            pass
    return _StabilizeStatus(
        converged=(not pending) and (not capped_keys) and (not hit_global_cap),
        updates=updates, rounds=rounds,
        capped_keys=tuple(sorted(capped_keys)),
        pending_count=len(pending), max_updates=max_updates,
        hit_global_cap=hit_global_cap)


def _return_tainted_with(body, src, summaries, taint: dict,
                         sink_class=None) -> bool:
    """Walk the body in order with the given seed taint; True if any return
    statement returns a tainted value."""
    if body is None:
        return False
    ana = _Analyzer(src, "", "", summaries)
    ana.probe_returns = True
    ana.return_probe_class = sink_class
    _walk_stmts(body, src, ana, taint, "@summary", "", "", summaries,
                record=False)
    return ana.return_tainted


def detect_file(abs_file: str, rel: str, summaries: dict,
                emit_guards: bool = True,
                callback_contexts: dict | None = None,
                summaries_complete: bool = False,
                parsed=None) -> tuple[list, dict]:
    """Analyze one PHP file. Returns (findings, summaries-from-this-file).

    `emit_guards=False` suppresses missing-guard emission so the plugin-level
    driver can emit them with cross-file context (used by detect() under
    WISP_GDA_EMIT so guards are emitted once, with caller/REST/admin credits)."""
    if not summaries_complete:
        # Standalone calls have no plugin property pass and must not inherit the
        # module-global table left by an earlier detect(plugin) invocation.
        global TAINTED_PROPS
        TAINTED_PROPS = {}
        _NAMESPACE_CACHE.clear()
        _reset_class_hierarchy()
    if parsed is not None:
        src, funcs, root = parsed
    else:
        try:
            with open(abs_file, "rb") as fh:
                src = fh.read()
        except OSError:
            return [], {}
        if b"<?" not in src:
            return [], {}
        root = _parser().parse(src).root_node
        funcs = _collect_functions(root, src)
    if not summaries_complete:
        _collect_class_hierarchy(root, src)
        _finish_class_hierarchy()
    local_summaries = {}
    if summaries_complete:
        # detect() has already stabilized the plugin-wide table. Rebuilding every
        # function here made pass 2 repeat the most expensive analysis per file.
        merged = summaries
    else:
        working_summaries = dict(summaries)
        definitions = {}
        for fn in funcs:
            key = _summary_key(fn, src)
            definitions[key] = (fn, src, rel, abs_file)
            working_summaries[key] = _build_summary(
                fn, src, working_summaries, rel, abs_file)
        _stabilize_summaries(definitions, working_summaries)
        local_summaries = {
            key: working_summaries[key] for key in definitions
            if key in working_summaries
        }
        merged = working_summaries
    if callback_contexts is None:
        # Standalone callers (self-tests / independent benchmarks) still obtain
        # callback semantics from registrations in this file. Plugin-level
        # detect() supplies a global, ambiguity-checked map across all files.
        callback_contexts = _build_callback_contexts(
            {abs_file: (src, funcs)}, merged, roots={abs_file: root})
    ana = _Analyzer(src, rel, abs_file, merged)

    # Analyze each function body with concrete (global) taint. Framework
    # callback parameters are attacker-influenced even when no superglobal is
    # read in the body (block attributes, shortcode attrs, REST request object).
    for fn in funcs:
        body = _child(fn, "compound_statement")
        fn_name = _fn_name(fn, src)
        contexts = callback_contexts.get(
            (abs_file, _summary_key(fn, src)), frozenset())
        params = _param_names(fn, src)
        extra_sources = {}
        if params and contexts:
            label_context = "/".join(sorted(contexts))
            if contexts.intersection(("block", "rest", "shortcode")):
                extra_sources[params[0]] = f"{label_context} callback input {params[0]}"
            if "acf_field_render" in contexts:
                for quote in ("'", '"'):
                    for field_key in ("value", "default_value"):
                        key = f"{params[0]}[{quote}{field_key}{quote}]"
                        extra_sources[key] = f"ACF stored field value {key}"
            if "embed" in contexts and len(params) >= 3:
                extra_sources[params[2]] = f"embed callback URL {params[2]}"
        render_contexts = sorted(contexts.intersection(("block", "shortcode")))
        fn_ana = _Analyzer(
            src, rel, abs_file, merged,
            return_xss_context="/".join(render_contexts),
            render_return_vars=_returned_variable_names(body, src),
            render_seed_vars=extra_sources,
            framework_contexts=contexts,
            acf_field_param=(params[0]
                             if params and "acf_field_render" in contexts else ""),
        )
        # Seed callback parameters into the normal taint state. This lets a
        # sanitizer/reassignment clean or transform the value correctly; an
        # immutable "extra source" check would re-taint the variable forever.
        _walk_stmts(body, src, fn_ana, dict(extra_sources), fn_name,
                    rel, abs_file, merged, record=True)
        ana.findings.extend(fn_ana.findings)
    # top-level code (outside any function)
    _walk_top_level(root, funcs, src, ana, rel, abs_file, merged)
    # framework-aware CSRF / access-control findings.
    if emit_guards:
        if os.environ.get("WISP_GDA_EMIT") == "1":
            # single-file dominance-based emission (intra-file only: no cross-file
            # caller/REST/admin credits). The plugin driver passes emit_guards=False
            # and does the cross-file emission itself, so this branch runs only for
            # standalone single-file callers (e.g. the selftest / detect_file API).
            from .taint_guardflow import emit_missing_guards
            cache1 = {abs_file: (src, funcs)}
            hmap = _build_handler_map(cache1)
            ep_of = _entry_point_per_func(hmap, _build_call_graph(cache1))
            ana.findings.extend(emit_missing_guards(
                cache1, {abs_file: rel}, ep_of=ep_of, handler_names=frozenset(hmap)))
        else:
            ana.findings.extend(_detect_missing_guards(funcs, src, rel, abs_file))

    return ana.findings, local_summaries


def _walk_top_level(root, funcs, src, ana, rel, abs_file, summaries,
                    record=True):
    fn_spans = [(f.start_byte, f.end_byte) for f in funcs]

    def inside_fn(node):
        return any(s <= node.start_byte and node.end_byte <= e for s, e in fn_spans)

    taint = {}
    for stmt in root.children:
        if inside_fn(stmt):
            continue
        # _visit (not _walk_stmts) so the statement NODE itself is handled — this
        # is what makes top-level echo / `<?= ?>` short-echo / include sinks fire
        # in template files, where the sink is a bare top-level statement.
        _visit(stmt, src, ana, taint, "@global", rel, abs_file, summaries,
               record=record)


def _iter_assignments(node):
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in ("assignment_expression", "augmented_assignment_expression"):
            yield n
        stack.extend(n.children)


def _collect_tainted_props(plugin, summaries, callback_contexts=None,
                           cache=None, roots=None) -> dict:
    """Build class-aware plugin property taint, including callback parameters.

    The normal statement walker is reused so locals, sanitizers, branch joins and
    callback seeds have the same semantics as final emission. Values retain their
    per-sink sanitizer annotations instead of reducing every property to a bool.
    """
    global TAINTED_PROPS
    if _MONOTONE_PROPS:
        # Measured 2026-08-11. The outer driver alternates _stabilize_summaries with this pass until
        # neither moves. Clearing the table here makes that alternation non-monotone: a property
        # proven tainted in one outer round is recomputed from scratch in the next, and if the
        # summary that established it changed shape the property silently disappears, which flips
        # the summaries back. On nelio-content the trace shows five stabilization calls that ALL
        # converge on their own (448, 23, 9, 9, 9 updates, no cap fired) while the record is still
        # reported non-converged, because the outer loop cycles with period one. Keeping the table
        # and joining into it makes the outer domain monotone over a finite key set, so the
        # alternation reaches the driver's own exit test instead of exhausting its round cap.
        #
        # NOT a termination proof, and an earlier version of this comment claimed one. The driver
        # still stops at a four-round cap, and the summary half of the product is replaced wholesale
        # rather than joined, so the pair is not proved monotone. What changes is that the exit test
        # can now fire at all.
        #
        # The precise reason is the driver's own exit test. That loop breaks when
        # `changed_props` is empty, comparing this table against the previous round's copy. Rebuilt
        # from scratch each round against summaries that are themselves still moving, keys can
        # appear AND disappear, so the difference never empties and the loop runs its full round cap
        # and falls into the else branch that records non-convergence. A test of the form "stop when
        # nothing changed" only terminates over a monotone sequence, and the reset denied it one.
        TAINTED_PROPS = dict(TAINTED_PROPS)
    else:
        TAINTED_PROPS = {}
    callback_contexts = callback_contexts or {}
    if cache is None:
        cache = {}
        for abs_file in plugin.php_files:
            try:
                with open(abs_file, "rb") as fh:
                    src = fh.read()
                if b"<?" not in src:
                    continue
                root = _parser().parse(src).root_node
                cache[abs_file] = (src, _collect_functions(root, src))
            except Exception:
                continue
    roots = dict(roots or {})
    for abs_file, (src, funcs) in cache.items():
        if abs_file in roots:
            continue
        if funcs:
            root = funcs[0]
            while root.parent is not None:
                root = root.parent
            roots[abs_file] = root
        else:
            try:
                roots[abs_file] = _parser().parse(src).root_node
            except Exception:
                pass

    def _writes_property(scope) -> bool:
        return any(asn.children and asn.children[0].type in _MEMBER_LHS
                   for asn in _iter_assignments(scope))

    def _calls_property_writer(scope, src) -> bool:
        for call in _descend_calls(scope):
            name = _call_name(call, src).lstrip("\\").split("\\")[-1]
            summary = _lookup_summary(call, name, summaries, src)
            if summary is not None and summary.tainted_params_to_props:
                return True
        return False

    property_funcs = {
        abs_file: [fn for fn in funcs
                   if (body := _child(fn, "compound_statement")) is not None
                   and (_writes_property(body)
                        or _calls_property_writer(body, src))]
        for abs_file, (src, funcs) in cache.items()
    }

    def _top_writes_property(root) -> bool:
        for asn in _iter_assignments(root):
            if not asn.children or asn.children[0].type not in _MEMBER_LHS:
                continue
            parent = asn.parent
            nested = False
            while parent is not None and parent is not root:
                if parent.type in _SKIP_SUBTREE:
                    nested = True
                    break
                parent = parent.parent
            if not nested:
                return True
        return False

    def _top_calls_property_writer(root, src) -> bool:
        for call in _descend_calls(root):
            parent = call.parent
            nested = False
            while parent is not None and parent is not root:
                if parent.type in _SKIP_SUBTREE:
                    nested = True
                    break
                parent = parent.parent
            if nested:
                continue
            name = _call_name(call, src).lstrip("\\").split("\\")[-1]
            summary = _lookup_summary(call, name, summaries, src)
            if summary is not None and summary.tainted_params_to_props:
                return True
        return False

    top_property_files = {
        abs_file for abs_file, root in roots.items()
        if (_top_writes_property(root)
            or _top_calls_property_writer(root, cache[abs_file][0]))
    }

    def _merge_collected(collected):
        nonlocal changed
        for key, value in collected.items():
            joined = _tv_join(TAINTED_PROPS.get(key), value)
            if joined != TAINTED_PROPS.get(key):
                TAINTED_PROPS[key] = joined
                changed = True

    for _ in range(4):
        changed = False
        for abs_file, (src, funcs) in cache.items():
            for fn in property_funcs.get(abs_file, ()):
                body = _child(fn, "compound_statement")
                params = _param_names(fn, src)
                contexts = callback_contexts.get(
                    (abs_file, _summary_key(fn, src)), frozenset())
                seed = {}
                if params and contexts.intersection(("block", "rest", "shortcode")):
                    seed[params[0]] = f"callback input {params[0]}"
                if "embed" in contexts and len(params) >= 3:
                    seed[params[2]] = f"embed callback URL {params[2]}"
                ana = _Analyzer(src, "", abs_file, summaries)
                ana.collected_props = {}
                _walk_stmts(body, src, ana, seed, _fn_name(fn, src), "",
                            abs_file, summaries, record=False)
                _merge_collected(ana.collected_props)
            root = roots.get(abs_file) if abs_file in top_property_files else None
            if root is not None:
                top_ana = _Analyzer(src, "", abs_file, summaries)
                top_ana.collected_props = {}
                _walk_top_level(root, funcs, src, top_ana, "", abs_file,
                                summaries, record=False)
                _merge_collected(top_ana.collected_props)
        if not changed:
            break
    return TAINTED_PROPS


def _property_reader_index(definitions: dict) -> dict[str, set[str]]:
    """Map canonical property keys to summaries affected by their value.

    Keep assignment LHS nodes in this conservative index: `_build_summary`'s
    property-effect pre-scan currently observes every member node, including a
    writer. This stays cheaper than rebuilding every definition while matching
    the summary transfer exactly.
    """
    readers: dict[str, set[str]] = {}
    for definition_key, (fn, src, _rel, _abs_file) in definitions.items():
        body = _child(fn, "compound_statement")
        stack = [body] if body is not None else []
        while stack:
            node = stack.pop()
            if node is not body and node.type in _SKIP_SUBTREE:
                continue
            if node.type in _MEMBER_LHS:
                prop_key = _property_summary_key(node, src)
                readers.setdefault(prop_key, set()).add(definition_key)
            stack.extend(node.children)
    return readers


def detect(plugin, _configs=None, _timeout=0, _jobs=0) -> list:
    """Detector entrypoint matching l2_detect.detect signature shape.

    Four passes over the plugin:
    1. Gather function summaries across files.
    1b. Bounded iterative stabilization of the summary table (Re3-inspired, Paper 04):
        a dependency-driven worklist re-builds summaries until no change, bounded by
        a per-definition and a global update cap. This resolves A→B→C call chains
        regardless of file-processing order — the dominant Cat-B miss class. It is
        NOT a guaranteed least fixed point on cyclic graphs; the returned status
        records whether a cap forced an approximation.
    1c. Collect plugin-wide tainted-property summary (cross-method OO flows).
    2. Emit findings using the completed summary table.

    Returns a _FindingList (a list subclass) whose .analysis_status reports whether
    the summary table converged or stopped at a bounded approximation.
    """
    global TAINTED_PROPS
    # Plugin analyses are independent; never let a previous plugin's property
    # table influence the next plugin's initial summary pass.
    TAINTED_PROPS = {}
    _NAMESPACE_CACHE.clear()
    _reset_class_hierarchy()
    summaries: dict = {}
    definitions: dict = {}
    # pass 1: cache parsed trees and collect the complete class hierarchy before
    # any method summary is built. This makes declaration/file order irrelevant.
    _cache: dict = {}  # abs_file -> (src, funcs)
    _roots: dict = {}
    for abs_file in plugin.php_files:
        try:
            with open(abs_file, "rb") as fh:
                src = fh.read()
            if b"<?" not in src:
                continue
            root = _parser().parse(src).root_node
            funcs = _collect_functions(root, src)
            _cache[abs_file] = (src, funcs)
            _roots[abs_file] = root
            _collect_class_hierarchy(root, src)
        except Exception:
            continue
    _finish_class_hierarchy()
    for abs_file, (src, funcs) in _cache.items():
        rel = os.path.relpath(abs_file, plugin.root)
        for fn in funcs:
            key = _summary_key(fn, src)
            definitions[key] = (fn, src, rel, abs_file)
            empty = _Summary(
                _fn_name(fn, src), _param_names(fn, src), {}, set(), False,
                set())
            empty.is_method = fn.type == "method_declaration"
            summaries[key] = empty

    # pass 1b: dependency-driven fixpoint (arbitrary call-chain depth). Every
    # definition key already exists, so call edges are complete without a first
    # redundant full summary sweep.
    summary_callers = _build_summary_callers(definitions, summaries)
    stab_status = _stabilize_summaries(
        definitions, summaries, callers=summary_callers)

    # pass 1c: plugin-wide tainted-property summary (cross-method).
    # Callback contexts must exist first: framework parameters, not only explicit
    # superglobals, can be assigned into properties consumed by another method.
    callback_contexts = _build_callback_contexts(
        _cache, summaries, roots=_roots)
    if os.environ.get("WISP_NO_PROPS") == "1":
        TAINTED_PROPS = {}
    else:
        # Properties and return summaries depend on each other (setter -> getter
        # -> second property). Alternate the two analyses under a bounded
        # iterative stabilization instead of stopping after a one-way property
        # pass. The round cap below is another approximation bound, not a proof of
        # convergence, so exhausting it is surfaced in the analysis status.
        property_readers = _property_reader_index(definitions)
        previous_props = {}
        _PROP_ROUND_CAP = 4
        for _property_round in range(_PROP_ROUND_CAP):
            try:
                _collect_tainted_props(
                    plugin, summaries, callback_contexts=callback_contexts,
                    cache=_cache, roots=_roots)
            except Exception:
                TAINTED_PROPS = {}
                break
            changed_props = {
                key for key in set(previous_props).union(TAINTED_PROPS)
                if previous_props.get(key) != TAINTED_PROPS.get(key)
            }
            if not changed_props:
                break
            affected = set()
            for prop_key in changed_props:
                affected.update(property_readers.get(prop_key, ()))
            if not affected:
                break
            changed_summaries = set()
            stab_status = stab_status.merge(_stabilize_summaries(
                definitions, summaries, initial_keys=affected,
                changed_out=changed_summaries, callers=summary_callers))
            if not changed_summaries:
                break
            previous_props = dict(TAINTED_PROPS)
        else:
            # Ran the full round cap with the property/summary pair still
            # changing: the cross-method property analysis did not converge.
            stab_status = stab_status.merge(_StabilizeStatus(
                converged=False, updates=0, rounds=_PROP_ROUND_CAP,
                capped_keys=(), pending_count=0,
                max_updates=_PROP_ROUND_CAP, hit_global_cap=True))
    # pass 2: emit findings using the completed summary table
    _gda_emit = os.environ.get("WISP_GDA_EMIT") == "1"
    all_findings = []
    for abs_file in plugin.php_files:
        rel = os.path.relpath(abs_file, plugin.root)
        try:
            # under WISP_GDA_EMIT the plugin-level emitter below produces the guards
            # (with cross-file credits), so per-file emission is suppressed here.
            fnds, _ = detect_file(
                abs_file, rel, summaries, emit_guards=not _gda_emit,
                callback_contexts=callback_contexts, summaries_complete=True,
                parsed=(_cache[abs_file][0], _cache[abs_file][1],
                        _roots[abs_file]))
            all_findings.extend(fnds)
        except Exception:
            continue
    # WISP_GDA_EMIT=1: dominance-based missing-guard emission at the plugin level
    # (recovers branch-specific / after-mutation guards the presence detector hides,
    # drops the caller/REST/admin over-reports). detect_file skipped the per-file
    # presence detector, so this is the sole missing-guard source when enabled.
    if _gda_emit:
        try:
            from .taint_guardflow import emit_missing_guards
            hmap = _build_handler_map(_cache)
            cg = _build_call_graph(_cache)
            ep_of = _entry_point_per_func(hmap, cg)
            rel_of = {a: os.path.relpath(a, plugin.root) for a in plugin.php_files}
            all_findings.extend(emit_missing_guards(
                _cache, rel_of, ep_of=ep_of, handler_names=frozenset(hmap)))
        except Exception:
            pass
    deduped = _dedupe(all_findings)
    if os.environ.get("WISP_HANDLER_EP") == "1":       # reviewer 2.3: handler-level
        annotated = _annotate_entry_points_handler(deduped, _cache)
    else:
        annotated = _annotate_entry_points(deduped, plugin.php_files)  # [Paper13] file-level

    # Inter-procedural guard-dominance analysis (GDA, taint_guardflow): attach a
    # guard deficit to each missing-guard (csrf/auth) finding. Pure re-ranking
    # signal — no finding is dropped, so recall is unchanged; it lifts the genuinely
    # unprotected access-control sink over the many spuriously-flagged guarded ones
    # (guard in caller / REST permission_callback / admin-cap registration / a
    # dominating intra-procedural guard). Default on; WISP_NO_GDA=1 disables it.
    if os.environ.get("WISP_NO_GDA") != "1":
        try:
            _apply_guard_deficits(annotated, _cache)
        except Exception:
            pass
    # Rank by exploitability so an analyst (and precision@K) sees the most likely-
    # reachable real vulnerabilities first. Pure reordering — no finding dropped,
    # so recall is untouched; it turns the flat 27-findings/plugin list into a
    # triaged one. Reachability from an UNAUTHENTICATED entry point (ajax_nopriv,
    # REST) is the strongest real-exploit signal on WP; a proven inter-procedural
    # data-flow and higher confidence break ties.
    if os.environ.get("WISP_NO_RANK") != "1":       # ABLATION: WISP_NO_RANK=1 keeps
        annotated.sort(key=_exploitability, reverse=True)   # natural discovery order

    # Record whether the summary table reached a true fixpoint or stopped at a
    # bounded approximation. A capped record is NOT a clean success: an
    # evaluation must count it as incomplete rather than "completed, no timeout".
    global LAST_ANALYSIS_STATUS
    status = stab_status.to_dict()
    status["complete"] = stab_status.converged
    status["sani_class_propagation"] = _sani_class_enabled()
    LAST_ANALYSIS_STATUS = status
    result = _FindingList(annotated)
    result.analysis_status = status
    return result


# entry-point exploitability weight: an unauthenticated hook is the most likely to
# be remotely reachable by an attacker; admin-only/unknown are least. Mirrors the
# _WP_ANCHOR_PATTERNS priority ladder (Paper 13/17 hook-reachability, as a RANKING
# signal only — never a hard prune, so recall-first is preserved).
_ENTRY_WEIGHT = {
    "ajax_nopriv": 5.0,   # unauthenticated AJAX — most exploitable
    "rest_api":    4.0,   # REST route (often permission_callback=__return_true)
    "shortcode":   3.0,   # attacker-influenced via post content / block attrs
    "ajax_auth":   2.5,   # authenticated AJAX (needs a session)
    "admin":       1.0,   # admin-context; needs privilege
    "unknown":     0.5,
}


def _exploitability(f) -> float:
    """Sort key: reachability-from-unauth first, then proven data-flow, then
    confidence. Higher = triage sooner.

    WISP_RANK_WFLOW (default 1.0) scales the per-finding reliability term
    (confidence). File-level entry-point weight (range 0.5-5.0) otherwise
    dominates, so within a single vulnerable file the ordering among findings of
    different classes is almost arbitrary. Raising w_flow lets a concrete
    source-to-sink taint finding (confidence 0.66-0.72) outrank a heuristic
    missing-guard (0.5) or risk-pattern (0.45) finding in the same file, which is
    what class-and-file@1 rewards. The weight is calibrated on a train split and
    evaluated on a disjoint test split (see eval.split_traintest), never tuned on
    the reported set.

    WISP_RANK_WGUARD (default 1.0) scales the inter-procedural guard-dominance
    deficit (taint_guardflow): a missing-guard finding whose access-control sink is
    genuinely unprotected on every path (deficit ~1) is ranked above one where a
    guard dominates in the caller/route/registration (deficit ~0). Access-control
    (auth) + CSRF are the largest advisory classes, so ordering the truly
    unprotected sink first is what class-and-file@K rewards on them. The deficit is
    -1 for non-missing-guard findings (term contributes 0 there)."""
    try:
        wflow = float(os.environ.get("WISP_RANK_WFLOW", "1.0"))
    except ValueError:
        wflow = 1.0
    try:
        wguard = float(os.environ.get("WISP_RANK_WGUARD", "0.5"))
    except ValueError:
        wguard = 0.5
    try:
        gcenter = float(os.environ.get("WISP_RANK_WGUARD_CENTER", "0.0"))
    except ValueError:
        gcenter = 0.0
    deficit = float(getattr(f, "guard_deficit", -1.0))
    # wguard*(deficit-center): center=0 promotes unprotected sinks; center=0.5 also
    # demotes guard-dominated ones so non-guard advisories surface. Calibrated on the
    # train split (eval.gda_report), evaluated on the disjoint test split.
    guard_term = wguard * (deficit - gcenter) if deficit >= 0.0 else 0.0
    return (_ENTRY_WEIGHT.get(getattr(f, "entry_point", "unknown"), 0.5)
            + (1.0 if getattr(f, "interprocedural", False) else 0.0)
            + wflow * float(getattr(f, "confidence", 0.6))
            + guard_term)


def _apply_guard_deficits(findings: list, cache: dict) -> None:
    """Attach the GDA guard deficit to each missing-guard (csrf/auth) finding.

    Resolves handler-level entry points once (independent of WISP_HANDLER_EP, which
    only controls per-finding entry-point *annotation*) so an unauthenticated reach
    keeps a sink's deficit high and an admin-only reach relaxes the capability
    deficit. Matches deficits to findings by (abs_file, line, class)."""
    from .taint_guardflow import compute_deficits
    handler_map = _build_handler_map(cache)
    call_graph = _build_call_graph(cache)
    ep_of = _entry_point_per_func(handler_map, call_graph)
    deficits = compute_deficits(cache, ep_of=ep_of, handler_names=frozenset(handler_map))
    for f in findings:
        if f.vuln_class not in ("csrf", "auth") or f.source != "request":
            continue
        fm = deficits.get(f.abs_file)
        if not fm:
            f.guard_deficit = 1.0          # unresolved => treat as unprotected
            continue
        key = (f.line, f.vuln_class)
        f.guard_deficit = fm.get(key, 1.0)


_WP_ANCHOR_PATTERNS = [
    # (regex, priority, entry_point_type)
    # Priority: lower = higher importance (ajax_nopriv = most exploitable)
    (b"add_action\\s*\\(\\s*['\"]wp_ajax_nopriv_([\\w]+)['\"]", 1, "ajax_nopriv"),
    (b"add_action\\s*\\(\\s*['\"]wp_ajax_([\\w]+)['\"]",        2, "ajax_auth"),
    (b"register_rest_route\\s*\\(",                              3, "rest_api"),
    (b"add_shortcode\\s*\\(\\s*['\"]([\\w-]+)['\"]",            4, "shortcode"),
    (b"add_action\\s*\\(\\s*['\"]init['\"]",                    5, "admin"),
    (b"add_action\\s*\\(\\s*['\"]admin_",                       6, "admin"),
]


def _build_anchor_map(php_files: list) -> dict:
    """Scan all PHP files for WordPress entry-point hooks.
    Returns dict: rel_file -> (priority, entry_point, name).
    Lower priority = more exploitable (ajax_nopriv=1).
    """
    import re
    file_anchors: dict = {}
    for abs_file in php_files:
        try:
            src = open(abs_file, "rb").read()
        except Exception:
            continue
        best = (99, "unknown", "")
        for pat, prio, ep_type in _WP_ANCHOR_PATTERNS:
            m = re.search(pat, src)
            if m:
                name = m.group(1).decode("utf-8", "ignore") if m.lastindex else ep_type
                if prio < best[0]:
                    best = (prio, ep_type, name)
        if best[1] != "unknown":
            rel = abs_file  # key by abs path; caller converts
            file_anchors[abs_file] = (best[1], best[2])
    return file_anchors


def _annotate_entry_points(findings: list, php_files: list) -> list:
    """Attach entry_point + entry_point_name to each finding (Paper 13 anchor query)."""
    anchor_map = _build_anchor_map(php_files)
    for f in findings:
        ep, ep_name = anchor_map.get(f.abs_file, ("unknown", ""))
        f.entry_point = ep
        f.entry_point_name = ep_name
    return findings


# --------------------------------------------------------------------------- #
# Handler-level entry-point resolution (reviewer 2.3): instead of tagging every
# finding in a file with the strongest hook registered anywhere in that file,
# resolve each hook registration to its callback FUNCTION, then attribute the
# entry point only to findings in that function and the functions it transitively
# calls. Behind WISP_HANDLER_EP=1 so the default numbers are unchanged until
# measured.
# --------------------------------------------------------------------------- #
_EP_PRIO = {"ajax_nopriv": 1, "ajax_auth": 2, "rest_api": 3, "shortcode": 4,
            "admin": 5, "unknown": 99}

# hook-name prefix -> entry-point type for add_action/add_filter callbacks
_HOOK_EP = [
    ("wp_ajax_nopriv_", "ajax_nopriv"),
    ("admin_post_nopriv_", "ajax_nopriv"),
    ("wp_ajax_", "ajax_auth"),
    ("admin_post_", "ajax_auth"),
]

_RE_ADD_ACTION = re.compile(
    r"""add_(?:action|filter)\s*\(\s*['"]([\w-]+)['"]\s*,\s*(.+?)\)""", re.S)
_RE_ADD_SHORTCODE = re.compile(
    r"""add_shortcode\s*\(\s*['"][\w-]+['"]\s*,\s*(.+?)\)""", re.S)
_RE_REST = re.compile(
    r"""register_rest_route\s*\((.+?)\)\s*;""", re.S)


def _iter_call_arguments(text: str, call_name: str):
    """Yield balanced argument text for calls named ``call_name``.

    Registration callbacks commonly use nested ``array(...)`` / ``[...]``
    expressions.  A non-greedy regex stops at the first closing parenthesis and
    silently truncates those callbacks, so scan balanced delimiters instead.
    """
    pat = re.compile(r"\b" + re.escape(call_name) + r"\s*\(")
    for match in pat.finditer(text):
        open_pos = text.find("(", match.start())
        depth = 1
        quote = ""
        escaped = False
        i = open_pos + 1
        while i < len(text):
            ch = text[i]
            if quote:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = ""
            elif ch in ("'", '"'):
                quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    yield text[open_pos + 1:i]
                    break
            i += 1


def _split_top_level_args(text: str) -> list[str]:
    """Split a PHP argument list on commas outside strings/delimiters."""
    parts = []
    start = 0
    stack = []
    quote = ""
    escaped = False
    pairs = {")": "(", "]": "[", "}": "{"}
    for i, ch in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if stack and stack[-1] == pairs[ch]:
                stack.pop()
        elif ch == "," and not stack:
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:].strip())
    return parts


def _extract_key_value(text: str, key: str) -> str | None:
    """Extract a balanced ``'key' => value`` expression from a PHP array."""
    match = re.search(r"['\"]" + re.escape(key) + r"['\"]\s*=>", text)
    if not match:
        return None
    tail = text[match.end():]
    return _split_top_level_args(tail)[0].strip() if tail.strip() else None


def _extract_array_value(nodes, key: str, src) -> str | None:
    """AST-safe lookup of a literal PHP array key.

    Comment text and string contents outside a real ``key => value`` initializer
    are never interpreted as registration metadata.
    """
    stack = list(nodes or ())
    while stack:
        node = stack.pop()
        if node.type == "array_element_initializer":
            named = [child for child in node.children if child.is_named]
            has_arrow = any(child.type == "=>" for child in node.children)
            if has_arrow and len(named) >= 2:
                raw_key = _text(named[0], src).strip().strip("'\"")
                if raw_key == key:
                    return _text(named[-1], src).strip()
        if node.type != "comment":
            stack.extend(node.children)
    return None


def _callback_terminal_name(cb_text: str):
    """Extract the terminal function/method name from a callback expression:
    'func' | "Class::method" | array($this,'m') | [$this,'m'] | array('C','m')."""
    cb_text = cb_text.strip()
    if re.match(r"^(?:static\s+)?(?:function|fn)\b", cb_text):
        return None                         # anonymous callback has no stable name
    # In callback arrays the terminal method is the LAST quoted identifier:
    # ['Handler', 'handle'], [$this, 'handle'], [Handler::class, 'handle'].
    quoted = re.findall(r"['\"]([A-Za-z_\\][\w\\:]*)['\"]", cb_text)
    raw = quoted[-1] if quoted else ""
    if not raw:
        scoped = re.search(r"\b[A-Za-z_\\][\w\\]*::([A-Za-z_]\w*)\b", cb_text)
        if scoped:
            raw = scoped.group(1)
    if not raw:
        bare = re.fullmatch(r"\\?([A-Za-z_]\w*)", cb_text)
        raw = bare.group(1) if bare else ""
    if "::" in raw:
        raw = raw.split("::")[-1]
    if "\\" in raw:
        raw = raw.split("\\")[-1]
    return raw or None


def _callback_identity(cb_text: str, owner_class: str | None = None,
                       lexical_ns: str = ""):
    """Resolve a callback to the same canonical key used by summaries.

    Explicit class arrays and ``$this`` callbacks must bind to that class; a
    terminal-name-only match can seed an unrelated same-named method. Dynamic
    object callbacks are deliberately unresolved rather than guessed.
    """
    text = (cb_text or "").strip()
    name = _callback_terminal_name(text)
    if not name:
        return None

    owner = (owner_class or "").strip("\\")
    quoted = re.findall(r"['\"]([A-Za-z_\\][\w\\:]*)['\"]", text)
    # Direct string callback: 'Class::method'.
    if len(quoted) == 1 and "::" in quoted[0]:
        cls, method = quoted[0].rsplit("::", 1)
        return _method_key(cls, method)       # callable strings are explicit
    # [$this, 'method'], [self::class, 'method'], [__CLASS__, 'method'].
    if re.search(r"\$this\b|\b(?:self|static)::class\b|\b__CLASS__\b", text):
        return _method_key(owner, name) if owner else None
    # [Concrete::factory(...), 'method'] is a common singleton callback shape.
    # The receiver class is still statically explicit; only the factory result
    # is dynamic. Resolve that exact class without guessing `$handler` arrays.
    factory_receiver = re.match(
        r"^(?:array\s*\(|\[)\s*((?:\\)?[A-Za-z_][A-Za-z0-9_\\]*)"
        r"::[A-Za-z_]\w*\s*\(", text)
    if factory_receiver:
        cls = _resolve_code_name(factory_receiver.group(1), lexical_ns)
        return _method_key(cls, name)
    # [Concrete::class, 'method'] or array(new Concrete(), 'method').
    explicit = re.search(
        r"(?<![A-Za-z0-9_\\])((?:\\)?[A-Za-z_][A-Za-z0-9_\\]*)::class\b",
        text)
    if not explicit:
        explicit = re.search(r"\bnew\s+((?:\\)?[A-Za-z_][A-Za-z0-9_\\]*)\b",
                             text)
    if explicit:
        cls = _resolve_code_name(explicit.group(1), lexical_ns)
        return _method_key(cls, name)
    # ['Concrete', 'method'] callback array.
    if len(quoted) >= 2 and ("[" in text or re.match(r"array\s*\(", text)):
        cls = quoted[-2].strip("\\")          # callable strings are explicit
        if cls in ("self", "static", "__CLASS__"):
            cls = owner
        return _method_key(cls, name) if cls else None
    # Any other callback array contains a dynamic receiver ($handler, expr...).
    if "[" in text or re.match(r"array\s*\(", text):
        return None
    # Plain quoted/bare callback is an explicit callable string. Preserve its
    # complete namespace instead of collapsing to the terminal function name.
    raw = quoted[0] if len(quoted) == 1 else text.strip().strip("'\"")
    return _free_key(raw)


def _build_callback_contexts(cache: dict, summaries: dict | None = None,
                             roots: dict | None = None) -> dict:
    """Map an unambiguous callback definition to its framework input context.

    Keys are ``(absolute_file, canonical-definition-key)``.
    Registrations cover only contexts whose first callback argument is attacker
    influenced; dynamic/unresolved callback receivers are dropped, not guessed.
    """
    registered: dict[str, set[str]] = {}

    def _record(callback_text, context, owner_class=None, lexical_ns=""):
        identity = _callback_identity(
            callback_text or "", owner_class, lexical_ns)
        if identity:
            registered.setdefault(identity, set()).add(context)

    definitions: dict[str, list[str]] = {}
    for abs_file, (src, funcs) in cache.items():
        for fn in funcs:
            definitions.setdefault(_summary_key(fn, src), []).append(abs_file)
        # Use AST call nodes so registrations shown in comments/documentation or
        # embedded in string literals cannot seed a real function parameter.
        root = (roots or {}).get(abs_file)
        if root is None:
            try:
                root = _parser().parse(src).root_node
            except Exception:
                continue
        for call in _descend_calls(root):
            if call.type != "function_call_expression":
                continue                    # core registrations are global calls
            if summaries is not None and not _is_global_vocab_call(call, src, summaries):
                continue                    # local shadow / vendor-qualified lookalike
            call_name = _call_name(call, src).lstrip("\\").split("\\")[-1]
            arg_nodes = _args(call)
            arg_text = [_text(arg, src) for arg in arg_nodes]
            owner = _enclosing_class_fq(call, src)
            namespace = _lexical_namespace(call, src)
            if call_name == "add_shortcode" and len(arg_text) >= 2:
                _record(arg_text[1], "shortcode", owner, namespace)
            elif call_name == "register_rest_route":
                _record(_extract_array_value(arg_nodes[2:], "callback", src),
                        "rest", owner, namespace)
            # Core embed handlers receive ($matches, $attr, $url, $rawattr); the
            # URL at index 2 originates in post/embed input and may reach SSRF.
            elif call_name == "wp_embed_register_handler" and len(arg_text) >= 3:
                _record(arg_text[2], "embed", owner, namespace)
            elif call_name in ("register_block_type", "register_block_type_from_metadata"):
                _record(_extract_array_value(
                            arg_nodes[1:], "render_callback", src),
                        "block", owner, namespace)

    contexts = {}
    for identity, kinds in registered.items():
        resolved_identity = identity
        locations = definitions.get(resolved_identity, ())
        if not locations and identity.startswith("M:\\") and "::" in identity:
            cls, method = identity[3:].rsplit("::", 1)
            inherited = _method_impl_key(cls, method, summaries or {})
            if inherited:
                resolved_identity = inherited
                locations = definitions.get(inherited, ())
        if len(locations) == 1:
            contexts[(locations[0], resolved_identity)] = frozenset(kinds)
    # Advanced Custom Fields invokes render_field($field) on subclasses of its
    # exact framework base class. This is an implicit callback contract rather
    # than a registration call, so seed it from the proven inheritance edge.
    for abs_file, (src, funcs) in cache.items():
        for fn in funcs:
            if fn.type != "method_declaration" or _fn_name(fn, src) != "render_field":
                continue
            cls = _enclosing_class_fq(fn, src)
            if cls and _class_inherits(cls, "acf_field"):
                key = (abs_file, _summary_key(fn, src))
                contexts[key] = frozenset(
                    set(contexts.get(key, ())).union({"acf_field_render"}))
    return contexts


def _build_handler_map(cache: dict) -> dict:
    """callback function name -> (entry_point, hook_name). Parses add_action /
    add_filter / add_shortcode / register_rest_route callback arguments."""
    handlers: dict = {}

    def _set(name, ep, hook):
        if not name:
            return
        if _EP_PRIO.get(ep, 99) < _EP_PRIO.get(handlers.get(name, ("unknown",))[0], 99):
            handlers[name] = (ep, hook)

    for _abs, (src, _funcs) in cache.items():
        try:
            text = src.decode("utf-8", "ignore")
        except Exception:
            continue
        for m in _RE_ADD_ACTION.finditer(text):
            hook, cb = m.group(1), m.group(2)
            ep = None
            for pref, eptype in _HOOK_EP:
                if hook.startswith(pref):
                    ep = eptype
                    break
            if ep is None and (hook == "init" or hook.startswith("admin_")):
                ep = "admin"
            if ep:
                _set(_callback_terminal_name(cb), ep, hook)
        for m in _RE_ADD_SHORTCODE.finditer(text):
            _set(_callback_terminal_name(m.group(1)), "shortcode", "shortcode")
        # Balanced parsing preserves callback arrays such as
        # ['Handler', 'handle']; the former regex stopped after 'Handler'.
        for args in _iter_call_arguments(text, "register_rest_route"):
            _set(_callback_terminal_name(_extract_key_value(args, "callback") or ""),
                 "rest_api", "rest")
    return handlers


def _build_call_graph(cache: dict) -> dict:
    """function name -> set of callee terminal names (name-based edges)."""
    graph: dict = {}
    for _abs, (src, funcs) in cache.items():
        for fn in funcs:
            name = _fn_name(fn, src)
            body = _child(fn, "compound_statement")
            callees = graph.setdefault(name, set())
            if body is None:
                continue
            for call in _descend_calls(body):
                cn = _call_name(call, src).lstrip("\\").split("\\")[-1]
                if cn:
                    callees.add(cn)
    return graph


def _entry_point_per_func(handler_map: dict, call_graph: dict, max_depth: int = 6) -> dict:
    """Propagate each handler's entry point forward through the call graph:
    a callee of an unauthenticated handler is itself reachable unauthenticated.
    Keeps the most-exploitable (lowest-priority) entry point per function."""
    ep_of: dict = {}
    frontier = []
    for name, (ep, hook) in handler_map.items():
        ep_of[name] = (ep, hook)
        frontier.append((name, ep, hook, 0))
    while frontier:
        name, ep, hook, depth = frontier.pop()
        if depth >= max_depth:
            continue
        for callee in call_graph.get(name, ()):  # forward edges
            cur = ep_of.get(callee)
            if cur is None or _EP_PRIO.get(ep, 99) < _EP_PRIO.get(cur[0], 99):
                ep_of[callee] = (ep, hook)
                frontier.append((callee, ep, hook, depth + 1))
    return ep_of


def _func_spans(cache: dict) -> dict:
    """abs_file -> list of (start_line, end_line, func_name), innermost last."""
    spans: dict = {}
    for abs_file, (src, funcs) in cache.items():
        lst = []
        for fn in funcs:
            lst.append((fn.start_point[0] + 1, fn.end_point[0] + 1, _fn_name(fn, src)))
        # sort by span width descending so the innermost enclosing wins on tie
        lst.sort(key=lambda t: (t[0], -(t[1] - t[0])))
        spans[abs_file] = lst
    return spans


def _annotate_entry_points_handler(findings: list, cache: dict) -> list:
    """Handler-level entry-point attribution (WISP_HANDLER_EP=1)."""
    handler_map = _build_handler_map(cache)
    call_graph = _build_call_graph(cache)
    ep_of = _entry_point_per_func(handler_map, call_graph)
    spans = _func_spans(cache)
    for f in findings:
        fn_name = None
        best = None
        for (s, e, nm) in spans.get(f.abs_file, ()):
            if s <= f.line <= e:
                # innermost: keep the smallest containing span
                if best is None or (e - s) <= best:
                    best = e - s
                    fn_name = nm
        ep, ep_name = ep_of.get(fn_name, ("unknown", "")) if fn_name else ("unknown", "")
        f.entry_point = ep
        f.entry_point_name = ep_name
    return findings


def _dedupe(findings: list) -> list:
    seen = {}
    for f in findings:
        # A callsite can fan out to multiple ultimate sinks with the same class
        # and canonical sink name. Retain each distinct trace endpoint.
        key = (f.file, f.line, f.vuln_class, f.sink,
               getattr(f, "sink_file", ""), getattr(f, "sink_line", 0))
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    out = list(seen.values())
    # Object-injection risk findings flood files with many unserialize() calls
    # (a plugin's own safe (de)serialization). Keep at most one risk finding per
    # file: enough for plugin-class recall and file-localization, far fewer FP.
    capped, risk_files = [], set()
    for f in out:
        if f.source == "unserialize(untrusted)":
            if f.file in risk_files:
                continue
            risk_files.add(f.file)
        capped.append(f)
    return capped
