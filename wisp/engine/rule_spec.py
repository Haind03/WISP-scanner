"""WISP rule-spec loader — replaces Semgrep with our own taint rules.

Loads the project's declarative taint specification (rules/wisp-rules.yaml)
into the vocabulary structures the tree-sitter taint engine consumes. Detection
is therefore driven by our own editable, machine-appendable rule file instead of
a third-party rule pack.

Why a loader and not hard-coded constants: the Stage-4 rule-mining loop appends
new sinks/sanitizers/rules to the YAML once a finding is PoC-confirmed and passes
false-positive regression. A declarative file is what makes that loop possible.

Graceful fallback: if the file (or pyyaml) is missing or malformed, `load()`
returns None and the caller keeps its built-in defaults, so the engine still runs.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field

DEFAULT_RULES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "rules", "wisp-rules.yaml",
)


@dataclass
class RuleSpec:
    superglobals: set
    source_funcs: set
    sink_funcs: dict          # callable name -> vuln class
    wpdb_sql_methods: set
    db_sink_funcs: set
    sanitizers: set
    # framework-aware missing-guard detector (CSRF / broken access control)
    state_change_funcs: set = field(default_factory=set)
    state_change_wpdb: set = field(default_factory=set)
    guard_nonce: set = field(default_factory=set)
    guard_capability: set = field(default_factory=set)
    # precision vocab learned from LLM-verify (Stage-4)
    safe_members: dict = field(default_factory=dict)   # superglobal -> {member,...}
    predicate_funcs: set = field(default_factory=set)  # return bool/int, drop taint
    pattern_only_sinks: set = field(default_factory=set)
    method_sinks: dict = field(default_factory=dict)  # $obj->NAME() sink -> class (recall-growth loop)
    version: int = 1
    path: str = ""

    def summary(self) -> str:
        return (f"WISP rules v{self.version}: "
                f"{len(self.superglobals)} sources, "
                f"{len(self.sink_funcs)} sink funcs, "
                f"{len(self.wpdb_sql_methods)} wpdb methods, "
                f"{len(self.db_sink_funcs)} db funcs, "
                f"{len(self.sanitizers)} sanitizers, "
                f"{len(self.state_change_funcs)} state-change funcs, "
                f"{len(self.predicate_funcs)} predicates, "
                f"{sum(len(v) for v in self.safe_members.values())} safe-members")


def load(path: str = DEFAULT_RULES) -> "RuleSpec | None":
    """Load the taint spec. Returns None on any failure (caller keeps defaults)."""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except Exception:
        return None

    try:
        superglobals = set(data.get("superglobals", []))
        source_funcs = set(data.get("source_funcs", []))
        # `learned_*` are append-only blocks the Stage-4 rule-mining loop writes
        # (LLM-proposed, reviewed, and regression-gated), kept separate so
        # automated edits never disturb the curated lists.
        sanitizers = set(data.get("sanitizers", [])) | set(data.get("learned_sanitizers", []) or [])
        if os.environ.get("WISP_NO_LEARNED") != "1":
            source_funcs |= set(data.get("learned_source_funcs", []) or [])

        sinks = data.get("sinks", {}) or {}
        sink_funcs: dict[str, str] = {}
        wpdb_methods: set[str] = set()
        db_funcs: set[str] = set()
        for vuln_class, spec in sinks.items():
            spec = spec or {}
            for fn in spec.get("funcs", []) or []:
                sink_funcs[fn] = vuln_class
            wpdb_methods.update(spec.get("wpdb_methods", []) or [])
            db_funcs.update(spec.get("db_funcs", []) or [])
        # learned detection sinks: function name -> vuln class (recall-growth loop)
        # ABLATION: WISP_NO_LEARNED=1 drops every recall-growth learned block
        no_learned = os.environ.get("WISP_NO_LEARNED") == "1"
        if not no_learned:
            for fn, vc in (data.get("learned_sinks", {}) or {}).items():
                sink_funcs[str(fn)] = str(vc)
        # learned METHOD sinks: $obj->name() -> vuln class (recall-growth loop)
        method_sinks: dict = {} if no_learned else {
            str(m): str(vc)
            for m, vc in (data.get("learned_method_sinks", {}) or {}).items()}
        # learned source functions already folded into source_funcs above

        # A spec with no sinks is useless; treat as failure -> defaults.
        if not (sink_funcs or wpdb_methods or db_funcs):
            return None

        sc = data.get("state_change", {}) or {}
        guards = data.get("guards", {}) or {}
        safe_members = {sg: set(members or [])
                        for sg, members in (data.get("safe_members", {}) or {}).items()}

        return RuleSpec(
            superglobals=superglobals,
            source_funcs=source_funcs,
            sink_funcs=sink_funcs,
            wpdb_sql_methods=wpdb_methods,
            db_sink_funcs=db_funcs,
            sanitizers=sanitizers,
            state_change_funcs=set(sc.get("funcs", []) or []),
            state_change_wpdb=set(sc.get("wpdb_methods", []) or []),
            guard_nonce=set(guards.get("nonce", []) or []),
            guard_capability=set(guards.get("capability", []) or []),
            safe_members=safe_members,
            predicate_funcs=set(data.get("predicate_funcs", []) or []),
            pattern_only_sinks=set(data.get("pattern_only_sinks", []) or []),
            method_sinks=method_sinks,
            version=int(data.get("version", 1)),
            path=path,
        )
    except Exception:
        return None
