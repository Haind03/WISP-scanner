"""L5 AI-Verify (LLM judge on the slice) - local CLI.

Sends the focused code slice + gate annotations to an LLM and asks for a
structured JSON verdict. Provider:

  * cli: a local agent CLI in headless mode (CLI_VERIFY_BIN). Supported bins are
         generic `-p` CLIs and `codex exec`. Uses the CLI's own login, so there
         is no metered API key. Optional CLI_VERIFY_MODEL picks the model.

The verdict shape, system prompt, and gate inputs are provider-neutral.
"""
from __future__ import annotations
import os
import re
import json
import subprocess
from dataclasses import dataclass

_PROPERTIES = {
    "is_vulnerable": "True only if a real, reachable vulnerability is present.",
    "vuln_class": "sqli, xss, lfi, rce, ssrf, csrf, auth, deserial, upload, other, or none.",
    "exploitable": "Can untrusted input actually reach the sink without an effective sanitizer/guard?",
    "sanitizer_present": "Is there an effective sanitizer/escaper/capability/nonce check on the path?",
    "confidence": "0.0-1.0 confidence in is_vulnerable.",
    "reasoning": "One or two sentences citing the specific lines/identifiers.",
    "safe_function": "If is_vulnerable is false BECAUSE one specific function on the "
                     "data path sanitizes/escapes/validates the input, give that bare "
                     "function name (e.g. my_clean, sanitize_foo, esc_widget); else "
                     "empty string. Used by the rule-mining loop.",
    # [Paper02 ISAL] line-level localization output
    "involved_lines": "Comma-separated line numbers (from the code slice) that form "
                      "the taint path — source line, key propagation lines, and sink "
                      "line. Empty string if not vulnerable. Improves line-level SFDR.",
}

VERDICT_TOOL = {
    "name": "report_verdict",
    "description": "Report the security verdict for the code slice.",
    "input_schema": {
        "type": "object",
        "properties": {k: ({"type": "boolean"} if k in ("is_vulnerable", "exploitable", "sanitizer_present")
                           else {"type": "number"} if k == "confidence" else {"type": "string"}) | {"description": d}
                       for k, d in _PROPERTIES.items()},
        "required": list(_PROPERTIES),
    },
}

# CWE descriptions and known WP sanitizers per class (Papers 22/23/15)
_CWE_CONTEXT = {
    "sqli":   ("CWE-89 SQL Injection",
               "user-controlled data reaches $wpdb->query/get_results/get_var without prepare().",
               ["prepare(", "esc_sql(", "intval(", "absint(", "(int)", "(float)"]),
    "xss":    ("CWE-79 Cross-Site Scripting",
               "user-controlled data output to HTML without encoding.",
               ["esc_html(", "esc_attr(", "esc_url(", "wp_kses", "htmlspecialchars("]),
    "rce":    ("CWE-78 Command Injection",
               "user-controlled data reaches system/exec/shell_exec/passthru/popen.",
               ["escapeshellarg(", "escapeshellcmd("]),
    "lfi":    ("CWE-22 Path Traversal",
               "user-controlled data in file path (include/require/file_get_contents).",
               ["realpath(", "basename(", "sanitize_file_name(", "wp_normalize_path("]),
    "upload": ("CWE-434 Unrestricted Upload",
               "file upload without mime/extension validation.",
               ["wp_check_filetype(", "getimagesize(", "finfo_file("]),
    "auth":   ("CWE-306 Authentication Bypass",
               "action/endpoint accessible without checking user capability or nonce.",
               ["current_user_can(", "wp_verify_nonce(", "check_ajax_referer("]),
    "csrf":   ("CWE-352 CSRF",
               "state-changing action without nonce verification.",
               ["wp_verify_nonce(", "check_admin_referer(", "check_ajax_referer("]),
    "ssrf":   ("CWE-918 SSRF",
               "user-controlled URL used in server-side HTTP request.",
               ["wp_http_validate_url(", "filter_var(", "FILTER_VALIDATE_URL"]),
    "deserial": ("CWE-502 Unsafe Deserialization",
                 "unserialize() on user-controlled input.",
                 ["maybe_unserialize(", "json_decode(", "class_exists("]),
}

SYSTEM = (
    "You are a precise application-security reviewer for WordPress/PHP code. "
    "You receive a short code slice flagged by a static taint scanner, plus heuristic "
    "annotations. Decide whether it is a REAL, reachable vulnerability or a false positive.\n\n"
    "CRITICAL RULES (Papers 22/23):\n"
    "1. Do NOT stop at superficial sanitizer checks. The EXISTENCE of esc_html(), intval(), "
    "wp_verify_nonce() etc. is NOT proof of safety. Verify they are: (a) applied to the "
    "CORRECT variable on the taint path, (b) applied BEFORE the sink (not after), "
    "(c) correct scope (not just in a branch that may not execute).\n"
    "2. Validate dataflow END-TO-END: source → [transforms?] → sink. "
    "Look for: bypasses, wrong order, partial coverage (covers some inputs but not all), "
    "trust boundary crossings.\n"
    "3. If claiming a sanitizer makes it safe, cite the SPECIFIC line number where it appears. "
    "If you cannot find it in the provided code slice, do NOT assume it exists elsewhere.\n"
    "4. Cite specific identifiers/lines in your reasoning."
)

_JSON_INSTRUCTION = (
    "\n\nRespond with ONLY one JSON object (no markdown fences, no prose) with "
    "exactly these keys: is_vulnerable (boolean), vuln_class (string), exploitable "
    "(boolean), sanitizer_present (boolean), confidence (number 0..1), reasoning "
    "(string), safe_function (string: the bare sanitizer/guard function name that "
    "makes it safe, or empty string), involved_lines (string: comma-separated "
    "line numbers from the slice forming the taint path, e.g. '3,7,12'; empty if "
    "not vulnerable)."
)


@dataclass
class Verdict:
    is_vulnerable: bool
    vuln_class: str
    exploitable: bool
    sanitizer_present: bool
    confidence: float
    reasoning: str
    safe_function: str = ""
    involved_lines: str = ""   # [Paper02 ISAL] line-level localization
    in_tokens: int = 0
    out_tokens: int = 0
    fail_open: bool = False        # [Paper15] True if LLM failed → kept as potential TP
    spec_ungrounded: bool = False  # [Paper14] True if claimed sanitizer not found in slice


def _build_user(finding, slice_text: str, gate: dict) -> str:
    rule = getattr(finding, "rule_id", None) or getattr(finding, "sink", "") or "taint"
    vc = getattr(finding, "vuln_class", "other") or "other"
    cwe_name, cwe_desc, expected_sanitizers = _CWE_CONTEXT.get(vc, (
        "Unknown vulnerability class", "user-controlled data reaches a dangerous sink.", []))
    sanitizer_hint = (
        f"Expected sanitizers for {vc}: {', '.join(expected_sanitizers)}"
        if expected_sanitizers else ""
    )
    # Post-condition: what a real exploit would achieve (Paper 20 AXE)
    _post_cond = {
        "sqli": "extracts or modifies data in the database without authorization",
        "xss": "injects JavaScript that executes in another user's browser",
        "rce": "executes OS commands as the web server user",
        "lfi": "reads arbitrary files from the server filesystem",
        "upload": "uploads and executes arbitrary PHP code",
        "auth": "accesses restricted functionality without proper authentication",
        "csrf": "performs unauthorized actions on behalf of an authenticated user",
        "ssrf": "makes the server issue requests to internal or external resources",
        "deserial": "executes arbitrary PHP objects/code via unserialize()",
    }
    post_cond = _post_cond.get(vc, "causes unauthorized security impact")
    # [Paper17 OpenAnt] Adversarial framing: realistic attacker privilege by WP entry
    # point (anchor query, Paper 13), plus the "victim requirement" — a real vuln must
    # harm SOMEONE ELSE, not just the attacker's own account/content.
    ep = getattr(finding, "entry_point", "unknown") or "unknown"
    ep_constraint = {
        "ajax_nopriv": "reachable WITHOUT authentication (wp_ajax_nopriv_) — assume an anonymous remote attacker",
        "ajax_auth": "requires a logged-in user (minimum: subscriber role)",
        "rest_api": "a REST route — reachable per its permission_callback; assume at most a low-privilege authenticated user unless the callback is __return_true",
        "shortcode": "reachable by anyone able to place/preview the shortcode (often contributor/author)",
        "admin": "an admin-context hook — assume an authenticated admin-area user",
    }.get(ep, "of unknown entry point — assume a low-privilege authenticated user")
    return (
        f"CWE: {cwe_name}\n"
        f"Description: {cwe_desc}\n"
        f"Scanner rule: {rule}\n"
        f"Reported class: {vc}\n"
        f"Message: {getattr(finding, 'message', '')}\n"
        f"Heuristic gate: request_source={gate.get('has_request_source')}, "
        f"sanitizer_seen={gate.get('has_sanitizer')}, reachability={gate.get('reachability')}\n"
        f"File: {finding.file}  (finding at line {getattr(finding, 'line', '?')})\n"
        f"Entry point: {ep} — {ep_constraint}.\n"
        + (f"{sanitizer_hint}\n" if sanitizer_hint else "")
        + "Victim requirement: a REAL vulnerability must let the attacker harm ANOTHER "
        "user or the site itself; an action that only affects the attacker's OWN "
        "account/content is NOT a vulnerability.\n"
        + f"Key question: Under the access constraint above, can an attacker {post_cond}?\n\n"
        f"Code slice:\n```php\n{slice_text}\n```"
    )


def _coerce(data: dict) -> dict:
    return {
        "is_vulnerable": bool(data.get("is_vulnerable", False)),
        "vuln_class": str(data.get("vuln_class", "none")),
        "exploitable": bool(data.get("exploitable", False)),
        "sanitizer_present": bool(data.get("sanitizer_present", False)),
        "confidence": float(data.get("confidence", 0.0) or 0.0),
        "reasoning": str(data.get("reasoning", "")),
        "safe_function": str(data.get("safe_function", "") or "").strip().lstrip("\\").split("(")[0],
        "involved_lines": str(data.get("involved_lines", "") or ""),
    }


_VERDICT_KEYS = ("is_vulnerable", "approve", "ok")

def _extract_json(text: str) -> dict:
    """Pull the model's JSON object out of CLI stdout (tolerates prose, fences, and
    the prompt being echoed back). Uses json.JSONDecoder.raw_decode, which is
    string-aware — so braces quoted INSIDE a JSON string (e.g. reasoning that
    cites PHP code like `} // function {`) no longer break parsing, unlike naive
    brace-depth counting. Scans every '{' and keeps the last valid object,
    preferring one that carries a known verdict key (the model's answer comes
    after any echoed prompt)."""
    if not text:
        return {}
    dec = json.JSONDecoder()
    best: dict = {}
    keyed: dict = {}
    idx = text.find("{")
    while idx != -1:
        try:
            obj, _ = dec.raw_decode(text, idx)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            best = obj
            if any(k in obj for k in _VERDICT_KEYS):
                keyed = obj
        idx = text.find("{", idx + 1)
    return keyed or best


class Verifier:
    def __init__(self, model: str | None = None, max_tokens: int = 1024,
                 use_cache: bool = True, provider: str | None = None):
        self.provider = (provider or os.environ.get("LLM_PROVIDER", "cli")).lower()
        self.max_tokens = max_tokens
        self.use_cache = use_cache
        self.total_in = 0
        self.total_out = 0
        self.calls = 0
        self.last_ok = True   # False if the last CLI call returned no parseable verdict

        if self.provider != "cli":
            raise ValueError(f"unknown LLM_PROVIDER: {self.provider} (use 'cli')")
        self.cli_bin = os.environ.get("CLI_VERIFY_BIN", "agy").strip().strip('"').strip("'")
        self.cli_model = os.environ.get("CLI_VERIFY_MODEL", "").strip().strip('"').strip("'")
        self.cli_timeout = int(os.environ.get("CLI_VERIFY_TIMEOUT", "150"))
        self.model = f"cli:{self.cli_bin}" + (f":{self.cli_model}" if self.cli_model else "")

    def cost_usd(self) -> float:
        return 0.0  # covered by the local CLI subscription

    def _model_for(self, finding):
        """Per-class CLI model override hook. The artifact uses the env default."""
        return None

    def verify(self, finding, slice_text: str, gate: dict) -> Verdict:
        user = _build_user(finding, slice_text, gate)
        model_override = self._model_for(finding)
        self.calls += 1
        data, itok, otok = self._verify_cli(user, model_override)
        self.total_in += itok
        self.total_out += otok

        # [Paper15 QASecClaw] Fail-open: if LLM failed/timed out, keep finding as TP
        if not data:
            return Verdict(
                is_vulnerable=True, vuln_class=getattr(finding, "vuln_class", "other"),
                exploitable=True, sanitizer_present=False, confidence=0.3,
                reasoning="LLM verify failed or timed out — keeping as potential TP (fail-open).",
                fail_open=True, in_tokens=itok, out_tokens=otok,
            )

        verdict = Verdict(**_coerce(data), in_tokens=itok, out_tokens=otok)

        # [Paper14 CODE-AUGUR] Spec-grounding + re-verify loop: if the LLM calls it a
        # FP because of a sanitizer that does NOT appear in the slice, the
        # justification is a hallucination. Re-ask ONCE with a counter-hint; a
        # reliable model typically flips these back to TP. This is the
        # recall-protecting half of spec-grounding (catches ~20-30% hallucinated FPs).
        if not verdict.is_vulnerable and verdict.safe_function \
                and verdict.safe_function not in slice_text:
            verdict.spec_ungrounded = True
            hint = (
                f"\n\nIMPORTANT RE-CHECK: your previous answer judged this a false "
                f"positive because of `{verdict.safe_function}`, but that function does "
                f"NOT appear anywhere in the code slice above. Do not assume sanitizers "
                f"that are not shown. Re-evaluate STRICTLY on the code given and answer "
                f"again."
            )
            data2, itok2, otok2 = self._verify_cli(user + hint, model_override)
            self.total_in += itok2
            self.total_out += otok2
            if data2:
                v2 = Verdict(**_coerce(data2),
                             in_tokens=itok + itok2, out_tokens=otok + otok2)
                # grounded again only if the new justification is actually in the slice
                v2.spec_ungrounded = bool(
                    not v2.is_vulnerable and v2.safe_function
                    and v2.safe_function not in slice_text)
                return v2

        return verdict

    # --- cli --------------------------------------------------------------- #
    def _verify_cli(self, user: str, model_override: str | None = None):
        prompt = SYSTEM + "\n\n" + user + _JSON_INSTRUCTION
        cli_model = model_override or self.cli_model
        if self.cli_bin == "codex":
            # codex exec: read-only sandbox (verify is pure reasoning, never runs
            # shell), --skip-git-repo-check so it works in any dir, and low
            # reasoning effort -> ~10s/verdict instead of >200s on defaults.
            # Emits clean JSON on stdout. Optional CLI_VERIFY_MODEL -> -m.
            cmd = [self.cli_bin, "exec", "--skip-git-repo-check",
                   "--sandbox", "read-only", "-c", "model_reasoning_effort=low"]
            if cli_model:
                cmd += ["-m", cli_model]
            cmd.append(prompt)
        else:  # generic local CLIs use -p for headless print
            cmd = [self.cli_bin, "-p", prompt]
            if cli_model:
                cmd[1:1] = ["--model", cli_model]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.cli_timeout)
            data = _extract_json(proc.stdout)
        except Exception:
            data = {}
        self.last_ok = bool(data)
        return data, 0, 0
