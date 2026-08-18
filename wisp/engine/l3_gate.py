"""L4 Reachability Gate (MVP heuristic).

The full design runs context-sensitive taint with path-feasibility. For the MVP
we apply a cheap, WordPress-aware heuristic over the slice:

  * If a recognized sanitizer/escaper/guard sits in the slice on the data path,
    the finding is likely already neutralized -> mark `sanitized=True` (lowers
    priority, still passed to AI for the final word).
  * We record whether the slice shows a request source ($_GET/$_POST/$_REQUEST/
    $_COOKIE/php://input) so the AI prompt can reason about reachability.

This gate never silently drops a finding in the MVP; it annotates. Dropping is
left to the AI-verify confidence threshold so we can measure the gate's effect
separately from the model's.
"""
from __future__ import annotations
import re

REQUEST_SOURCES = [
    r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE", r"\$_FILES",
    r"\$_SERVER", r"php://input", r"file_get_contents\s*\(\s*['\"]php://input",
]
_SRC_RE = re.compile("|".join(REQUEST_SOURCES))


def _flatten_sanitizers(cfg_list) -> list[str]:
    out = []
    for item in cfg_list or []:
        for tok in str(item).split(","):
            tok = tok.strip()
            if tok:
                out.append(re.escape(tok))
    return out


def annotate(finding, slice_text: str, sanitizer_cfg) -> dict:
    sans = _flatten_sanitizers(sanitizer_cfg)
    san_re = re.compile("|".join(sans), re.IGNORECASE) if sans else None

    has_source = bool(_SRC_RE.search(slice_text))
    has_sanitizer = bool(san_re.search(slice_text)) if san_re else False

    # Heuristic reachability score: tainted source present and no sanitizer seen.
    if has_source and not has_sanitizer:
        reach = "likely"
    elif has_source and has_sanitizer:
        reach = "guarded"
    else:
        reach = "unclear"     # source not visible in this slice

    return {
        "has_request_source": has_source,
        "has_sanitizer": has_sanitizer,
        "reachability": reach,
    }
