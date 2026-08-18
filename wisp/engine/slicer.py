"""Lightweight PHP slicer.

The full WISP design slices a Unified Code Property Graph. For the MVP we
approximate a slice with the enclosing PHP function/method plus a little context.
This keeps the prompt small and focused (the cost lever) without a full CPG.
"""
from __future__ import annotations
import re

FUNC_RE = re.compile(r"\bfunction\s+&?\s*\w+\s*\(", re.IGNORECASE)


def _enclosing_function(lines: list[str], target_idx: int) -> tuple[int, int] | None:
    """Return (start, end) line indices of the function enclosing target_idx,
    using brace balancing. 0-based, end exclusive."""
    start = None
    for i in range(target_idx, -1, -1):
        if FUNC_RE.search(lines[i]):
            start = i
            break
    if start is None:
        return None
    # Walk forward from the function signature, balancing braces.
    depth = 0
    seen_open = False
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            seen_open = True
        if seen_open and depth <= 0:
            return start, j + 1
    return start, len(lines)


def extract_slice(file_path: str, line: int, context_lines: int = 6,
                  max_chars: int = 6000, max_lines: int = 80) -> dict:
    """Extract a code slice around (1-based) `line` in file_path.

    Prefers the enclosing function; falls back to a context window. Returns a dict
    with the slice text and the [start,end] line span actually used.

    max_lines (Paper09): functions > max_lines cause LLM reasoning failures (avg +95 lines
    for all-method-fail cases). When the enclosing function exceeds max_lines, fall back to
    a focused window centered on the sink rather than including the entire large function.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return {"text": "", "start": line, "end": line}

    idx = max(0, min(line - 1, len(lines) - 1))
    span = _enclosing_function(lines, idx)
    if span is None:
        s = max(0, idx - context_lines)
        e = min(len(lines), idx + context_lines + 1)
    else:
        s, e = span
        # [Paper09] Long-function fallback: if function > max_lines, use a focused
        # window around the sink (40 lines before + 40 after) instead of the whole
        # function — avoids LLM long-context reasoning failure on 200+ line methods.
        if (e - s) > max_lines:
            half = max_lines // 2
            s = max(span[0], idx - half)
            e = min(span[1], idx + half + 1)

    text = "\n".join(lines[s:e])
    if len(text) > max_chars:
        s2 = max(0, idx - context_lines)
        e2 = min(len(lines), idx + context_lines + 1)
        text = "\n".join(lines[s2:e2])[:max_chars]
        s, e = s2, e2
    return {"text": text, "start": s + 1, "end": e}
