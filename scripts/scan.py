#!/usr/bin/env python3
"""Scan one WordPress plugin (a .zip or an unpacked directory) with the WISP
taint engine and print the exploitability-ranked findings.

    python scripts/scan.py path/to/plugin.zip
    python scripts/scan.py path/to/plugin_dir/ --json out.json
    python scripts/scan.py examples/vuln_handler.php     # a single PHP file works too

The engine is CPU-only and needs no network or API key. The optional LLM
verification stage (wisp/engine/l4_verify.py) is not invoked here.
"""
from __future__ import annotations
import os
import sys
import json
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wisp.engine import l1_ingest, taint_engine as te


def _load(path):
    """Accept a zip, a directory, or a single .php file."""
    if os.path.isfile(path) and path.endswith(".php"):
        # wrap a lone file in a throwaway Plugin so the engine can scan it
        root = os.path.dirname(os.path.abspath(path)) or "."
        return l1_ingest.Plugin(slug=os.path.basename(path), version="", name="",
                                root=root, php_files=[os.path.abspath(path)])
    return l1_ingest.load_plugin(path)


def main():
    ap = argparse.ArgumentParser(description="WISP WordPress taint scan")
    ap.add_argument("target", help="plugin .zip, plugin directory, or a .php file")
    ap.add_argument("--json", default="", help="also write the full findings to this file")
    ap.add_argument("--top", type=int, default=0, help="print only the top-K ranked findings")
    args = ap.parse_args()

    plugin = _load(args.target)
    if not plugin or not plugin.php_files:
        sys.exit(f"[wisp] no PHP files found in {args.target}")

    findings = te.detect(plugin)
    shown = findings[: args.top] if args.top else findings

    for i, f in enumerate(shown, 1):
        rel = os.path.relpath(f.abs_file, plugin.root)
        flags = []
        if f.interprocedural:
            flags.append("inter-proc")
        if f.entry_point != "unknown":
            flags.append(f.entry_point)
        tag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"{i:3}. {f.vuln_class.upper():9} {rel}:{f.line}  "
              f"(conf {f.confidence:.2f}){tag}")
        print(f"      {f.source}  ->  {f.sink}")

    by_class = {}
    for f in findings:
        by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
    print(f"\n[wisp] {len(findings)} findings in {len(plugin.php_files)} PHP files; "
          f"classes: {dict(sorted(by_class.items()))}")

    if args.json:
        rows = [{"file": os.path.relpath(f.abs_file, plugin.root), "line": f.line,
                 "class": f.vuln_class, "source": f.source, "sink": f.sink,
                 "interprocedural": f.interprocedural, "confidence": f.confidence,
                 "entry_point": f.entry_point, "entry_point_name": f.entry_point_name,
                 "trace": f.trace} for f in findings]
        json.dump(rows, open(args.json, "w"), indent=2)
        print(f"[wisp] wrote {args.json}")

    plugin.cleanup()


if __name__ == "__main__":
    main()
