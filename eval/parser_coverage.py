#!/usr/bin/env python3
"""Parser-coverage statistics over the full corpus (reviewer req: report parser
coverage and unsupported-feature statistics rather than only claiming
error-tolerance).

For every unique VULNERABLE zip in the gold set, parse each .php member with the
same tree-sitter-php configuration the engine uses (L1 skip rule mirrored: a file
without an opening `<?` tag is skipped) and count:

  total_php_files      .php members across all vulnerable trees
  skipped_no_open_tag  files the engine skips (no `<?`)
  parsed_files         files handed to tree-sitter
  files_with_error     parsed files whose AST contains >=1 ERROR/MISSING node
  error_bytes_share    bytes under ERROR nodes / total parsed bytes (per corpus)

Usage:
  python -m eval.parser_coverage --csv <metadata.csv> --base <corpus root> \
      [--out parser_coverage.json] [--workers 8]

The CSV is the released WISP-1108 metadata file (column "Vulnerable File" holds
the zip path relative to the corpus root; a historical `plugins/` prefix is
normalized to `plugins_01/`).
"""
import argparse
import csv
import json
import os
import zipfile
from multiprocessing import Pool

import tree_sitter_php as tsphp
from tree_sitter import Language, Parser

_PARSER = None


def _get_parser():
    global _PARSER
    if _PARSER is None:
        _PARSER = Parser(Language(tsphp.language_php()))
    return _PARSER


def _error_bytes(node):
    """Total bytes covered by ERROR/MISSING subtrees (no double counting)."""
    if node.is_error or node.is_missing:
        return node.end_byte - node.start_byte
    if not node.has_error:
        return 0
    return sum(_error_bytes(c) for c in node.children)


def scan_zip(zpath):
    st = {"zips": 1, "zip_errors": 0, "total_php_files": 0,
          "skipped_no_open_tag": 0, "parsed_files": 0, "files_with_error": 0,
          "parsed_bytes": 0, "error_bytes": 0}
    parser = _get_parser()
    try:
        with zipfile.ZipFile(zpath) as z:
            for info in z.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".php"):
                    continue
                st["total_php_files"] += 1
                try:
                    data = z.read(info)
                except Exception:
                    st["skipped_no_open_tag"] += 1
                    continue
                if b"<?" not in data:
                    st["skipped_no_open_tag"] += 1
                    continue
                st["parsed_files"] += 1
                st["parsed_bytes"] += len(data)
                tree = parser.parse(data)
                if tree.root_node.has_error:
                    st["files_with_error"] += 1
                    st["error_bytes"] += _error_bytes(tree.root_node)
    except Exception:
        st["zip_errors"] += 1
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", default="parser_coverage.json")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    zips = set()
    with open(args.csv, encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            vf = row["Vulnerable File"].strip()
            if vf.startswith("plugins/"):
                vf = vf.replace("plugins/", "plugins_01/", 1)
            p = os.path.join(args.base, vf)
            if os.path.exists(p):
                zips.add(p)
    zips = sorted(zips)
    print(f"unique vulnerable zips: {len(zips)}")

    tot = None
    with Pool(args.workers) as pool:
        for st in pool.imap_unordered(scan_zip, zips, chunksize=8):
            if tot is None:
                tot = st
            else:
                for k, v in st.items():
                    tot[k] += v

    tot["pct_skipped"] = round(100.0 * tot["skipped_no_open_tag"] / tot["total_php_files"], 3)
    tot["pct_files_with_error"] = round(100.0 * tot["files_with_error"] / tot["parsed_files"], 3)
    tot["pct_error_bytes"] = round(100.0 * tot["error_bytes"] / tot["parsed_bytes"], 4)
    with open(args.out, "w") as fh:
        json.dump(tot, fh, indent=1)
    print(json.dumps(tot, indent=1))


if __name__ == "__main__":
    main()
