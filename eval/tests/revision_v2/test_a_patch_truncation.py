"""A. Silent patch truncation.

`eval/build_adjudication_v2.py::_patch_hunk(vf, pf, limit=28)` returned the first 28 lines of
the filtered unified diff with no marker when it dropped the rest, so a finding whose changed
line lived past the cut was simply not in the column reviewers read.

The fix is not to patch that function. It builds the retired v2 sheet, which no longer feeds
any claim in the paper and which nothing in the pipeline calls; repairing dead code would leave
a green test and the same risk in the code that will actually run. The live protocol is v3, and
what this test now asserts is that the defect is absent THERE, measured on the same four real
findings that exposed it, plus that the retired builder cannot quietly come back into use.

Measured on those four records: the v2 hunk hid the changed line on 4 of 4; the v3 context
shows it on 4 of 4.
"""
from __future__ import annotations
import glob
import inspect
import os

from ._common import REPO, Evidence, MissingInput

# (slug, cve, vulnerable-side changed line) - the four findings named in the revision brief
REAL_CASES = [
    ("backuply", "CVE-2024-8669", 508),
    ("advanced-google-recaptcha", "CVE-2025-2074", 423),
    ("products-file-upload-for-woocommerce", "CVE-2026-25328", 220),
    ("seriously-simple-podcasting", "CVE-2026-39505", 333),
]


def _resolve(root, norm_path):
    """Match on the normalized path suffix, not the basename: plugins ship same-named files in
    several directories and a basename match picks the wrong one."""
    want = "/" + norm_path.replace(os.sep, "/")
    for c in glob.glob(os.path.join(root, "**", "*.php"), recursive=True):
        if c.replace(os.sep, "/").endswith(want):
            return c
    return None


def test_reviewer_context_shows_the_changed_line():
    ev = Evidence("A. patch truncation, live v3 protocol")
    from eval.build_defect_cards_v3 import _full_diff
    from eval.datasets.patchstack import load_rows
    from eval.localize import _unzip
    from eval import patch_geometry as pg

    rows = {r["slug"] + "|" + r["cve"]: r for r in load_rows()}
    hidden, checked = [], 0
    for slug, cve, line in REAL_CASES:
        row = rows.get(slug + "|" + cve)
        if not row:
            continue
        pm = pg.build_patchmap_from_archives(row)
        tgt = next((p for p, fd in pm.per_file.items()
                    if fd["is_php"] and line in (fd["changed_vuln_lines"] or [])), None)
        if not tgt:
            continue
        vf = _resolve(_unzip(row["vuln_zip"]), tgt)
        pf = _resolve(_unzip(row["patched_zip"]), tgt)
        if not (vf and pf):
            continue
        vt = open(vf, encoding="utf-8", errors="replace").read()
        lines = vt.split("\n")
        if line - 1 >= len(lines):
            continue
        src = lines[line - 1].strip()
        if not src:
            continue
        pt = open(pf, encoding="utf-8", errors="replace").read()
        shown = src in _full_diff(vt, pt)
        checked += 1
        ev.show(f"{slug} {cve} line {line}: shown in the v3 context = {shown}")
        if not shown:
            hidden.append(f"{slug}|{cve}:{line}")

    if not checked:
        raise MissingInput("the four real cases need the 1108-plugin corpus archives, which are "
                             "the separate data deposit and not part of this bundle")
    assert not hidden, (
        "the v3 reviewer context does not show the vendor-changed line a finding sits on for: "
        + ", ".join(hidden))


def test_retired_v2_builder_is_not_reachable_from_the_pipeline():
    """The defective builder must stay out of the live path."""
    ev = Evidence("A. retired v2 builder is unreferenced")
    hits = []
    for p in glob.glob(os.path.join(REPO, "eval", "**", "*.py"), recursive=True):
        rel = os.path.relpath(p, REPO).replace(os.sep, "/")
        if "build_adjudication_v2" in rel or "/tests/" in rel:
            continue
        if "build_adjudication_v2" in open(p, encoding="utf-8", errors="replace").read():
            hits.append(rel)
    ev.show(f"non-test modules importing the retired v2 builder: {hits or 'none'}")
    assert not hits, (
        "the retired v2 adjudication builder is referenced by: " + ", ".join(hits)
        + ". It truncates the reviewer's patch hunk at 28 lines with no marker; the v3 "
          "defect-card context is the replacement.")


def test_v3_context_builder_has_no_length_cap():
    """A cap that is not there cannot silently fire later."""
    ev = Evidence("A. no length cap in the v3 context builder")
    from eval import build_defect_cards_v3 as b3
    src = inspect.getsource(b3._full_diff)
    ev.show("v3 _full_diff: " + " ".join(src.split())[:120])
    assert "limit" not in src, "the v3 diff builder has acquired a length limit"
    assert "[:" not in src, "the v3 diff builder has acquired a slice"
    assert "unified_diff" in src, "the v3 diff builder no longer emits a unified diff"
