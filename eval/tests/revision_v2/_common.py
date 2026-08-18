"""Shared helpers for the revision-v2 regression tests.

These tests REPRODUCE bugs that exist in the current code and data. Every
`test_*` function asserts the DESIRED (post-fix) invariant, so it FAILS while the
bug is present. Do not weaken an assertion to make it green; the fix goes in the
production code, not here.
"""
from __future__ import annotations
import os, sys, csv, re, difflib

# repo root = .../wisp-artifact  (this file is .../wisp-artifact/eval/tests/revision_v2/_common.py)
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SYS_ROOT = os.path.dirname(REPO)                       # .../System-ScanInfosec
if REPO not in sys.path:
    sys.path.insert(0, REPO)

# Canonical adjudication sheets + baseline JSON ship in the reproduction bundle.
DATA = os.environ.get("WISP_REVISION_DATA") or os.path.join(
    SYS_ROOT, "final", "supplementary-data", "reproduce", "data")
UPDATE_FINAL = os.path.join(SYS_ROOT, "final", "update-final.sh")


class MissingInput(Exception):
    """This test's input is not on this machine, which is not the same as this test failing.

    Some tests read the 1108-plugin corpus or a legacy sheet that the submission bundle does not
    carry, because those live in the separate data deposit. Run from the repository they pass; run
    from the bundle they cannot run at all. Reporting that as a failure tells a reviewer the
    artifact's own tests are broken, which is both false and the worst possible thing to be wrong
    about, so the runner reports it as a skip and names the input it wanted."""


def data(name: str) -> str:
    return os.path.join(DATA, name)


def read_csv(name: str) -> list[dict]:
    with open(data(name), encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def verdict(row: dict, col: str) -> str:
    return (row.get(col) or "").strip().upper()


def diff_filtered(vtext: str, ptext: str, n: int = 2) -> list[str]:
    """The exact filtered unified diff `_patch_hunk` builds (before its [:limit])."""
    v, p = vtext.split("\n"), ptext.split("\n")
    return [l for l in difflib.unified_diff(v, p, lineterm="", n=n)
            if not l.startswith(("---", "+++"))]


def vuln_coverage(out: list[str]) -> dict[int, int]:
    """Map each diff-line index -> the vulnerable-side source line it represents
    (context ' ' and deletion '-' lines advance the vulnerable counter; '+' does
    not). Lets us ask which source lines a truncated hunk still shows."""
    idx2v: dict[int, int] = {}
    vcur = None
    for i, l in enumerate(out):
        if l.startswith("@@"):
            m = re.search(r"-(\d+)", l)
            vcur = int(m.group(1)) if m else None
        elif l.startswith("-") or l.startswith(" "):
            if vcur is not None:
                idx2v[i] = vcur
                vcur += 1
    return idx2v


class Evidence:
    """Collects and prints the buggy reality a test surfaces, so the failure log
    is self-explanatory."""
    def __init__(self, name: str):
        self.name = name
        print(f"\n----- {name} : evidence -----")

    def show(self, msg: str):
        print(f"  {msg}")
        return self
