"""AB. The software citation must resolve to the engine the paper says it scored under.

The availability paragraph is macro-driven and says the scans are scored on the engine released as
\\EngineRelease with \\code{taint\\_engine.py} sha256 \\EngineSha. The bibliography is not
macro-driven. When the engine moved from wisp-scanner-v1.2 to v1.3, @misc{wispsoftware} kept naming
v1.2 and 012279d6, so the paper contradicted itself one line apart and every check passed, because
nothing read the bibliography.

It then went wrong a second way, and the second way is why the mutations below changed. The guard
was written to demand \\EngineTag, the development build label the run manifests stamp. That label
is not a thing a reader can fetch: the repository publishes exactly one tag, the release. So the
guard was enforcing a citation that pointed at a tag which does not exist on the remote. The rule is
now that the bib names the release, the sha256 carries the identity, and the build label is the
value the bib must NOT name. These tests mutate the release tag into the build label, which is the
defect that actually shipped.

Correcting references.bib was not enough either. The build ran pdflatex twice and never ran bibtex,
so the PDF kept printing v1.2 out of a .bbl that no step regenerated. A corrected source that never
reaches the reader is the worse failure of the two, because the repository now says the paper is
right.

So there are three surfaces here and all three are checked: the .bib the author edits, the .bbl the
build compiles, and the build script that has to run bibtex for the second to follow the first.

The guard lives in eval/check_paper_macros_v3.py. These tests prove it bites, by mutating each
surface and restoring it byte-identically, rather than trusting that it is present.
"""
from __future__ import annotations
import os, re, io, sys, hashlib, contextlib
from ._common import SYS_ROOT, MissingInput

LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
BIB = os.path.join(LATEX, "references.bib")
BBL = os.path.join(LATEX, "WISP-paper-CnS-elsarticle.bbl")
BUILD = os.path.join(LATEX, "build_paper_v3.sh")


def _guard(check_bbl=True) -> tuple:
    """Run the guard in-process and return (exit code, captured output)."""
    from eval import check_paper_macros_v3 as chk
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        rc = chk.main(check_bbl=check_bbl)
    return rc, buf.getvalue()


def _sha(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


@contextlib.contextmanager
def _mutated(path: str, old: str, new: str):
    """Swap a string, run the body, restore the original bytes and assert they are the originals."""
    if not os.path.isfile(path):
        raise MissingInput(path)
    original = open(path, "rb").read()
    before = hashlib.sha256(original).hexdigest()
    text = original.decode("utf-8")
    if old not in text:
        raise AssertionError(f"{os.path.basename(path)} does not contain {old!r}, so this test "
                             f"cannot mutate what it means to mutate")
    open(path, "w", encoding="utf-8").write(text.replace(old, new))
    try:
        yield
    finally:
        open(path, "wb").write(original)
        assert _sha(path) == before, f"{path} was not restored byte-identically"


def test_the_guard_passes_on_the_tree_as_it_stands():
    """Half of a guard's evidence is that it is quiet when nothing is wrong."""
    rc, out = _guard()
    assert rc == 0, f"the guard fails on an unmutated tree, so any firing below proves nothing:\n{out}"


def test_a_stale_tag_in_the_bib_fails_the_guard():
    with _mutated(BIB, "wisp-scanner-v1.0", "wisp-scanner-v1.3"):
        rc, out = _guard()
    assert rc != 0, ("references.bib naming the development build label instead of the published\n                     release tag did not fail the guard, which is the state it shipped in")
    assert "references.bib" in out and "wispsoftware" in out, (
        f"the guard failed but did not name the bibliography as the reason:\n{out}")


def test_a_stale_sha_in_the_bib_fails_the_guard():
    with _mutated(BIB, "d07a4bbc", "012279d6"):
        rc, out = _guard()
    assert rc != 0, "references.bib naming the baseline engine sha256 did not fail the guard"


def test_a_stale_compiled_bibliography_fails_the_guard():
    """The defect that actually shipped for one build: .bib right, .bbl stale, PDF wrong."""
    with _mutated(BBL, "wisp-scanner-v1.0", "wisp-scanner-v1.3"):
        rc, out = _guard()
    assert rc != 0, (
        "a .bbl naming a different engine from the one the paper claims did not fail the guard, "
        "which is the exact state the 22:32 build shipped in")
    assert ".bbl" in out, f"the guard failed without naming the compiled bibliography:\n{out}"


def test_the_pre_latex_gate_skips_the_bbl_so_the_build_cannot_deadlock():
    """The .bbl is an output of the build. If the pre-LaTeX gate demanded it be current, a stale
    .bbl could never be regenerated: the guard would abort before bibtex ever ran."""
    with _mutated(BBL, "wisp-scanner-v1.0", "wisp-scanner-v1.3"):
        rc, _ = _guard(check_bbl=False)
    assert rc == 0, ("the pre-LaTeX gate rejects a stale .bbl, so a build that would have fixed it "
                     "can never reach bibtex")


def test_the_build_runs_bibtex_and_checks_the_bibliography_after_latex():
    if not os.path.isfile(BUILD):
        raise MissingInput(BUILD)
    src = open(BUILD, encoding="utf-8").read()
    assert re.search(r"^\s*bibtex ", src, re.M), (
        "build_paper_v3.sh never runs bibtex, so an edit to references.bib cannot reach the PDF. "
        "That is how the software citation printed wisp-scanner-v1.2 in a v1.3 paper.")
    assert "--no-bbl" in src, (
        "the pre-LaTeX guard call does not pass --no-bbl, so a stale .bbl deadlocks the build")
    pre = src.index("--no-bbl")
    post = src.rindex("check_paper_macros_v3")
    assert post > pre, (
        "build_paper_v3.sh does not run the full guard after LaTeX, so the compiled bibliography "
        "is never checked against the engine macros")
