"""AD. The packaging sweep must ship what the documents print, and nothing else.

Two lists describe the same set and are written by different hands. The gate at 15e2b in
update-final-v2.sh derives its expectation from the macro manifest, restricted to macros the two
documents actually print. The copy step beside it was hand-typed, so the two drifted every time an
analysis was added, and on 2026-08-13 the build refused to package because five sources behind 24
printed macros were missing.

The first fix swept the whole manifest, which was too wide in the other direction. It shipped
AI_ADJUDICATION_V3.json, a summary of two AI annotators' agreement, into a bundle whose stated
integrity rule is that the model-assisted adjudication was removed. Neither document prints any of
its 37 macros, so it was never needed. The validator passed the bundle, because its leak list names
raw annotator sheets by filename and this is a derived summary.

So the sweep is scoped to printed macros, matching the gate, and the filename is on the leak list as
a second line of defence. These tests hold both ends: the script must scope its sweep, and the
validator must refuse the file if it ever reappears by another route.
"""
from __future__ import annotations
import os, re, json
from ._common import SYS_ROOT, MissingInput

BUILD = os.path.join(SYS_ROOT, "2026-07-07", "latex", "update-final-v2.sh")
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
BUNDLE = os.path.join(SYS_ROOT, "submission-cns-revision-v2")
AI_FILE = "AI_ADJUDICATION_V3.json"


def test_the_validator_refuses_the_ai_adjudication_summary():
    from eval import validate_submission_v2 as v
    src = open(v.__file__, encoding="utf-8").read()
    m = re.search(r"leak\s*=\s*\[(.*?)\]", src, re.S)
    assert m, "validate_submission_v2 no longer defines a leak list"
    assert AI_FILE in m.group(1), (
        f"{AI_FILE} is not on the validator's leak list, so a bundle carrying the AI annotators' "
        f"own agreement statistics passes while the paper says that adjudication was removed")


def test_the_packaging_sweep_is_scoped_to_macros_the_documents_print():
    if not os.path.isfile(BUILD):
        raise MissingInput(BUILD)
    src = open(BUILD, encoding="utf-8").read()
    m = re.search(r"MACCOPY'\n(.*?)\nMACCOPY", src, re.S)
    assert m, "update-final-v2.sh no longer contains the MACCOPY sweep"
    body = m.group(1)
    assert "elsarticle.tex" in body and "supplement.tex" in body, (
        "the packaging sweep does not read the documents, so it cannot tell a printed macro from an "
        "unprinted one and will ship every source in the manifest")
    assert re.search(r"re\.search\(.*?\\\\.*?name", body) or "re.escape(name)" in body, (
        "the packaging sweep does not test whether each macro appears in the documents")


def test_no_ai_adjudication_artifact_sits_in_the_built_bundle():
    if not os.path.isdir(BUNDLE):
        raise MissingInput(BUNDLE)
    hits = [os.path.relpath(os.path.join(r, f), BUNDLE)
            for r, _d, fs in os.walk(BUNDLE) for f in fs if f == AI_FILE]
    assert not hits, f"the built bundle carries {hits}, which no document reads"


def test_the_two_bundle_readmes_agree_on_the_reproduction_counts():
    """Three files quoted three different answers to one countable question.

    The root README said four targets skip, `reproduce/README.md` said two and named the wrong ones,
    and the run skips three. The four came from a hand-typed `gated` set in reproduce_all_v3.py that
    still named `fullcorpus_policy` after it stopped needing the corpus. The build now takes both
    numbers from a real in-bundle run, and this holds the two files to the same answer.

    The first version of that build step then wrote 26 where the run has 27, because its regex
    required the output column to match [A-Za-z0-9_.]+ and one output is `SANI_ABLATION_V3.json:paired`.
    A counter that silently drops a row it cannot parse is worse than no counter, so the totals are
    checked here against each other rather than assumed."""
    root = os.path.join(BUNDLE, "README.md")
    sub = os.path.join(BUNDLE, "reproduce", "README.md")
    for p in (root, sub):
        if not os.path.isfile(p):
            raise MissingInput(p)
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8}

    def _counts(path, pat):
        m = re.search(pat, open(path, encoding="utf-8").read(), re.I)
        if not m:
            return None
        skip = m.group(1).lower()
        return (words.get(skip, None) if not skip.isdigit() else int(skip)), int(m.group(2))

    a = _counts(root, r"([A-Za-z0-9]+) of its (\d+) targets report `SKIP`")
    b = _counts(sub, r"([A-Za-z0-9]+) of the (\d+) targets are reported as SKIP")
    # Both sentences are written by step 15e4 of the packaging script, from a real in-bundle run.
    # Before that step has ever completed, reproduce/README.md still carries the un-substituted
    # heredoc text and cannot be parsed. Asserting then would deadlock the build that produces the
    # very file under test, which is the same trap the .bbl guard had to be rescued from: a check on
    # a build output must not block the build. Treat it as a missing input instead.
    if not (a and b):
        raise MissingInput(
            "the bundle READMEs are not in their packaged form yet (root=%s reproduce=%s); "
            "run update-final-v2.sh to completion first" % (a, b))
    assert a == b, (f"the two bundle READMEs disagree on the reproduction counts: "
                    f"README.md says {a[0]} of {a[1]}, reproduce/README.md says {b[0]} of {b[1]}")


def test_every_source_behind_a_printed_macro_is_in_the_bundle():
    """The other direction, which is the failure that stopped the 22:49 build. Kept here so the
    scoping fix above cannot be over-applied into shipping too little."""
    if not os.path.isdir(BUNDLE):
        raise MissingInput(BUNDLE)
    manp = os.path.join(LATEX, "PAPER_MACROS_V3.manifest.json")
    if not os.path.isfile(manp):
        raise MissingInput(manp)
    man = json.load(open(manp, encoding="utf-8"))["macros"]
    tex = ""
    for f in os.listdir(LATEX):
        if f.endswith("-CnS-elsarticle.tex") or f.endswith("-CnS-supplement.tex"):
            tex += open(os.path.join(LATEX, f), encoding="utf-8").read()
    # The bundle is a build output. When the paper has gained a macro since the last successful
    # package, this check would fail on a source the build is about to ship, and the build cannot
    # reach the packaging step because this check runs before it. That is the same deadlock the
    # .bbl guard and the README count check both had to be rescued from, so apply the same rule: a
    # check on a build output must not block the build that produces it. The bundle's own macro file
    # is the tell, since it is copied at package time.
    bundle_macros = os.path.join(BUNDLE, "artifact", "2026-07-07", "latex", "PAPER_MACROS_V3.tex")
    if os.path.isfile(bundle_macros) and os.path.isfile(os.path.join(LATEX, "PAPER_MACROS_V3.tex")):
        if (open(bundle_macros, "rb").read()
                != open(os.path.join(LATEX, "PAPER_MACROS_V3.tex"), "rb").read()):
            raise MissingInput(
                "the bundle was packaged from an older macro set than the paper now uses, so its "
                "file list cannot be checked against today's macros; run update-final-v2.sh to "
                "completion first")
    present = set()
    for _r, _d, fs in os.walk(BUNDLE):
        present.update(fs)
    missing = {}
    for name, meta in man.items():
        base = os.path.basename(meta.get("json") or "")
        if not base.endswith(".json") or base in present:
            continue
        if re.search(r"\\" + re.escape(name) + r"(?![A-Za-z])", tex):
            missing.setdefault(base, []).append(name)
    assert not missing, (
        "these sources are named by macros the documents print but are not in the bundle, so a "
        "reviewer reading a number and looking up its file finds nothing: "
        + ", ".join(f"{b} ({len(v)} macros)" for b, v in sorted(missing.items())))
