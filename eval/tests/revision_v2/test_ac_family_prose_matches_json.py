"""AC. Qualitative claims about the paired family must agree with the family JSON.

The macro guard compares numbers to their source. It cannot see a sentence, and the paper's central
claim is a sentence: that nothing separates at exact-changed-line granularity. Under
wisp-scanner-v1.2 that was true, all 8 survivors being coarse. Under v1.3 the family grew to 20 and
one of them is `exact@10` against Progpilot, Holm p = 0.0357, interval [0.058, 0.208]. The abstract
and the contributions list went on asserting the absolute form for a full day, while the threats
section had already been narrowed to "against Semgrep or wp-taint-scan", so the paper contradicted
itself and every check passed.

The lesson is the one from the bibliography earlier the same day: a claim that lives outside the
macro system has no guard unless one is written for it. This is that guard, and it runs in both
directions. If an exact-line comparison survives, the absolute phrasings are banned. If none
survives, a sentence conceding one is banned. Either way the prose has to track the JSON.
"""
from __future__ import annotations
import os, re, json
from ._common import SYS_ROOT, MissingInput

LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
MAIN = os.path.join(LATEX, "WISP-paper-CnS-elsarticle.tex")
SUPP = os.path.join(LATEX, "WISP-paper-CnS-supplement.tex")
FAMILY = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "PAIRED_FAMILY_V3.json")

# Two earlier versions of this list were wrong in opposite directions, and both failures are worth
# keeping in view. Matching bare phrases flagged two sentences that are correctly scoped, because the
# banned tail sits inside them. Generalising to "line rung + any negation" then flagged patch-shape
# sentences that deny something entirely different, such as a pure-insertion patch having no
# exact-line target at all.
#
# What is actually being guarded is narrow: a sentence that denies separation AT THE LINE RUNG. So
# the trigger is a denial phrase, and the verdict is whether the sentence containing it says which
# baselines the denial holds for. A new phrasing escapes this list, which is why the disclosure test
# below runs from the JSON side and needs no phrase list at all.
DENIAL = (
    "any baseline at line granularity",
    "none of them at exact-line granularity",
    "at line granularity no difference is detected",
    "nothing separates at line granularity",
    "no comparison at exact-line granularity survives",
    "no corrected evidence that WISP differs",
    "no corrected difference from any baseline",
)
# an explicit restriction to some baselines, which is what makes the claim checkable
SCOPED = re.compile(r"Semgrep|wp-taint-scan|Progpilot|independent baselines?", re.I)
# universal quantifiers, which put the claim back over every baseline no matter what else is named
UNIVERSAL = re.compile(r"\bany baseline|\bnone of them|\bevery baseline|\bno baseline", re.I)


def _survivors() -> list:
    if not os.path.isfile(FAMILY):
        raise MissingInput(FAMILY)
    d = json.load(open(FAMILY, encoding="utf-8"))
    comps = d["comparisons"]
    vals = comps.values() if isinstance(comps, dict) else comps
    return [v for v in vals if v.get("survives_holm")]


def _exact_survivors() -> list:
    return [v for v in _survivors() if str(v.get("endpoint", "")).startswith("exact")]


def _docs() -> list:
    out = []
    for p in (MAIN, SUPP):
        if os.path.isfile(p):
            out.append((os.path.basename(p), open(p, encoding="utf-8").read()))
    if not out:
        raise MissingInput(MAIN)
    return out


def _sentences(txt: str) -> list:
    flat = " ".join(txt.split())
    flat = re.sub(r"%.*?(?= )", " ", flat)
    return [s for s in re.split(r"(?<=\.)\s+", flat) if s.strip()]


def test_no_document_asserts_an_absolute_null_at_line_granularity_when_one_survives():
    ex = _exact_survivors()
    if not ex:
        return          # the absolute form is licensed; the opposite test below covers that case
    named = ", ".join(f"{v['endpoint']} vs {v['baseline']} (Holm p={v['p_holm_adjusted']:.4f})"
                      for v in ex)
    bad = []
    for name, txt in _docs():
        for s in _sentences(txt):
            if not any(d in s for d in DENIAL):
                continue
            if UNIVERSAL.search(s) or not SCOPED.search(s):
                bad.append(f"{name}: {s.strip()[:190]}")
    assert not bad, (
        "the family has surviving comparisons at exact-changed-line granularity, so a claim that "
        "none survives is false unless it says which baselines it holds for. Survivors: " + named
        + ". Offending sentence(s):\n    " + "\n    ".join(bad)
        + "\n  Scope the sentence to the baselines it actually holds for.")


def test_no_document_concedes_a_line_granularity_survivor_when_none_survives():
    """The other direction. A conceded exception that the data does not support understates the
    result just as wrongly as an absolute null overstates it."""
    if _exact_survivors():
        return
    conceded = ("one survivor at line granularity", "exact changed line at $K{=}10$ against")
    bad = [f"{n}: {p!r}" for n, t in _docs() for p in conceded if p in " ".join(t.split())]
    assert not bad, (
        "no exact-changed-line comparison survives Holm correction, but the text concedes one: "
        + "; ".join(bad))


def test_the_surviving_count_matches_the_family_json():
    from ._common import SYS_ROOT as _s
    macros = os.path.join(LATEX, "PAPER_MACROS_V3.tex")
    if not os.path.isfile(macros):
        raise MissingInput(macros)
    m = re.search(r"\\newcommand\{\\FamilySurvive\}\{([^}]*)\}", open(macros, encoding="utf-8").read())
    assert m, "PAPER_MACROS_V3.tex defines no \\FamilySurvive"
    assert int(m.group(1)) == len(_survivors()), (
        f"\\FamilySurvive = {m.group(1)} but the family JSON has {len(_survivors())} survivors")


def test_no_document_denies_a_survivor_that_the_family_actually_has():
    """The general form of the defect, not restricted to the line rung.

    The line-granularity check above was written first and was too narrow. A reviewer then found
    "No class-and-file comparison against either Semgrep or wp-taint-scan survives the family-wise
    correction at any cutoff" in the manuscript, while cf@5 and cf@10 against Semgrep both survive.
    Same shape, different endpoint, invisible to a check that only knew about exact lines.

    So this reads the family JSON and, for every (endpoint family, baseline) pair that has at least
    one survivor, refuses a sentence that denies all of them. The patterns are the two negation
    forms the papers actually use, joined to the endpoint name and the baseline name.
    """
    display = {"wpt": "wp-taint-scan", "progpilot": "Progpilot", "semgrep": "Semgrep"}
    families = {"cf@": "class-and-file", "pf@": "patch-file", "exact@": "exact",
                "class": "class emission"}
    have = {}
    for v in _survivors():
        for pref, label in families.items():
            if v["endpoint"].startswith(pref):
                have.setdefault(label, set()).add(display.get(v["baseline"], v["baseline"]))
    bad = []
    for name, txt in _docs():
        for s in _sentences(txt):
            low = s.lower()
            if not re.search(r"\bno\b|\bnone\b|\bnothing\b|\bneither\b", low):
                continue
            if "surviv" not in low:
                continue
            for label, baselines in have.items():
                if label.split()[0] not in low:
                    continue
                named = {b for b in baselines if b in s}
                # a sentence that denies survival while naming a baseline that does survive
                if named and not re.search(r"\bonly\b|\bexcept\b|\bother than\b", low):
                    bad.append(f"{name}: denies {label} survival while naming {sorted(named)}, "
                               f"which do survive -> {s.strip()[:150]}")
    assert not bad, ("a document denies a survival the family JSON records:\n    "
                     + "\n    ".join(bad))


def test_every_baseline_with_a_line_granularity_survivor_is_named_where_the_claim_is_made():
    """A survivor that the text never names is a survivor the reader cannot check."""
    ex = _exact_survivors()
    if not ex:
        return
    display = {"wpt": "wp-taint-scan", "progpilot": "Progpilot", "semgrep": "Semgrep"}
    main = " ".join(open(MAIN, encoding="utf-8").read().split())
    missing = []
    for v in ex:
        who = display.get(v["baseline"], v["baseline"])
        # the concession has to sit in a sentence that is about the exact-line rung
        near = [s for s in re.split(r"(?<=\.)\s", main)
                if who in s and re.search(r"exact[- ](changed[- ])?line|exact@", s)]
        if not near:
            missing.append(f"{v['endpoint']} vs {who}")
    assert not missing, (
        "these exact-changed-line survivors are never disclosed in a sentence about the exact-line "
        "rung, so the manuscript reports a null it does not have: " + ", ".join(missing))
