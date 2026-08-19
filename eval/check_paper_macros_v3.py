#!/usr/bin/env python3
"""Build guard for the v3 manuscript numbers (Prompt 7/10). Exit nonzero = fail the build.

Fails when:
  * a macro the paper uses is missing from the generated macro files,
  * a macro's value does not match a fresh derivation from the result JSONs, or
  * the abstract contains a primary number (a decimal rate, an N-fold ratio, or a kappa) written as a
    literal instead of a macro, i.e. a number with no traceable source.

It re-derives every macro by re-running build_paper_macros_v3.build() against the JSONs, so the check
is independent of the manifest file and catches a stale macro file.

    python3 -m eval.check_paper_macros_v3            # exit 0 pass, 2 fail
"""
from __future__ import annotations
import os, sys, re, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
_m = glob.glob(os.path.join(LATEX, "*-CnS-elsarticle.tex"))
MAIN = _m[0] if _m else os.path.join(LATEX, "WISP-paper-CnS-elsarticle.tex")
_s = glob.glob(os.path.join(LATEX, "*-CnS-supplement.tex"))
SUPP = _s[0] if _s else os.path.join(LATEX, "WISP-paper-CnS-supplement.tex")

from eval import build_paper_macros_v3 as gen


def _parse_newcommands(path):
    defs = {}
    if not os.path.isfile(path):
        return defs
    # The body must balance braces: a p-value macro holds 1.9\times 10^{-8}, and a regex that
    # stopped at the first '}' reported every one of them as a mismatch against its own JSON.
    head = re.compile(r"\\newcommand\{\\([A-Za-z]+)\}\{")
    for line in open(path, encoding="utf-8"):
        m = head.search(line)
        if not m:
            continue
        i, depth = m.end(), 1
        while i < len(line) and depth:
            if line[i] == "{":
                depth += 1
            elif line[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            defs[m.group(1)] = line[m.end():i - 1]
    return defs


def check_preprints_are_not_load_bearing(main_text, fails):
    """The paper claims preprints are cited only in Related Work and the Introduction.

    That is a new claim as of 2026-08-18 and it is exactly the kind that goes false quietly: one
    citation added to a Results paragraph next year makes the sentence a lie and nothing would
    notice. 17 of the 30 references are 2026 preprints, a reviewer flagged the share as high for
    this venue, and the answer we gave is that none of them carries a measurement. So the claim is
    checked rather than asserted.
    """
    bib = os.path.join(LATEX, "references.bib")
    if not os.path.isfile(bib):
        return
    body = open(bib, encoding="utf-8").read()
    pre = set()
    for m in re.finditer(r"@\w+\{([^,]+),(.*?)\n\}", body, re.S):
        if re.search(r"arxiv|eprint|preprint", m.group(2), re.I):
            pre.add(m.group(1).strip())
    if not pre:
        return
    allowed = ("Introduction", "Related Work")
    secs = [(mm.start(), mm.group(1)) for mm in re.finditer(r"\\section\*?\{([^}]*)\}", main_text)]

    def sec_of(pos):
        cur = "(front matter)"
        for p_, n in secs:
            if p_ < pos:
                cur = n
            else:
                break
        return cur

    bad = []
    for m in re.finditer(r"\\cite[a-z]*\{([^}]*)\}", main_text):
        for k in (x.strip() for x in m.group(1).split(",")):
            if k in pre:
                sec = sec_of(m.start())
                if not any(a in sec for a in allowed):
                    bad.append(f"{k} cited in {sec!r}")
    if bad:
        fails.append("the manuscript says no measurement rests on a preprint, but "
                     f"{len(bad)} preprint citation(s) sit outside the Introduction and Related "
                     f"Work: {'; '.join(sorted(set(bad))[:4])}")


def _abstract(text):
    m = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", text, re.S)
    return m.group(1) if m else ""


# Literals that are allowed to stay literal in the body, each with the reason it is not a
# measurement. Anything not listed here has to come from a macro, so a result number can never
# again be typed into prose and drift away from the table beside it.
LITERAL_OK = {
    "0.05": "the significance level alpha, a chosen constant",
    "0.28": "parse-error file share, a corpus property stated as a percentage",
    "0.34": "no-PHP-tag file share, a corpus property stated as a percentage",
    "0.08": "parse-error byte share, a corpus property stated as a percentage",
    "0.001": "a rounding floor in prose (\"by less than 0.001\"), not a measured value",
}
# A blanket exemption is only safe when the value cannot also be a result. 0.05 can: it is the
# significance level in four places and a class-and-file rate in three others, and the blanket
# form waved the rates through. The exemption now has to earn itself from the line it sits on.
LITERAL_OK_CONTEXT = {
    "0.05": ("alpha",),
}
# Measurement literals that are still typed into prose. Each was checked against its result JSON
# and agrees with it today, but agreeing today is exactly what the localization prose did before
# the corrected run moved out from under it. They are listed rather than tolerated silently: a
# literal not on this list and not in LITERAL_OK fails the build, so the debt can only shrink.
# Keyed by (value, a snippet of its line) so it survives renumbering.
LITERAL_PENDING = [
    ('0.00', 'score 0.00 on them, wp-taint'),
    ('0.00', 'agnostic, scoring 0.00 on'),
    ('0.00', 'rpose SAST scores 0.00)}};'),
    ('0.283', 'to 0.283, so roughly seven'),
    ('0.013', 'the same $+0.013$, but \\emph{not on the'),
    # 0.893 left this list on 2026-08-17: the sentence now prints \WpBlockRate, so the debt is paid
    # and a tolerated literal that no longer exists is a hole, not a record.
    ('0.00', 'baselines score 0.00.'),
]
# The same debt list for the supplement, which the body check did not cover until now. That gap is
# why the supplement's ZIPPER table, budget curve, temporal cohorts and ranking calibration were all
# still typed by hand while the manuscript beside them was macro-generated. Everything derivable
# from a shipped JSON has been converted; what stays here is what no shipped result file produces,
# and every entry names the reason rather than being tolerated silently.
SUPP_LITERAL_PENDING = [
    # tab:vocab and its prose. A four-arm pre-contract ablation (stock Semgrep, transplanted taint
    # vocabulary, full transplant, WISP). Only the full arm was re-scanned under the contract, and
    # that one is a macro-generated column in the main table. The caption says the table predates
    # the contract; the per-arm rates have no shipped result file.
    ('0.40', 'class emission           & 0.40 & 0.31'),
    ('0.31', 'class emission           & 0.40 & 0.31'),
    ('0.61', 'class emission           & 0.40 & 0.31'),
    ('0.70', 'class emission           & 0.40 & 0.31'),
    ('0.30', 'patch-file@1           & 0.30 & 0.34 &'),
    ('0.46', 'patch-file@1           & 0.30 & 0.34 &'),
    ('0.51', 'patch-file@1           & 0.30 & 0.34 &'),
    ('0.40', 'patch-file@10          & 0.40 & 0.54 &'),
    ('0.54', 'patch-file@10          & 0.40 & 0.54 &'),
    ('0.73', 'patch-file@10          & 0.40 & 0.54 &'),
    ('0.05', 'class-and-file@1       & 0.05 & 0.03 &'),
    ('0.03', 'class-and-file@1       & 0.05 & 0.03 &'),
    ('0.10', 'class-and-file@1       & 0.05 & 0.03 &'),
    ('0.12', 'class-and-file@10      & 0.12 & 0.09 &'),
    ('0.09', 'class-and-file@10      & 0.12 & 0.09 &'),
    ('0.17', 'class-and-file@10      & 0.12 & 0.09 &'),
    ('0.32', 'class-and-file@10      & 0.12 & 0.09 &'),
    ('0.97', 'coverage               & 0.97 & 1.00 &'),
    ('1.00', 'coverage               & 0.97 & 1.00 &'),
    ('0.30', "sinks in Semgrep's taint engine) lifts"),
    ('0.61', 'scanner already has rules. The jump to'),
    ('0.46', 'scanner already has rules. The jump to'),
    ('0.10', 'endpoint WISP is ahead of every Semgre'),
    ('0.05', 'most 0.05 at $K{=}1$, 0.32 against at '),
    ('0.32', 'most 0.05 at $K{=}1$, 0.32 against at '),
    ('0.17', 'most 0.05 at $K{=}1$, 0.32 against at '),
    # tab:mech and its prose. The decomposition of the 854 kept-basis class hits by the detector
    # that produced each one. The ratios are arithmetically exact and the missing-guard row matches
    # the per-class census exactly (372 hits over 422 auth+csrf records), but the taint/risk split
    # rests on a per-finding mechanism attribution that no shipped output records, so it cannot be
    # regenerated here without inventing the census.
    ('0.402', '854 hits, so taken alone the taint eng'),
    ('0.737', 'carries the number to 0.737. The synta'),
    ('0.649', 'Proven taint flow & 445 & 686 & 0.649 '),
    ('0.882', 'Missing-guard predicate & 372 & 422 & '),
    ('0.402', 'Taint only & 445 & 1108 & 0.402 \\\\'),
    ('0.737', '\\quad + missing-guard & 817 & 1108 & 0'),
    # Pre-contract arms the surrounding sentence already labels as such.
    ('0.390', 'and its class emission falls to 0.390 '),
    ('0.004', 'current ablation) reported a 0.004 Wor'),
]
# Values the corrected run superseded outright. Each was a headline number of the pre-contract run
# and has no remaining legitimate use in either document, so any reappearance is a regression to
# the old scoring and fails the build. Kept narrow on purpose: values that a disclosed pre-contract
# table still prints (the Semgrep-WP transplant column) are not listed, since those are labelled.
STALE_VALUES = {
    "0.7708": "old full-corpus WISP class emission, now \\FcCorpusWispEmission",
    "0.771": "old full-corpus WISP class emission, now \\FcCorpusWispEmission",
    "294 of 1108": "old non-convergence count, now \\CorpusNonConv",
    "returns no findings": "Progpilot's pre-fix exit-code behaviour, not a capability",
}
# Lines that are layout, not prose. A width or a TikZ coordinate is not a result.
_LAYOUT = ("\\includegraphics", "\\draw", "\\node", "\\begin{tabular}", "\\setlength",
           "columnwidth", "textwidth", "linewidth", "\\vspace", "\\hspace", "pos=",
           "\\resizebox", "\\scalebox", "\\rule", "\\arraystretch")


def _body_literals(text, defined, pending=()):
    """Every bare decimal left in the body after macro calls are removed."""
    lines = text.split("\n")
    try:
        start = next(i for i, l in enumerate(lines) if "\\begin{document}" in l)
    except StopIteration:
        return []
    names = sorted(defined, key=len, reverse=True)
    # A version string is not a measurement: Semgrep 1.165, tree-sitter 0.25.2, PHP 8.1.2.
    version = re.compile(r"\d+\.\d+(\.\d+)+|(?:Semgrep|tree-sitter|PHP|Python|numpy)~?\s*\d[\d.]*",
                         re.I)
    # {2,3} let every four-decimal number through. 0.8035 sat hand-typed in three places and
    # 0.7536 in two more, all of them beside generated neighbours, because the guard could not see
    # a number one digit longer than it expected. Any decimal length counts now.
    pat = re.compile(r"(?<![\w.])\d?\.\d{2,}(?![\d])")
    out = []
    for i, raw in enumerate(lines[start:], start=start + 1):
        s = raw.strip()
        if not s or s.startswith("%"):
            continue
        if any(k in s for k in _LAYOUT):
            continue
        stripped = version.sub(" ", s)
        for n in names:
            stripped = stripped.replace("\\" + n, " ")
        for m in pat.finditer(stripped):
            num = m.group(0)
            key = num if num in LITERAL_OK else num.lstrip("0")
            if key in LITERAL_OK:
                need = LITERAL_OK_CONTEXT.get(key)
                if not need or any(w in s for w in need):
                    continue
            if any(n == num and snip in s for n, snip in pending):
                continue
            out.append((i, num, s[:96]))
    return out


# Comparative claims the prose makes, checked against the macro values it cites.
#
# Every number in this paper is generated, and that was not enough. The manuscript shipped the
# sentence "at the tight 25 s budget wp-taint-scan is ahead on patch-file success@1 (0.340 for WISP
# against 0.330)", which asserts an ordering its own two macros contradict. Both macros were correct
# and matched their JSON, so nothing here could see it: the defect was in the comparison between
# them, and a comparison is not a number.
#
# This does not try to read prose. It pins the specific orderings the text asserts, so a re-run that
# flips one of them fails the build instead of shipping a sentence that argues with its own figures.
# Add a row whenever the text makes a new comparative claim, and delete the row with the claim.
ORDERINGS = [
    ("WISP leads wp-taint-scan on pf@1 at 25 s",
     "WispPfOneAtTwentyFive", ">", "WptPfOneAtTwentyFive"),
    ("WISP leads wp-taint-scan on pf@1 at 60 s",
     "WispPfOneAtSixty", ">", "WptPfOneAtSixty"),
    ("WISP leads wp-taint-scan on pf@1 at 300 s",
     "WispPfOneAtThreeHundred", ">", "WptPfOneAtThreeHundred"),
    ("Semgrep stays behind wp-taint-scan on pf@1 at 300 s",
     "SemgrepPfOneAtThreeHundred", "<", "WptPfOneAtThreeHundred"),
    ("Progpilot stays behind Semgrep on pf@1 at 300 s",
     "ProgpilotPfOneAtThreeHundred", "<", "SemgrepPfOneAtThreeHundred"),
    # The corpus point estimates go opposite ways at the two budgets and the supplement says so in
    # as many words. Both claims are directional and neither is a separation: both paired intervals
    # span zero, which the surrounding prose states. Written 2026-08-10 as a single "the corpus
    # reverses the ordering at both budgets", which is what wisp-scanner-v1.2 measured; the 60 s
    # claim inverted under v1.3 and this guard is what refused to build until the sentence was
    # rewritten. Keep both directions pinned, so the next flip fails the build in the same way.
    ("at corpus scale wp-taint-scan leads WISP on pf@1 at 25 s",
     "CmxWptPfOneTwentyFive", ">", "CmxWispPfOneTwentyFive"),
    ("at corpus scale WISP leads wp-taint-scan on pf@1 at 60 s",
     "CmxWispPfOneSixty", ">", "CmxWptPfOneSixty"),
    # Section~\ref{sec:rankcorr}. The class-level reading says the two WordPress-aware tools
    # preserve the class ordering across the two rungs and the general-purpose one does not, and
    # the plugin-level sentence names wp-taint-scan as the floor and Progpilot as the ceiling.
    # Both are comparisons, so neither is protected by the macro check on its own.
    ("the class-level correlation is higher for WISP than for Semgrep",
     "RkClsWispRho", ">", "RkClsSemgrepRho"),
    ("the class-level correlation is higher for wp-taint-scan than for Semgrep",
     "RkClsWptRho", ">", "RkClsSemgrepRho"),
    ("the plugin-level correlation runs from wp-taint-scan up to Progpilot",
     "RkPlugProgpilotRho", ">", "RkPlugWptRho"),
    # tab:localize. Its caption asserted for a day that SG-WP led WISP on patch-file at every K.
    # That was true at wisp-scanner-v1.2, where WISP sat at 0.440, and false at v1.3's 0.520, and
    # nothing could see it: every cell was a macro while the direction was a sentence, and the table
    # even bolded the wrong column. A reviewer found it. These four entries make the direction part
    # of the build.
    ("WISP is ahead of SG-WP on patch-file at K=1",
     "LocWispPfOne", ">", "SwpPfOne"),
    ("WISP is ahead of SG-WP on patch-file at K=3",
     "LocWispPfThree", ">", "SwpPfThree"),
    ("WISP is ahead of SG-WP on patch-file at K=5",
     "LocWispPfFive", ">", "SwpPfFive"),
    ("WISP is ahead of SG-WP on class-and-file at K=1",
     "LocWispCfOne", ">", "SwpCfOne"),
]

# Macro pairs that must be EQUAL because they are two names for one quantity, read from two files.
# The manuscript's Wordfence per-finding ladder said WISP emitted 3631 findings while the
# supplement's denominator reconciliation said 3646, because eval/wordfence_rescore_v3.py defaulted
# to the 2026-07-31 scan (engine commit 84f5eb14) while the denominator read the v1.3 contract
# rescan. Both were macro-driven and both were right about their own file, which is exactly why
# nothing caught it. A reviewer did.
EQUALITIES = [
    ("the Wordfence per-finding ladder and the denominator reconciliation count the same findings",
     "ExtLadderWispN", "EdEmitted"),
]


def _check_equalities(defined):
    out = []
    for claim, a, b in EQUALITIES:
        if a not in defined or b not in defined:
            out.append(f"EQUALITY unverifiable, missing macro: {claim} (\\{a} == \\{b})")
            continue
        av, bv = defined[a].replace("{,}", "").replace(",", ""), defined[b].replace("{,}", "").replace(",", "")
        if av != bv:
            out.append(f"EQUALITY VIOLATED: {claim}, but \\{a}={defined[a]} and \\{b}={defined[b]}. "
                       f"These are two readings of one quantity, so a difference means the two "
                       f"sources are different scans.")
    return out


def _check_orderings(defined):
    """Each asserted ordering must hold among the macro values the sentence cites."""
    out = []
    for claim, a, rel, b in ORDERINGS:
        if a not in defined or b not in defined:
            out.append(f"ORDERING unverifiable, missing macro: {claim} (\\{a} {rel} \\{b})")
            continue
        try:
            av, bv = float(defined[a]), float(defined[b])
        except ValueError:
            out.append(f"ORDERING unverifiable, non-numeric macro: {claim}")
            continue
        ok = av > bv if rel == ">" else av < bv
        if not ok:
            out.append(f"ORDERING VIOLATED: the text claims {claim}, but "
                       f"\\{a}={av} {rel} \\{b}={bv} is false")
    return out


def main(check_bbl=True):
    """check_bbl=False for the pre-LaTeX gate. The .bbl is an output of the build, so demanding it
    be current before the build has run would deadlock: a stale .bbl could never be regenerated
    because the guard would abort before bibtex. The build calls this twice, without the .bbl check
    before LaTeX and with it after."""
    fails = []

    # 1. fresh derivation from JSON
    gen.MACROS.clear()
    gen.build()
    expected = {k: v[0] for k, v in gen.MACROS.items()}

    # 2. parse what the generated files actually define
    defined = {}
    defined.update(_parse_newcommands(os.path.join(LATEX, "LATEX_MACROS_V3.tex")))
    defined.update(_parse_newcommands(os.path.join(LATEX, "PAPER_MACROS_V3.tex")))

    for name, val in expected.items():
        if name not in defined:
            fails.append(f"MISSING macro \\{name} (JSON says {val})")
        elif defined[name] != val:
            fails.append(f"MISMATCH \\{name}: macro file = {defined[name]!r}, JSON = {val!r}")

    fails += _check_orderings(defined)
    fails += _check_equalities(defined)

    # 3. manuscript must input the macro file
    if os.path.isfile(MAIN):
        main_tex = open(MAIN, encoding="utf-8").read()
        if "\\input{PAPER_MACROS_V3" not in main_tex and "\\input{PAPER_MACROS_V3.tex" not in main_tex:
            fails.append("manuscript does not \\input{PAPER_MACROS_V3} (numbers not macro-sourced)")
        check_preprints_are_not_load_bearing(main_tex, fails)

        # 4. abstract must carry no literal primary number (decimal rate / ratio / kappa).
        #    Strip only DEFINED macro calls so their expansion is not scanned, but keep plain
        #    LaTeX like \times so an "N\times" ratio literal is still caught.
        abs = _abstract(main_tex)
        abs_wo_macros = abs
        for name in sorted(defined, key=len, reverse=True):
            abs_wo_macros = abs_wo_macros.replace("\\" + name, " ")
        literal_num = re.compile(
            r"(?<![\w.])(0?\.\d{2,}|\d+(?:\.\d+)?\s*\\times|\d+(?:\.\d+)?\s*[x\u00d7]\b|"
            r"\\kappa\s*[={]|kappa\s*[=:]\s*\d)")
        hits = [h if isinstance(h, str) else h[0] for h in literal_num.findall(abs_wo_macros)]
        bad = [h.strip() for h in hits if h.strip()]
        if bad:
            fails.append(f"abstract has literal primary number(s) with no macro source: {bad}")

        # 5. the BODY must carry no literal decimal either. The abstract-only rule is what let
        #    Figure 3 and the localization prose keep the 2026-07-14 run while the tables moved
        #    to the corrected one: a literal in prose is invisible to every check above.
        # 4b. neither document may reprint a superseded headline value.
        for doc, path in (("manuscript", MAIN), ("supplement", SUPP)):
            if not os.path.isfile(path):
                continue
            txt = open(path, encoding="utf-8").read()
            for bad_val, why in STALE_VALUES.items():
                if bad_val in txt:
                    fails.append(f"{doc} reprints superseded value {bad_val!r} ({why})")

        # 5b. The supplement gets the same rule. It was outside this check until now, which is how
        #     four of its tables kept hand-typed numbers while the manuscript was macro-generated.
        for doc, path, pend in (("manuscript", MAIN, LITERAL_PENDING),
                                ("supplement", SUPP, SUPP_LITERAL_PENDING)):
            if not os.path.isfile(path):
                continue
            txt = open(path, encoding="utf-8").read()
            body_bad = _body_literals(txt, defined, pend)
            if body_bad:
                fails.append(f"{doc} body has literal decimal(s) with no macro source, "
                             + str(len(body_bad)) + " site(s):")
                for ln, num, ctx in body_bad[:40]:
                    fails.append(f"    line {ln}: {num}   {ctx}")

        # 6. The software citation must name the engine the paper says it scored under. The bib is
        #    outside the macro system, so nothing above can see it: the availability paragraph moved
        #    to \EngineTag and \EngineSha while @misc{wispsoftware} kept naming v1.2 and 012279d6,
        #    and the two contradicted each other one line apart with every check passing. A reader
        #    resolving the citation would have fetched the engine that produced the OLD numbers.
        #    The .bbl files are checked alongside the .bib because the .bbl is what the reader
        #    actually sees. Correcting the .bib alone left the PDF printing v1.2 for one build, since
        #    nothing regenerated the .bbl, and a check that reads only the source would have called
        #    that build clean.
        sources = [("references.bib", r"@misc\{wispsoftware,(.*?)\n\}")]
        if check_bbl:
            for stem in (os.path.basename(MAIN), os.path.basename(SUPP)):
                sources.append((stem[:-4] + ".bbl", r"\\bibitem\{wispsoftware\}(.*?)(?=\\bibitem|\\end\{thebibliography\})"))
        for fname, pat in sources:
            path = os.path.join(LATEX, fname)
            if not os.path.isfile(path) or "EngineRelease" not in defined:
                continue
            txt = open(path, encoding="utf-8").read()
            m = re.search(pat, txt, re.S)
            if not m:
                if fname.endswith(".bib"):
                    fails.append(f"{fname} has no wispsoftware entry, so the engine the citation "
                                 f"resolves to cannot be checked against \\EngineTag")
                continue        # a .bbl for a document that does not cite the software is fine
            entry = m.group(1)
            # The rule changed once and the change is the point. This used to demand \EngineTag,
            # the internal build label the run manifests stamp, and that is not a thing a reader
            # can fetch: the repository publishes exactly one tag, the release. Demanding the build
            # label sent the citation to a tag that does not exist on the remote, which is a worse
            # failure than the one this check was written for. \EngineRelease and \EngineTag name
            # the same bytes, and the sha256 checked below is what actually pins the engine, so the
            # citation names the release and the identity is carried by the hash.
            for macro, what in (("EngineRelease", "release tag"), ("EngineSha", "engine sha256")):
                want = defined[macro]
                if want not in entry:
                    fails.append(
                        f"{fname} wispsoftware entry does not name the {what} the paper scored "
                        f"under: \\{macro} = {want!r} appears nowhere in it, so the citation sends "
                        f"the reader to a different engine"
                        + (" (run bibtex: the .bbl is stale)" if fname.endswith(".bbl") else ""))
            for stale, why in (("wisp-scanner-v1.2", "the baseline build label"),
                               ("wisp-scanner-v1.3", "the development build label, not a published tag"),
                               ("012279d6", "the baseline engine sha256")):
                if stale in entry and stale not in (defined.get("EngineRelease"),
                                                    defined.get("EngineSha")):
                    fails.append(
                        f"{fname} wispsoftware entry still names {stale!r} ({why}), which is not "
                        f"what this revision was scored under")

    if fails:
        print("PAPER MACRO CHECK: FAIL")
        for f in fails:
            print("  x " + f)
        return 2
    print(f"PAPER MACRO CHECK: PASS ({len(expected)} macros match JSON, abstract clean, "
          "manuscript inputs the macro file)")
    print(f"  body literals still typed in prose: {len(LITERAL_PENDING)} in the manuscript, "
          f"{len(SUPP_LITERAL_PENDING)} in the supplement "
          "(listed in the checker, any new one fails the build)")
    # A pending entry that no longer matches anything has been converted to a macro. Say so, so
    # the debt list cannot quietly rot into a list of things that are not there any more.
    for doc, path, pend, name in (("manuscript", MAIN, LITERAL_PENDING, "LITERAL_PENDING"),
                                  ("supplement", SUPP, SUPP_LITERAL_PENDING,
                                   "SUPP_LITERAL_PENDING")):
        if not os.path.isfile(path):
            continue
        # An entry is dead when no line still carries both the snippet and the number. Testing the
        # snippet alone missed conversions: the sentence survives a macro substitution while the
        # literal in it does not, and the entry then sits in the list forever exempting nothing.
        lines = open(path, encoding="utf-8").read().split("\n")
        dead = [(n, s) for n, s in pend
                if not any(s in ln and n in ln for ln in lines)]
        if dead:
            print(f"  {len(dead)} pending entr(ies) no longer match the {doc} and can be "
                  f"removed from {name}:")
            for n, s in dead:
                print(f"    {n}  {s!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(check_bbl="--no-bbl" not in sys.argv))
