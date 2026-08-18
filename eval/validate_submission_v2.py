#!/usr/bin/env python3
"""Final submission validator (Prompt 8/6). Exit nonzero if the bundle is not shippable.

    python3 -m eval.validate_submission_v2 <bundle_dir>

Fails on any of: a superseded fold-change ratio in the abstract or conclusion; a human-adjudication
/ same-defect / kappa claim that the evidence on disk does not support, which is the v2 integrity
rule, originally a blanket ban because the adjudication was model-assisted and was removed, and now
a conditional one because the study has been run by two declared non-author humans and the check
verifies that declaration, the locks and the result file before allowing the vocabulary; an
AI-generated annotator sheet shipped inside the bundle; a manuscript Progpilot budget
that contradicts the provenance; a manuscript sanitizer default that contradicts the engine; missing
raw data; a stale Zenodo DOI; a supplement, README, cover letter or PDF that carries a superseded
title; a wrong README page count; a manuscript word count over 9200; an
undefined reference or citation; a generated PDF older than its source; or a canonical result JSON
with no input hashes.
"""
from __future__ import annotations
import os, sys, re, json, hashlib, glob, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
WISP = os.path.dirname(HERE)
SYS_ROOT = os.path.dirname(WISP)
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
_mt = glob.glob(os.path.join(LATEX, "*-CnS-elsarticle.tex"))
_st = glob.glob(os.path.join(LATEX, "*-CnS-supplement.tex"))
MAIN_TEX = _mt[0] if _mt else os.path.join(LATEX, "WISP-paper-CnS-elsarticle.tex")
SUPP_TEX = _st[0] if _st else os.path.join(LATEX, "WISP-paper-CnS-supplement.tex")
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
CURRENT_DOI = "21627535"
# 21620269 joins the stale list: it was pinned here AND asserted by the build script, so the
# guard was enforcing the wrong record and no check could see it. A wrong value in the checker
# is worse than no checker, because it converts a mistake into a verified mistake.
STALE_DOIS = ("21253353", "21316432", "21620269")

fails: list[str] = []
warns: list[str] = []


def fail(msg):
    fails.append(msg)


def warn(msg):
    warns.append(msg)


def _pdf_text(path):
    try:
        import pypdf
        return "\n".join((p.extract_text() or "") for p in pypdf.PdfReader(path).pages)
    except Exception as e:
        warn(f"could not extract text from {os.path.basename(path)}: {e}")
        return ""


def _pdf_pages(path):
    try:
        import pypdf
        return len(pypdf.PdfReader(path).pages)
    except Exception:
        return None


def _texcount(tex):
    """texcount-like body word count (Introduction..CRediT), stripping floats, math, and commands."""
    m = re.search(r"\\section\{Introduction\}(.*?)\\section\*\{CRediT", tex, re.S)
    body = m.group(1) if m else tex
    body = re.sub(r"\\begin\{(table\*?|figure\*?|tabular|tikzpicture|algobox|equation\*?|align\*?)\}"
                  r".*?\\end\{\1\}", " ", body, flags=re.S)
    # An escaped dollar is a literal character, not a math delimiter, and this paper is about PHP so
    # it carries 21 of them (\$_GET, \$wpdb, \$x). Pairing them as math shifted every subsequent
    # $...$ boundary by one and made the regex below swallow whole sentences of prose between the
    # closing delimiter of one real span and the opening of the next. The count read 9216 while the
    # body was 9882, a 666-word undercount that had been passing the limit gate for weeks. Strip the
    # escapes before pairing.
    body = body.replace(r"\$", "")
    body = re.sub(r"\$[^$]*\$", " ", body)
    body = re.sub(r"\\[a-zA-Z]+\*?(\[[^\]]*\])?(\{[^{}]*\})?", " ", body)
    body = re.sub(r"[{}\\&%~]", " ", body)
    return len([w for w in body.split() if any(c.isalpha() for c in w)])


def _abstract_conclusion(tex):
    ab = re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}", tex, re.S)
    co = re.search(r"\\section\{Conclusion\}(.*?)(\\section|\Z)", tex, re.S)
    return (ab.group(1) if ab else "") + "\n" + (co.group(1) if co else "")


def check_bundle_files(bundle):
    required = ["manuscript.pdf", "supplement.pdf", "latex.zip", "HIGHLIGHTS.txt", "COVER-LETTER.md",
                "CLAIM-MAP.csv", "OLD-VS-NEW-RESULTS.csv", "SHA256SUMS.txt",
                "artifact", "reproduce"]
    for r in required:
        if not os.path.exists(os.path.join(bundle, r)):
            fail(f"bundle missing required entry: {r}")
    # 2026-08-06: REVISION-AUDIT.md was required here. It is now deliberately not shipped, being an
    # internal handoff record carrying the pre-rebrand tool name and an assistant token, so its
    # presence is the failure rather than its absence.
    if os.path.exists(os.path.join(bundle, "REVISION-AUDIT.md")):
        fail("bundle ships REVISION-AUDIT.md, an internal record that must stay out of the upload")


def check_ratios(mtext):
    # superseded fold-change ratios must not appear in the abstract or conclusion
    ac = _abstract_conclusion(mtext)
    bad = re.findall(r"\b(?:21|11|7\.5|4\.5)\s*\\?times|\b(?:21|11|7\.5|4\.5)\s*[x\u00d7]\b", ac)
    if bad:
        fail(f"superseded fold-change ratio in abstract/conclusion: {bad}")


AIADJ_REQUIRED = [
    # the section must say, in the text itself, that the annotators were not human experts
    r"automated",
    # and it must say the study does not supply defect-level ground truth
    r"not.{0,40}(ground truth|defect-level)|does not supply|left to future work",
    # and it must record that the blinding key stayed sealed, so no rate can reach a tool
    r"did not open the blinding key|blinding key.{0,30}(sealed|not open)",
]
AIADJ_FORBIDDEN = [
    # a per-tool defect rate is the thing the integrity rule exists to prevent, in any section
    (r"\b(WISP|Semgrep|Progpilot)\b[^.]{0,80}same[- ]defect", "attributes a same-defect rate to a tool"),
    (r"same[- ]defect rate of", "states a same-defect rate as a result"),
]


def check_no_human_claim(mtext, bundle):
    # v2 integrity rule: no same-defect / two-annotator claim may stand as a result, and the bundle
    # must not ship model-written annotator sheets.
    #
    # The rule is about the CLAIM, not the vocabulary. A section that reports the adjudication
    # attempt as a failed measurement has to name the axes it measured, so a blanket ban on the
    # words also bans the honest disclosure. The ban therefore still applies everywhere by default,
    # and is lifted only inside the section labelled sec:aiadj, and only when that section carries
    # the disclosures in AIADJ_REQUIRED. AIADJ_FORBIDDEN applies everywhere including there.
    supptext = open(SUPP_TEX).read() if os.path.isfile(SUPP_TEX) else ""
    banned = [r"same[- ]defect", r"\bannotator", r"inter[- ]annotator", r"two[- ]annotator",
              r"blinded (annotator|two|human|same)", r"Cohen'?s \$?\\?kappa",
              r"root[- ]cause relation"]
    # Macro names from the removed study. These are matched case-sensitively and the prose patterns
    # are not, because \Kappa under re.I also matches LaTeX's own \kappa, so the guard was banning
    # the Greek letter and with it any honest report of an agreement statistic.
    banned_cs = [r"\\Kappa\b", r"\\WispSameDefect\b", r"\\KappaRootCause\b"]

    # 2026-08-18: the study was run by two human annotators, so a blanket ban on the vocabulary now
    # bans a true statement. The rule was never about the words though, it was about a claim
    # outrunning its evidence, so the ban lifts only when the evidence is on disk and says what the
    # claim needs it to say. If any of these fails the ban stays and the words fail the build, which
    # is the behaviour that caught the model-assisted sheets in the first place.
    def _human_study_is_evidenced():
        why = []
        meta_p = os.path.join(SYS_ROOT, "revision-cns-v2", "adjudication", "tier1",
                              "REVIEWER_METADATA_TEMPLATE.json")
        if not os.path.isfile(meta_p):
            return ["no reviewer metadata file on disk"]
        meta = json.load(open(meta_p)).get("payload", {})
        for who in ("reviewer_A", "reviewer_B"):
            m = meta.get(who) or {}
            for f in ("expertise_php_wordpress_security", "years_experience",
                      "knows_research_objective", "is_paper_author", "conflict_of_interest"):
                if not str(m.get(f, "")).strip():
                    why.append(f"{who}.{f} is blank")
            if str(m.get("is_paper_author", "")).strip().lower() not in ("no", "false", "0"):
                why.append(f"{who} did not declare non-author status")
        for tier, fn in ((1, "reviewer_%s_defect_cards.json"), (2, "reviewer_%s_findings.json")):
            d = os.path.join(SYS_ROOT, "revision-cns-v2", "adjudication", f"tier{tier}")
            if not os.path.isfile(os.path.join(d, "LOCK.json")):
                why.append(f"tier {tier} is not locked")
            for who in ("A", "B"):
                if not os.path.isfile(os.path.join(d, fn % who)):
                    why.append(f"tier {tier} sheet for {who} is missing")
        res = os.path.join(OUT, "DEFECT_STUDY_RESULT_V3.json")
        if not os.path.isfile(res):
            why.append("no DEFECT_STUDY_RESULT_V3.json")
        return why

    # The reverse rule a reviewer asked for. Allowing the vocabulary once the working tree carries
    # the evidence is not enough, because a reader has the bundle and not the working tree. If the
    # documents print a human rate or an agreement statistic, the bundle has to carry the labels
    # those come from, or the reader is back to taking the one human number on trust while every
    # geometric rate beside it reproduces.
    def _bundle_ships_labels():
        for root, _d, files in os.walk(bundle):
            if "defect_study_labels.csv" in files:
                return os.path.relpath(os.path.join(root, "defect_study_labels.csv"), bundle)
        return None

    prints_human = any(re.search(p_, t) for t in (mtext, supptext)
                       for p_ in (r"\\DsPooled", r"\\DsKappa", r"\\DsWisp", r"\\DsFactor"))
    shipped_at = _bundle_ships_labels()
    if prints_human and not shipped_at:
        fail("the documents print a human-judged rate or an agreement statistic but the bundle "
             "ships no defect_study_labels.csv, so the one number resting on human judgment "
             "cannot be recomputed by a reader while every geometric rate beside it can")
    elif prints_human:
        warn(f"human-judged numbers are printed and their labels ship at {shipped_at}")

    unevidenced = _human_study_is_evidenced()
    if unevidenced:
        warn("human-adjudication vocabulary stays banned: " + "; ".join(unevidenced[:4]))
    else:
        banned = [b for b in banned if b not in (r"\bannotator", r"inter[- ]annotator",
                                                 r"two[- ]annotator", r"same[- ]defect",
                                                 r"root[- ]cause relation",
                                                 r"Cohen'?s \$?\\?kappa")]
        warn("human-adjudication vocabulary allowed: both annotators declared non-author with "
             "complete independence metadata, both tiers locked, result file present")

    def _aiadj_span(txt):
        m = re.search(r"\\section\{[^}]*\}\\label\{sec:aiadj\}", txt)
        if not m:
            return None
        nxt = re.search(r"\n\\section\{", txt[m.end():])
        return (m.start(), m.end() + (nxt.start() if nxt else len(txt) - m.end()))

    for label, txt in (("manuscript", mtext), ("supplement", supptext)):
        span = _aiadj_span(txt)
        if span:
            # LaTeX wraps prose, so a required phrase is routinely split across a newline
            body = re.sub(r"\s+", " ", txt[span[0]:span[1]])
            for pat in AIADJ_REQUIRED:
                if not re.search(pat, body, re.I):
                    fail(f"{label} sec:aiadj is missing a required disclosure: /{pat}/. The "
                         f"exemption for that section only holds while it states plainly that the "
                         f"annotation was automated and is not defect-level ground truth.")
        for pat, flags in [(b, re.I) for b in banned] + [(b, 0) for b in banned_cs]:
            for m in re.finditer(pat, txt, flags):
                if span and span[0] <= m.start() < span[1]:
                    continue                     # inside the disclosed section
                fail(f"{label} still makes a human-adjudication claim: matched /{pat}/ "
                     f"near ...{txt[max(0, m.start()-30):m.start()+40].strip()}...")
                break
            else:
                continue
            break
        for pat, why in AIADJ_FORBIDDEN:
            m = re.search(pat, txt, re.I)
            if m:
                fail(f"{label} {why}: ...{txt[max(0, m.start()-20):m.start()+70].strip()}...")
    # the AI-generated annotator artifacts must not be inside the shipped bundle
    # AI_ADJUDICATION_V3.json joins the list on 2026-08-13. It is a derived summary rather than a
    # raw sheet, so every name-based rule above missed it, and a manifest-wide sweep in the packaging
    # script put it in the bundle while the validator passed. Neither document prints any of its 37
    # macros, so it is never needed, and a bundle whose integrity story is "the model-assisted
    # adjudication was removed" must not carry the model's own agreement statistics.
    leak = ["reviewer_A_findings.json", "reviewer_B_findings.json", "BLINDING_KEY.json",
            "PACKETS.json", "reviewer_A_defect_cards.json", "reviewer_B_defect_cards.json",
            "defect_adjudication_kappa.json", "defect_adjudication_sheet.csv",
            "defect_adjudication_sheet_key.json", "reconciliation.csv", "reconciliation.json",
            "AI_ADJUDICATION_V3.json"]
    for root, _dirs, files in os.walk(bundle):
        for fn in files:
            if fn in leak:
                fail(f"bundle ships an AI-generated adjudication artifact: {os.path.relpath(os.path.join(root, fn), bundle)}")


def check_progpilot(mtext):
    # a fixed Progpilot cap in the manuscript that contradicts the provenance
    prov_budgets = set()
    mx = os.path.join(OUT, "BASELINE_MATRIX_V3.json")
    if os.path.isfile(mx):
        for k in json.load(open(mx)).get("cells", {}):
            if k.startswith("progpilot@"):
                prov_budgets.add(k.split("@")[1])
    for m in re.finditer(r"[Pp]rogpilot[^.\n]{0,40}?(\d+)\s*\\?,?\s*s\b", mtext):
        cap = m.group(1)
        if prov_budgets and cap not in prov_budgets:
            fail(f"manuscript states Progpilot {cap}s but provenance budgets are {sorted(prov_budgets)}")


def check_sanitizer(mtext):
    # manuscript must not say the sanitizer class flag is off by default while the engine defaults on
    eng = os.path.join(WISP, "wisp", "engine", "taint_engine.py")
    default_on = False
    if os.path.isfile(eng):
        src = open(eng).read()
        m = re.search(r'WISP_SANI_CLASS"\s*,\s*"([01])"', src)
        default_on = bool(m and m.group(1) == "1")
    says_off = bool(re.search(r"(class propagation|sanitizer[^.]{0,40})[^.]{0,60}off by default", mtext, re.I))
    if default_on and says_off:
        fail("manuscript says sanitizer/class propagation off by default but engine default is on")


def check_raw_data():
    # geometry-only: the primary numbers derive from the finding population and the baseline matrix,
    # no adjudication sheet is required any more.
    # The corpus population is listed beside them because the supplement's corpus-scale ladder is
    # aggregated from it, and both of its failure-policy arms are verified against it on every build.
    need = ["revision-cns-v2/data/FINDING_POPULATION_V3.jsonl",
            "revision-cns-v2/out/BASELINE_MATRIX_V3.json",
            "revision-cns-v2/out/CORPUS_FINDING_POPULATION_V3.jsonl"]
    for n in need:
        if not os.path.isfile(os.path.join(SYS_ROOT, n)):
            fail(f"missing raw data: {n}")


# Text-bearing members of the bundle. A DOI can hide in a docstring or a helper README just as
# easily as in the manuscript, so the sweep is by extension rather than by a hand-kept file list.
DOI_SWEEP_EXT = (".md", ".py", ".tex", ".bib", ".txt", ".sh", ".json", ".jsonl", ".csv", ".cfg")
# This module is the one place a stale DOI is supposed to appear, because it is the list that bans it.
DOI_SWEEP_SKIP = ("validate_submission_v2.py",)


def check_doi(mtext, bundle):
    """Fail on any stale Zenodo DOI anywhere in the shipped bundle, not just the front matter.

    The first version of this check read the manuscript and the bundle README and nothing else. That
    is how `10.5281/zenodo.21620269` survived in `eval/datasets/patchstack.py` and
    `eval/testset/README.md` while every build reported PASS: the artifact tree ships inside the
    bundle and a reader who follows its instructions lands on the wrong record, which is the same
    harm as a wrong DOI on page one. Scoping a guard to where the mistake was last seen is what let
    the mistake move."""
    readme = os.path.join(bundle, "README.md")
    texts = {"manuscript": mtext, "README": open(readme).read() if os.path.isfile(readme) else ""}
    for where, t in texts.items():
        for stale in STALE_DOIS:
            if stale in t:
                fail(f"stale Zenodo DOI {stale} in {where}")
        if "zenodo" in t.lower() and CURRENT_DOI not in t:
            warn(f"{where} mentions zenodo but not the current DOI {CURRENT_DOI}")

    swept = 0
    for root, _dirs, files in os.walk(bundle):
        for fn in files:
            if not fn.endswith(DOI_SWEEP_EXT) or fn in DOI_SWEEP_SKIP:
                continue
            p = os.path.join(root, fn)
            try:
                body = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            swept += 1
            for stale in STALE_DOIS:
                if stale in body:
                    fail(f"stale Zenodo DOI {stale} in {os.path.relpath(p, bundle)}")
    warn(f"swept {swept} bundle files for stale DOIs, current DOI is {CURRENT_DOI}")


# The retitle of 2026-08-17 reached the manuscript and stopped there: the supplement's own \title,
# the bundle README and the cover letter's opening sentence all still printed the superseded wording,
# so supplement.pdf and manuscript.pdf disagreed on the front page. Same shape as the .bib and the
# caption before it. A title is prose, it carries no macro, so nothing was checking it.
TITLE_SHAPE = re.compile(r"What Patch-File (\w+) Does Not Measure")
# A line may quote the superseded title only where it says so.
FORMER_TITLE_MARKERS = ("previously", "formerly", "superseded", "was titled", "old title")


def _manuscript_title():
    m = re.search(r"\\title\{(.+?)\}\s*$", open(MAIN_TEX).read(), re.M | re.S) if os.path.isfile(MAIN_TEX) else None
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def check_title_agrees(bundle):
    title = _manuscript_title()
    if not title:
        fail("could not read \\title{} from the manuscript, so no title check ran")
        return
    shape = TITLE_SHAPE.search(title)
    if not shape:
        warn(f"manuscript title does not match the known title shape, only exact matches checked: {title}")
    word = shape.group(1) if shape else None

    if os.path.isfile(SUPP_TEX):
        sm = re.search(r"\\title\{(.+?)\}\s*$", open(SUPP_TEX).read(), re.M | re.S)
        st = re.sub(r"\s+", " ", sm.group(1)).strip() if sm else ""
        sw = TITLE_SHAPE.search(st)
        if not sw:
            fail(f"supplement title carries no recognizable title clause: {st!r}")
        elif word and sw.group(1) != word:
            fail(f"supplement title says {sw.group(1)!r} where the manuscript says {word!r}: {st!r}")

    # The prose that names the paper to an editor has to name the paper the editor will open.
    for fn in ("README.md", "COVER-LETTER.md"):
        p = os.path.join(bundle, fn)
        if not os.path.isfile(p):
            continue
        raw = open(p, encoding="utf-8", errors="replace").read()
        if re.sub(r"\s+", " ", raw).find(title) < 0:
            fail(f"{fn} never states the manuscript's current title verbatim")
        for line in raw.splitlines():
            m = TITLE_SHAPE.search(line)
            if not m or not word or m.group(1) == word:
                continue
            if not any(k in line.lower() for k in FORMER_TITLE_MARKERS):
                fail(f"{fn} carries the superseded title clause {m.group(1)!r} without saying it is "
                     f"the former title: {line.strip()[:90]}")

    # A PDF built before the retitle looks fine on disk and wrong on the front page.
    for pdfname, tex in (("manuscript.pdf", MAIN_TEX), ("supplement.pdf", SUPP_TEX)):
        p = os.path.join(bundle, pdfname)
        if not os.path.isfile(p) or not word:
            continue
        printed = {m.group(1) for m in TITLE_SHAPE.finditer(re.sub(r"\s+", " ", _pdf_text(p)))}
        if printed and word not in printed:
            fail(f"{pdfname} prints the title clause {sorted(printed)} but the source says {word!r}")
    warn(f"title checked across supplement, README, cover letter and both PDFs: {title}")


def check_pagecount(bundle, mtext):
    readme = os.path.join(bundle, "README.md")
    rt = open(readme).read() if os.path.isfile(readme) else ""
    for pdfname, label in (("manuscript.pdf", "main"), ("supplement.pdf", "supplement")):
        p = os.path.join(bundle, pdfname)
        if not os.path.isfile(p):
            continue
        pages = _pdf_pages(p)
        m = re.search(rf"`{pdfname}`[^|]*\|[^|]*?(\d+)\s*page", rt) or \
            re.search(rf"{label}[^\n]*?(\d+)\s*page", rt, re.I)
        if pages and m and int(m.group(1)) != pages:
            fail(f"README page count for {pdfname} is {m.group(1)} but the PDF has {pages}")


def check_wordcount(mtext):
    n = _texcount(mtext)
    if n > 9200:
        fail(f"manuscript word count {n} exceeds 9200")
    else:
        warn(f"manuscript body word count (texcount-approx) = {n}")


def check_undefined(bundle):
    for pdfname in ("manuscript.pdf", "supplement.pdf"):
        t = _pdf_text(os.path.join(bundle, pdfname))
        # undefined refs render as "??" and undefined citations as "[?]"
        if re.search(r"\?\?", t) or re.search(r"\[\?\]", t):
            fail(f"{pdfname} contains an undefined reference/citation marker (?? or [?])")


def check_pdf_not_stale(bundle):
    # This catches "edited the source but forgot to rebuild" on the working tree. Inside a shipped
    # bundle the .tex sources are frozen copies mirrored under artifact/, so their mtimes only reflect
    # copy order and the check would false-positive; skip it there (the build touches the PDFs last).
    if os.path.basename(SYS_ROOT) == "artifact":
        warn("running inside a shipped bundle; the PDF-vs-source staleness check is skipped")
        return
    for pdfname, tex in (("manuscript.pdf", MAIN_TEX), ("supplement.pdf", SUPP_TEX)):
        p = os.path.join(bundle, pdfname)
        if os.path.isfile(p) and os.path.isfile(tex):
            if os.path.getmtime(p) < os.path.getmtime(tex):
                fail(f"{pdfname} is older than its source {os.path.basename(tex)} (rebuild before shipping)")


def check_input_hashes():
    canonical = ["GEOMETRIC_LADDER_V3.json", "BASELINE_MATCHED100_V3.json",
                 "SANI_ABLATION_V3.json", "TOOL_MANIFEST_V3.json"]
    for f in canonical:
        p = os.path.join(OUT, f)
        if not os.path.isfile(p):
            continue
        d = json.load(open(p))
        blob = json.dumps(d)
        if not any(k in blob for k in ("input_hashes", "provenance", "taint_engine_sha256",
                                       "artifact_source_sha256")):
            fail(f"canonical result {f} has no input hashes / provenance")


def check_reproduction(bundle):
    """Actually run the artifact's one-command reproduction, and require it to exit 0.

    This validator reported "PASS: shippable" for weeks while `reproduce/run.sh` exited 1 inside the
    bundle, because it checked everything about the reproduction except whether it runs. A reviewer
    found that in minutes. Two targets failed on inputs that were never packaged, and the whole point
    of the promise on the bundle's front page is that a stranger can run one command.

    The second half matters as much. The reproduction used to run in place and rewrite eight of the
    result JSONs it had just verified, so verifying SHA256SUMS.txt afterwards reported the bundle as
    tampered with. run.sh now works in a temporary copy, and this check proves it by re-verifying the
    manifest after the run rather than trusting the script to be well behaved.

    Set WISP_SKIP_REPRODUCTION=1 to skip during iteration. It is reported as a warning, loudly,
    because a skipped check is not a passed one."""
    run = os.path.join(bundle, "reproduce", "run.sh")
    if not os.path.isfile(run):
        fail("reproduce/run.sh is missing, so the bundle's one-command promise cannot be checked")
        return
    if os.environ.get("WISP_SKIP_REPRODUCTION") == "1":
        warn("REPRODUCTION NOT RUN (WISP_SKIP_REPRODUCTION=1). This is not a pass.")
        return

    sums = os.path.join(bundle, "SHA256SUMS.txt")
    before = _manifest_state(bundle, sums)

    r = subprocess.run(["bash", run], capture_output=True, text=True, cwd=bundle)
    if r.returncode != 0:
        tail = (r.stdout or "").strip().splitlines()[-6:]
        fail(f"reproduce/run.sh exited {r.returncode}; last lines: " + " | ".join(tail))
    else:
        warn("reproduce/run.sh exited 0")

    after = _manifest_state(bundle, sums)
    if before is not None and after is not None and before != after:
        fail(f"reproduce/run.sh modified {after} shipped file(s) that SHA256SUMS.txt attests "
             f"(was {before}); the reproduction must not write into the shipped tree")


def _manifest_state(bundle, sums):
    """Count files that fail their recorded checksum, or None when there is no manifest yet."""
    if not os.path.isfile(sums):
        return None
    r = subprocess.run(["sha256sum", "-c", os.path.basename(sums)],
                       capture_output=True, text=True, cwd=bundle)
    return sum(1 for ln in (r.stdout or "").splitlines() if ln.strip().endswith("FAILED"))


def main():
    if len(sys.argv) < 2:
        print("usage: validate_submission_v2.py <bundle_dir>"); return 2
    bundle = os.path.abspath(sys.argv[1])
    mtext = open(MAIN_TEX).read() if os.path.isfile(MAIN_TEX) else ""

    # A reviewer reported this looked hung: the reproduction check alone runs the whole kit, which
    # takes minutes, and the script printed nothing until it was finished. Silence and a hang are
    # indistinguishable, so each step announces itself before it runs and reports how long it took.
    steps = [
        ("bundle files", lambda: check_bundle_files(bundle)),
        ("superseded ratios", lambda: check_ratios(mtext)),
        ("human-adjudication claims vs evidence", lambda: check_no_human_claim(mtext, bundle)),
        ("Progpilot budget vs provenance", lambda: check_progpilot(mtext)),
        ("sanitizer default vs engine", lambda: check_sanitizer(mtext)),
        ("raw data present", check_raw_data),
        ("Zenodo DOI sweep", lambda: check_doi(mtext, bundle)),
        ("title agreement", lambda: check_title_agrees(bundle)),
        ("README page counts", lambda: check_pagecount(bundle, mtext)),
        ("manuscript word count", lambda: check_wordcount(mtext)),
        ("undefined references", lambda: check_undefined(bundle)),
        ("PDF newer than source", lambda: check_pdf_not_stale(bundle)),
        ("result provenance hashes", check_input_hashes),
        ("in-bundle reproduction (slow, runs the whole kit)",
         lambda: check_reproduction(bundle)),
    ]
    import time as _t
    for i, (name, fn) in enumerate(steps, 1):
        print(f"[{i:2}/{len(steps)}] {name} ...", end="", flush=True)
        t0 = _t.time()
        fn()
        print(f" {_t.time() - t0:.1f}s", flush=True)

    print("=" * 70)
    print(f"SUBMISSION VALIDATOR v2  ->  {bundle}")
    print("=" * 70)
    for w in warns:
        print(f"  [note] {w}")
    if fails:
        print(f"\nFAIL ({len(fails)} blocking issue(s)):")
        for f in fails:
            print(f"  x {f}")
        print("\nBUNDLE NOT SHIPPABLE.")
        return 1
    print("\nPASS: no blocking issue. Bundle is shippable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
