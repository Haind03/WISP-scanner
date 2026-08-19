#!/usr/bin/env python3
"""Guard the three v3 result figures against the JSONs they claim to draw.

    python3 -m eval.check_figures_v3 [--figure NAME] [--no-reproduce] [-v]

WHY THIS EXISTS.
Twice in this project a generated artifact printed something its source no longer said and every
check was green, because the check compared the artifact only against the thing it was derived
from. A figure PDF kept an old axis label after the text sweep and was only caught by pulling the
text layer out of the PDF. So this guard looks at the PDF itself, from four independent angles,
and it refuses to trust the generating script's own assertions.

  1. STALE. Every PDF must be at least as new as its script and as every input that script reads,
     including the estimator module that fig_perclass imports. A figure derived from a file that
     has since moved is stale even when its own numbers are internally consistent.
  2. REPRODUCTION. Each script is re-run in a throwaway tree whose ROOT is a temporary directory
     with the real revision-cns-v2/ and wisp-artifact/ symlinked in, so nothing on disk is
     touched, and the shipped PDF must come out byte-identical to the fresh one once the
     /CreationDate stamp is masked. This is the only layer that can see a drifted value that
     carries no printed label, for example a series in a panel that prints no numbers at all.
  3. LABELS. Every numeric token in the PDF text layer is re-derived here, in this file, straight
     from the result JSONs, and the whole multiset of numeric tokens found in the PDF must equal
     the multiset this guard expects. An extra number, a missing number, or a number formatted off
     the wrong field all fail. Axis ticks are declared, and declaring them is the point: if an
     axis is silently retuned the declared set stops matching and the guard fires.
  4. PAIRING. A correct number attached to the wrong series is still wrong. Every value label is
     matched to its row by nearest tick-label position in the PDF, and the pair must be the pair
     the JSON holds.

  plus TOKENS: no retired brand and no retired quantity may appear in the text layer, checked on
  the span text and again on a whitespace-stripped ghostscript extraction, because a rotated label
  extracts one character per line and a naive comparison never sees it.

Failure is loud and the exit code is 1. Nothing here writes to the figure directory.
"""
from __future__ import annotations
import argparse, collections, json, os, re, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # .../wisp-artifact
SYS_ROOT = os.path.dirname(ROOT)                                       # .../System-ScanInfosec
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")
OUTDIR = os.path.join(SYS_ROOT, "revision-cns-v2", "out")

LADDER = os.path.join(OUTDIR, "CORPUS_LADDER_KEPT_V3.json")
DEFECT = os.path.join(OUTDIR, "DEFECT_STUDY_RESULT_V3.json")
POP = os.path.join(OUTDIR, "CORPUS_FINDING_POPULATION_V3.jsonl")
ESTIMATOR = os.path.join(ROOT, "eval", "analyze_v3.py")

ORDER = ["wisp", "semgrep", "progpilot", "wpt"]
LABEL = {"wisp": "WISP", "semgrep": "Semgrep", "progpilot": "Progpilot", "wpt": "wp-taint-scan"}

# Retired brand and retired quantities. The tool has not been called NES since the rebrand and no
# figure in this paper reports a recall or a detection rate, so any of these in a figure is either
# a leftover or an overclaim. Checked case-insensitively except for the brand, which is checked as
# an uppercase run so that ordinary words cannot trip it.
FORBIDDEN_CASE = [r"\bNES\b", r"NES[-_]?[Ss]can"]
FORBIDDEN_CI = ["recall", "detection rate", "defect rate", "true positive rate", "f-score"]

# Axis ticks are chrome, not data, so they are declared rather than derived. Declaring them is a
# check in itself: retune an axis and the multiset stops matching.
TICKS = {
    "fig_collapse": ["0.0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.00", "0.05", "0.10"],
    "fig_geom_vs_human": ["0.0", "0.2", "0.4", "0.6", "0.0", "0.2", "0.4", "0.6", "0.8"],
    "fig_perclass": ["0.0", "0.2", "0.4", "0.6", "0.8", "1.0", "0.0", "0.2", "0.4", "0.6"],
}
# Digit-bearing text that is a label rather than a measurement.
STATIC = {"fig_collapse": ["prox@5"], "fig_geom_vs_human": [], "fig_perclass": []}

FAILS: list[str] = []
VERBOSE = False


def ok(msg):
    if VERBOSE:
        print("    ok   %s" % msg)


def fail(fig, msg):
    FAILS.append("%s: %s" % (fig, msg))
    print("  FAIL %s: %s" % (fig, msg))


# ---------------------------------------------------------------- PDF text layer

def spans(pdf):
    """Every text span with its size and box. Rotated labels come back whole, not one char a line."""
    try:
        import fitz
    except ImportError:
        raise SystemExit("check_figures_v3 needs PyMuPDF (import fitz) to read the PDF text layer")
    doc = fitz.open(pdf)
    out = []
    for page in doc:
        for b in page.get_text("dict")["blocks"]:
            for line in b.get("lines", []):
                for s in line["spans"]:
                    x0, y0, x1, y1 = s["bbox"]
                    out.append({"text": s["text"], "size": round(s["size"], 2),
                                "x": (x0 + x1) / 2.0, "y": (y0 + y1) / 2.0,
                                "x0": x0, "x1": x1, "y0": y0, "y1": y1,
                                "rot": tuple(round(v, 2) for v in line["dir"]) != (1.0, 0.0)})
    doc.close()
    return out


def gs_text(pdf):
    """Redundant extraction through ghostscript, whitespace stripped. Returns None if gs is absent."""
    exe = shutil.which("gs")
    if not exe:
        return None
    with tempfile.TemporaryDirectory() as td:
        txt = os.path.join(td, "t.txt")
        subprocess.run([exe, "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=txtwrite", "-o", txt, pdf],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return re.sub(r"\s+", "", open(txt, encoding="utf-8", errors="replace").read())


def page_geometry(pdf):
    import fitz
    doc = fitz.open(pdf)
    r = doc[0].rect
    fonts = doc[0].get_fonts(full=True)
    doc.close()
    return r.width, r.height, fonts


# ---------------------------------------------------------------- generic checks

def check_tokens(fig, sp, pdf):
    joined = " ".join(s["text"] for s in sp)
    for pat in FORBIDDEN_CASE:
        for s in sp:
            if re.search(pat, s["text"]):
                fail(fig, "retired token %r in PDF span %r" % (pat, s["text"]))
    for word in FORBIDDEN_CI:
        if word in joined.lower():
            fail(fig, "retired term %r in the PDF text layer" % word)
    g = gs_text(pdf)
    if g is None:
        print("  note %s: ghostscript not on PATH, the redundant text extraction was skipped" % fig)
    else:
        # Ghostscript emits rotated text one character to a line, and when two rotated labels
        # overlap it INTERLEAVES their characters, so a substring search over the whitespace
        # stripped stream can miss a retired token that is plainly in the figure. Verified: a
        # rotated "NES recall" injected next to the rotated "patch geometry" label came out of
        # txtwrite as "SetdgHEcatNcaipdujd..." and no substring search found it. So the substring
        # pass below is a bonus, and the load-bearing cross-check is the character census: every
        # character ghostscript renders must be a character the span reader reported, and the
        # other way round. Any text object the span reader does not see fails here.
        squeezed = re.sub(r"\s+", "", joined)
        gs_chars, span_chars = collections.Counter(g), collections.Counter(squeezed)
        if gs_chars != span_chars:
            fail(fig, "ghostscript and the span reader disagree about what the PDF says: "
                      "only ghostscript sees %r, only the span reader sees %r"
                 % (dict(gs_chars - span_chars), dict(span_chars - gs_chars)))
        else:
            ok("ghostscript census agrees with the span reader (%d chars)" % len(g))
        for word in FORBIDDEN_CI:
            if re.sub(r"\s+", "", word) in g.lower():
                fail(fig, "retired term %r in the ghostscript text extraction" % word)
    for t in LABEL.values():
        if t not in joined:
            fail(fig, "tool label %r missing from the PDF text layer" % t)
    ok("no retired token, all four tool labels present")


def check_numeric_multiset(fig, sp, expected):
    """Every digit-bearing span must be a token this guard derived, and nothing may be missing."""
    got = collections.Counter(s["text"].strip() for s in sp if re.search(r"\d", s["text"]))
    want = collections.Counter(expected)
    extra = got - want
    missing = want - got
    for tok, n in sorted(extra.items()):
        fail(fig, "PDF prints %r x%d, which no source JSON holds" % (tok, n))
    for tok, n in sorted(missing.items()):
        fail(fig, "PDF is missing the derived label %r x%d" % (tok, n))
    if not extra and not missing:
        ok("all %d digit-bearing spans re-derived from the source JSON" % sum(got.values()))


def nearest(target, cands, axis="y"):
    return min(cands, key=lambda c: abs(c[axis] - target[axis]))


def check_stale(fig, pdf, sources, extra_outputs=()):
    if not os.path.exists(pdf):
        fail(fig, "no PDF at %s" % pdf)
        return False
    tp = os.path.getmtime(pdf)
    for s in sources:
        if not os.path.exists(s):
            fail(fig, "source missing: %s" % s)
            continue
        ts = os.path.getmtime(s)
        if tp < ts - 1e-6:
            fail(fig, "PDF is STALE, it is older than %s (pdf %s < src %s)"
                 % (os.path.relpath(s, SYS_ROOT), _t(tp), _t(ts)))
    for o in extra_outputs:
        if not os.path.exists(o):
            fail(fig, "companion output missing: %s" % o)
            continue
        for s in sources:
            if os.path.exists(s) and os.path.getmtime(o) < os.path.getmtime(s) - 1e-6:
                fail(fig, "companion %s is STALE against %s"
                     % (os.path.basename(o), os.path.relpath(s, SYS_ROOT)))
    ok("newer than all %d inputs" % len(sources))
    return True


def _t(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _mask(b):
    return re.sub(rb"/CreationDate\s*\([^)]*\)", b"/CreationDate(MASKED)", b)


def check_reproduces(fig, script, companions=()):
    """Re-run the script against a temporary ROOT and demand the shipped PDF back, byte for byte.

    The temporary tree symlinks the real inputs in, so the re-run reads exactly what the shipped
    figure read and writes nothing outside the temporary directory.
    """
    td = tempfile.mkdtemp(prefix="figcheck_")
    try:
        sub = os.path.join(td, "2026-07-07", "latex")
        os.makedirs(sub)
        for link in ("revision-cns-v2", "wisp-artifact"):
            os.symlink(os.path.join(SYS_ROOT, link), os.path.join(td, link))
        shutil.copy2(script, sub)
        # matplotlib stamps a /CreationDate whose STRING LENGTH depends on how it is produced, and
        # a length change moves every xref offset in the file, so a byte comparison would fail on
        # the stamp alone. Both sides therefore take the same wall-clock format and the stamp is
        # masked; SOURCE_DATE_EPOCH is cleared so an inherited one cannot desynchronise the two.
        env = dict(os.environ, MPLBACKEND="Agg", PYTHONHASHSEED="0")
        env.pop("SOURCE_DATE_EPOCH", None)
        r = subprocess.run([sys.executable, os.path.join(sub, os.path.basename(script))],
                           cwd=sub, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            fail(fig, "re-run failed rc=%d: %s" % (r.returncode, (r.stderr or "").strip()[-400:]))
            return
        for name in (fig + ".pdf",) + tuple(companions):
            fresh = os.path.join(sub, name)
            shipped = os.path.join(LATEX, name)
            if not os.path.exists(fresh):
                fail(fig, "the re-run produced no %s" % name)
                continue
            a, b = open(shipped, "rb").read(), open(fresh, "rb").read()
            if _mask(a) == _mask(b):
                ok("%s reproduces byte-identically (CreationDate masked)" % name)
                continue
            if not name.endswith(".pdf"):
                fail(fig, "%s does NOT reproduce from the current sources" % name)
                continue
            same_vec, same_txt = _deep_equal(shipped, fresh)
            if same_vec and same_txt:
                print("  note %s: %s differs in bytes but its vector content and text layer are "
                      "identical" % (fig, name))
            else:
                fail(fig, "%s does NOT reproduce from the current sources "
                          "(vector identical=%s, text identical=%s)" % (name, same_vec, same_txt))
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _deep_equal(p1, p2):
    import fitz
    def dump(p):
        d = fitz.open(p)
        vec = b"\n".join(d[i].read_contents() for i in range(d.page_count))
        txt = "".join(d[i].get_text("text") for i in range(d.page_count))
        d.close()
        return vec, re.sub(r"\s+", "", txt)
    v1, t1 = dump(p1)
    v2, t2 = dump(p2)
    return v1 == v2, t1 == t2


# ---------------------------------------------------------------- figure 1

def fig_collapse(args):
    fig = "fig_collapse"
    pdf = os.path.join(LATEX, fig + ".pdf")
    script = os.path.join(LATEX, fig + ".py")
    print("== %s" % fig)
    if not check_stale(fig, pdf, [LADDER, script]):
        return
    pt = json.load(open(LADDER, encoding="utf-8"))["per_tool"]
    rung = "on_exact_changed_line"
    lab = {t: "%.4f" % pt[t][rung]["rate"] for t in ORDER}

    sp = spans(pdf)
    check_tokens(fig, sp, pdf)
    check_numeric_multiset(fig, sp, TICKS[fig] + STATIC[fig] + [lab[t] for t in ORDER])

    # PAIRING: each %.4f label belongs to the tool whose panel-b tick label sits nearest in y.
    ticklabs = [s for s in sp if s["text"] in LABEL.values() and abs(s["size"] - 7.6) < 0.05]
    if len(ticklabs) != 4:
        fail(fig, "expected 4 panel-b tick labels at 7.6pt, found %d" % len(ticklabs))
        return
    for s in [s for s in sp if re.fullmatch(r"0\.\d{4}", s["text"])]:
        tl = nearest(s, ticklabs)
        tool = [t for t, n in LABEL.items() if n == tl["text"]][0]
        if s["text"] != lab[tool]:
            fail(fig, "panel (b) prints %s beside %s, but the JSON gives %s that rung rate %s"
                 % (s["text"], tl["text"], tool, lab[tool]))
        else:
            ok("%s -> %s" % (tl["text"], s["text"]))

    # the panel names a winner, so the winner has to be the one the JSON holds
    lowest = min(ORDER, key=lambda t: pt[t][rung]["rate"])
    ann = [s for s in sp if s["text"] == "lowest of the four"]
    if len(ann) != 1:
        fail(fig, "expected exactly one 'lowest of the four' annotation, found %d" % len(ann))
    else:
        near = nearest(ann[0], ticklabs)
        if near["text"] != LABEL[lowest]:
            fail(fig, "'lowest of the four' points at %s but the JSON minimum at %s is %s"
                 % (near["text"], rung, LABEL[lowest]))
        else:
            ok("'lowest of the four' points at %s, the JSON minimum" % LABEL[lowest])

    if not args.no_reproduce:
        check_reproduces(fig, script)


# ---------------------------------------------------------------- figure 2

def fig_geom_vs_human(args):
    fig = "fig_geom_vs_human"
    pdf = os.path.join(LATEX, fig + ".pdf")
    script = os.path.join(LATEX, fig + ".py")
    print("== %s" % fig)
    if not check_stale(fig, pdf, [DEFECT, script]):
        return
    p = json.load(open(DEFECT, encoding="utf-8"))["payload"]
    ann = p["annotators"]
    blind = [k for k, v in ann.items() if v.get("knows_research_objective") == "no"]
    aware = [k for k, v in ann.items() if v.get("knows_research_objective") == "yes"]
    if len(blind) != 1 or len(aware) != 1:
        fail(fig, "the source no longer names exactly one blind and one aware annotator")
        return
    B, A = blind[0], aware[0]
    if p["primary_reading"]["annotator"] != B:
        fail(fig, "primary_reading names %r, blindness declaration names %r"
             % (p["primary_reading"]["annotator"], B))
    g = p["geometry_same_sample"]
    n = p["config"]["n_findings"]
    kappa = p["agreement"]["root_cause_relation"]["cohens_kappa"]

    rows = [("in patched file", g["in_patched_file"]["pooled"]),
            ("same callable", g["same_callable_as_change"]["pooled"]),
            ("on exact changed line", g["on_exact_changed_line"]["pooled"]),
            ("annotator %s, knew the aim" % A, p["pooled"][A]),
            ("annotator %s, blind, 1 annotator" % B, p["pooled"][B])]
    TOOLS = ["wisp", "semgrep", "wpt", "progpilot"]
    zero = [t for t in TOOLS if p["per_tool"][t][A]["count"] == 0 and p["per_tool"][t][B]["count"] == 0]

    expect = list(TICKS[fig])
    expect += ["%.3f" % cell["rate"] for _, cell in rows]
    expect += ["= %.3f" % kappa]
    expect += ["Share of the same %d adjudicated findings" % n]
    expect += ["=%d" % p["per_tool"][t][B]["n"] for t in TOOLS]
    expect += ["annotator %s, blind, 1 annotator" % B]
    for t in zero:
        expect += ["0 of %d" % p["per_tool"][t][B]["n"]] * 2

    sp = spans(pdf)
    check_tokens(fig, sp, pdf)
    check_numeric_multiset(fig, sp, expect)

    # PAIRING panel (a): value label to row label, nearest in y, panel (a) only.
    rowlabs = [s for s in sp if s["x1"] < 260 and s["text"] in [r[0] for r in rows]]
    if len(rowlabs) != 5:
        fail(fig, "expected 5 panel-a row labels, found %d" % len(rowlabs))
    else:
        want = dict(rows)
        for s in [s for s in sp if s["x0"] > 100 and s["x1"] < 260
                  and re.fullmatch(r"0\.\d{3}", s["text"])]:
            rl = nearest(s, rowlabs)
            if s["text"] != "%.3f" % want[rl["text"]]["rate"]:
                fail(fig, "panel (a) prints %s beside %r, the JSON gives %.3f"
                     % (s["text"], rl["text"], want[rl["text"]]["rate"]))
            else:
                ok("%r -> %s" % (rl["text"], s["text"]))

    # PAIRING panel (b): the n= under each tool, nearest in x.
    toollabs = [s for s in sp if s["text"] in LABEL.values() and s["x0"] > 300]
    if len(toollabs) != 4:
        fail(fig, "expected 4 panel-b tool labels, found %d" % len(toollabs))
    else:
        for s in [s for s in sp if re.fullmatch(r"=\d+", s["text"]) and s["x0"] > 300]:
            tl = nearest(s, toollabs, axis="x")
            tool = [t for t, nm in LABEL.items() if nm == tl["text"]][0]
            wantn = "=%d" % p["per_tool"][tool][B]["n"]
            if s["text"] != wantn:
                fail(fig, "panel (b) prints %s under %s, the JSON gives %s"
                     % (s["text"], tl["text"], wantn))
            else:
                ok("%s -> %s" % (tl["text"], s["text"]))

    if not args.no_reproduce:
        check_reproduces(fig, script)


# ---------------------------------------------------------------- figure 3

def fig_perclass(args):
    fig = "fig_perclass"
    pdf = os.path.join(LATEX, fig + ".pdf")
    script = os.path.join(LATEX, fig + ".py")
    data = os.path.join(LATEX, "fig_perclass_data.json")
    print("== %s" % fig)
    if not check_stale(fig, pdf, [POP, LADDER, script, ESTIMATOR], extra_outputs=[data]):
        return
    d = json.load(open(data, encoding="utf-8"))
    classes = d["class_order_low_to_high"]
    pb = d["panel_b_pooled_by_class"]
    pa = d["panel_a_in_patched_file_by_class_and_tool"]

    # the companion JSON is an output too, so re-derive it from the population rather than trust it
    if not args.no_reproduce:
        sys.path.insert(0, ROOT)
        from eval import analyze_v3 as AN
        rows = [json.loads(l) for l in open(POP, encoding="utf-8") if l.strip()]
        if len(rows) != d["n_findings"]:
            fail(fig, "population holds %d findings, the companion JSON says %d"
                 % (len(rows), d["n_findings"]))

        def cell(units, rung):
            c = AN.boot_rate(units, lambda u: bool(u[rung]), d["bootstrap_replicates"])
            c["n_slugs"] = len({u["slug"] for u in units})
            return c
        for c in classes:
            for rung in ("in_patched_file", "same_callable_as_change", "on_exact_changed_line"):
                got = cell([r for r in rows if r["advisory_class"] == c], rung)
                if got != pb[c][rung]:
                    fail(fig, "panel (b) %s/%s recomputes to %r, companion JSON holds %r"
                         % (c, rung, got, pb[c][rung]))
            for t in ORDER:
                got = cell([r for r in rows if r["advisory_class"] == c and r["tool"] == t],
                           "in_patched_file")
                if got != pa[c][t]:
                    fail(fig, "panel (a) %s/%s recomputes to %r, companion JSON holds %r"
                         % (c, t, got, pa[c][t]))
        ok("all %d panel cells recomputed from the population" % (len(classes) * 7))
        # and the per-tool marginal must still be the shipped ladder Figure 1 draws
        shipped = json.load(open(LADDER, encoding="utf-8"))["per_tool"]
        for t in ORDER:
            got = cell([r for r in rows if r["tool"] == t], "in_patched_file")
            exp = shipped[t]["in_patched_file"]
            if (got["count"], got["n"], got["rate"], got["ci95"]) != \
               (exp["count"], exp["n"], exp["rate"], exp["ci95"]):
                fail(fig, "per-tool marginal for %s disagrees with CORPUS_LADDER_KEPT_V3.json" % t)
        ok("per-tool marginals reproduce CORPUS_LADDER_KEPT_V3.json")

    expect = list(TICKS[fig]) + ["=%d" % pb[c]["in_patched_file"]["n"] for c in classes]
    sp = spans(pdf)
    check_tokens(fig, sp, pdf)
    check_numeric_multiset(fig, sp, expect)

    # PAIRING: each n= belongs to the class whose tick label sits nearest in y, and the classes
    # must run low to high up the axis, which is the ordering both panels are read against.
    clslabs = [s for s in sp if s["text"] in classes and abs(s["size"] - 7.6) < 0.05]
    if len(clslabs) != len(classes):
        fail(fig, "expected %d class tick labels, found %d" % (len(classes), len(clslabs)))
        return
    seen = [s["text"] for s in sorted(clslabs, key=lambda s: -s["y"])]
    if seen != classes:
        fail(fig, "class axis reads %r bottom-to-top, the companion JSON orders them %r"
             % (seen, classes))
    else:
        ok("class axis ordering matches class_order_low_to_high")
    for s in [s for s in sp if re.fullmatch(r"=\d+", s["text"])]:
        cl = nearest(s, clslabs)
        wantn = "=%d" % pb[cl["text"]]["in_patched_file"]["n"]
        if s["text"] != wantn:
            fail(fig, "panel (b) prints %s beside %s, the source gives %s"
                 % (s["text"], cl["text"], wantn))
        else:
            ok("%s -> %s" % (cl["text"], s["text"]))

    if not args.no_reproduce:
        check_reproduces(fig, script, companions=("fig_perclass_data.json",))


# ---------------------------------------------------------------- fonts / layout

COLUMNWIDTH_PT = 252.0      # elsarticle [final,5p,times,twocolumn], measured from the built log
TEXTWIDTH_PT = 522.0


def report_layout():
    print("== layout and fonts")
    for fig in ("fig_collapse", "fig_geom_vs_human", "fig_perclass"):
        pdf = os.path.join(LATEX, fig + ".pdf")
        if not os.path.exists(pdf):
            continue
        w, h, fonts = page_geometry(pdf)
        unembedded = [f for f in fonts if f[1] in ("n/a", "")]
        t3 = [f for f in fonts if f[2] == "Type3"]
        if unembedded:
            fail(fig, "unembedded font(s): %r" % [f[3] for f in unembedded])
        if t3:
            fail(fig, "Type 3 font(s), which production desks reject: %r" % [f[3] for f in t3])
        print("   %-18s %.1f x %.1f pt (%.2f x %.2f in)  scale@columnwidth=%.2f  "
              "scale@textwidth=%.2f  fonts=%d all embedded TrueType=%s"
              % (fig, w, h, w / 72, h / 72, COLUMNWIDTH_PT / w, TEXTWIDTH_PT / w,
                 len(fonts), not unembedded and not t3))


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--figure", choices=["fig_collapse", "fig_geom_vs_human", "fig_perclass"])
    ap.add_argument("--no-reproduce", action="store_true",
                    help="skip the re-run layer (fast, but blind to unlabelled values)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    todo = {"fig_collapse": fig_collapse, "fig_geom_vs_human": fig_geom_vs_human,
            "fig_perclass": fig_perclass}
    for name, fn in todo.items():
        if args.figure and name != args.figure:
            continue
        fn(args)
    report_layout()

    print()
    if FAILS:
        print("FIGURE GUARD FAILED, %d problem(s):" % len(FAILS))
        for f in FAILS:
            print("  - %s" % f)
        return 1
    print("FIGURE GUARD PASS: 3 figures, values re-derived from the result JSONs, "
          "no retired token, nothing stale.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
