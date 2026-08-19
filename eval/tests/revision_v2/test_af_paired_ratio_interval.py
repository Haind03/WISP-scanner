"""AF. The overstatement factor is a ratio, so its interval has to be built like one.

The paper's defect-level claim is a ratio of two rates. The numerator is the share of the 200 sampled
findings that land in a patched file. The denominator is the share the blind annotator called the
same defect. Until 2026-08-19 the interval shipped beside that ratio was built by holding the
numerator at its point estimate and dividing it by the two endpoints of the denominator's own
interval. That is a plug-in interval and it is wrong in two separate ways.

  1. It gives the numerator no uncertainty at all. The geometric rate is itself a sample statistic
     with an interval of its own, and pretending it is a constant understates the ratio's spread.
  2. Both rates are measured on the SAME 200 findings, so they are correlated. An interval built by
     combining a fixed number with the other rate's interval never sees that correlation, so its
     width is wrong in a direction that cannot be predicted from the point estimates.

The replacement resamples plugin slugs with replacement, which is the cluster every other interval
in this paper uses, and recomputes BOTH rates inside each replicate before taking the ratio. The
pairing survives because one draw feeds both.

These tests exist so the plug-in interval cannot come back. The dangerous version of that regression
is not someone deleting the new field. It is someone filling the new field from the old formula, or
rewriting the bootstrap so it resamples findings instead of slugs, or reseeding per replicate. Each
of those leaves a plausible number in place, so each is checked directly rather than by reading the
shipped value.

The last test in this module was expected to FAIL while the prose still cited the plug-in macros.
It passes as of 2026-08-19: the defect-study paragraph now prints the paired interval and the
abstract prints the factor without one, so no document carries the superseded endpoints.
"""
from __future__ import annotations
import os, json, re
import numpy as np
from . import _common as C

from eval import defect_study_result_v3 as DS
from eval.analyze_v3 import _slug_index

RESULT = os.path.join(C.SYS_ROOT, "revision-cns-v2", "out", "DEFECT_STUDY_RESULT_V3.json")
LATEX = os.path.join(C.SYS_ROOT, "2026-07-07", "latex")
MACROS = os.path.join(LATEX, "PAPER_MACROS_V3.tex")
MANIFEST = os.path.join(LATEX, "PAPER_MACROS_V3.manifest.json")
MAIN = os.path.join(LATEX, "WISP-paper-CnS-elsarticle.tex")
SUPP = os.path.join(LATEX, "WISP-paper-CnS-supplement.tex")

PAIRED = "paired_cluster_bootstrap_ci95"
PLUGIN = "from_rate_ci95"


def _shipped():
    if not os.path.isfile(RESULT):
        raise C.MissingInput("DEFECT_STUDY_RESULT_V3.json (run eval.defect_study_result_v3)")
    return json.load(open(RESULT, encoding="utf-8"))["payload"]


def _macros():
    if not os.path.isfile(MACROS):
        raise C.MissingInput("PAPER_MACROS_V3.tex (run eval.build_paper_macros_v3)")
    out = {}
    for line in open(MACROS, encoding="utf-8"):
        m = re.match(r"\\newcommand\{\\([A-Za-z]+)\}\{(.*)\}\s*$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _u(slug, num, den):
    """One analysis unit. Only the three fields the ratio bootstrap reads are needed."""
    return {"slug": slug, "num": num, "den": den}


def _plug_in_ci(units, num, den, reps=DS.REPS, seed=DS.SEED):
    """The superseded construction, reimplemented here so the tests can compare against it.

    It bootstraps the denominator rate alone, holds the numerator at its point estimate, and divides
    that constant by the denominator's endpoints. This is the thing that must never come back, so
    the suite carries its own copy rather than trusting a description of it.
    """
    slugs, idx = _slug_index(units)
    kn = np.zeros(len(slugs))
    kd = np.zeros(len(slugs))
    n = np.zeros(len(slugs))
    for u in units:
        i = idx[u["slug"]]
        n[i] += 1
        kn[i] += 1 if num(u) else 0
        kd[i] += 1 if den(u) else 0
    gf = kn.sum() / n.sum()
    rng = np.random.default_rng(seed)
    picks = rng.integers(0, len(slugs), size=(reps, len(slugs)))
    Ns = n[picks].sum(1)
    rates = np.divide(kd[picks].sum(1), Ns, out=np.full(reps, np.nan), where=Ns > 0)
    lo, hi = np.nanpercentile(rates, [2.5, 97.5])
    return [gf / hi, gf / lo]


def test_the_shipped_result_carries_a_paired_cluster_interval():
    """Both annotators, and the interval must declare its cluster, its replicates and its seed."""
    of = _shipped()["overstatement_factor"]
    ev = C.Evidence("AF.1 the shipped result carries a paired interval")
    for who in ("A", "B"):
        assert who in of, f"annotator {who} missing from overstatement_factor"
        pc = of[who].get(PAIRED)
        assert pc is not None, (
            f"annotator {who} has no {PAIRED}. The ratio's interval must come from a paired "
            f"bootstrap, not from the denominator's interval alone.")
        assert pc["cluster_unit"] == "plugin_slug", pc
        assert pc["replicates"] == DS.REPS, pc
        assert pc["seed"] == DS.SEED, pc
        assert pc["replicates_defined"] == pc["replicates"], (
            "some replicates drew no same-defect finding, so the ratio was undefined in them. "
            "That has to be reported, not averaged over.")
        assert of[who].get(PLUGIN) is not None, (
            f"the superseded {PLUGIN} was deleted for annotator {who}. It is the interval the "
            f"earlier prose quoted, and removing it erases that record.")
        ev.show(f"{who}: paired {pc['ci95']} over {pc['replicates_defined']}/{pc['replicates']} "
                f"replicates, seed {pc['seed']}, cluster {pc['cluster_unit']}, "
                f"superseded plug-in {of[who][PLUGIN]}")


def test_the_paired_interval_is_not_the_plug_in_interval():
    """The shipped interval must be a fresh paired bootstrap of the labels, and not the old formula.

    Two things are checked and both have to hold. First the interval is recomputed from the shipped
    anonymised label sheet through the production function and must come back identical, so a
    hand-written value cannot sit in the field. Second it must differ from the plug-in construction
    at the precision the paper prints, so a paired bootstrap that quietly reduces to the old formula
    is caught too. Only the labels are read here, never written.
    """
    p = _shipped()
    of = p["overstatement_factor"]
    gf = of["geometric_rate"]
    ev = C.Evidence("AF.2 the paired interval is a fresh paired bootstrap")
    if not os.path.isfile(DS.SHIPPED):
        raise C.MissingInput("defect-study/defect_study_labels.csv")
    units = DS._units_from_shipped()
    for who in ("A", "B"):
        again = DS.boot_ratio(units, lambda u: u["in_patched_file"],
                              lambda u, w=who: u[w]["root_cause_relation"] == "SAME_DEFECT")
        paired = of[who][PAIRED]["ci95"]
        assert again["ci95"] == paired, (
            f"annotator {who}: the shipped interval {paired} does not reproduce from the label "
            f"sheet, which gives {again['ci95']}. The field is not what the bootstrap computed.")

        rlo, rhi = p["pooled"][who]["ci95"]
        naive = [gf / rhi, gf / rlo]
        ev.show(f"{who}: paired [{paired[0]:.2f}, {paired[1]:.2f}] reproduced from the labels, "
                f"plug-in [{naive[0]:.2f}, {naive[1]:.2f}]")
        assert any(round(a, 1) != round(b, 1) for a, b in zip(paired, naive)), (
            f"annotator {who}: the paired interval {paired} prints as the plug-in interval "
            f"[{naive[0]:.2f}, {naive[1]:.2f}]. Either the numerator is still being held fixed or "
            f"the field was filled from the old formula.")


def test_a_paired_bootstrap_moves_the_numerator_too():
    """Drive both constructions on a population where the right answer is known by construction.

    Sixty plugins, four findings each, and the same denominator pattern in both halves of the test.
    In the first population half the plugins carry the numerator event on every finding and half on
    none, so resampling slugs moves the numerator a great deal. A construction that holds the
    numerator at its point estimate cannot see any of that, so it must come back visibly narrower.
    The second population differs in one respect only: the numerator event is spread evenly over
    every plugin, so resampling slugs cannot move it. There the two constructions must nearly
    coincide. Together they pin the difference on resampling the numerator rather than on some
    unrelated gap between the two implementations.
    """
    ev = C.Evidence("AF.3 a paired bootstrap moves the numerator too")
    num = lambda u: u["num"]
    den = lambda u: u["den"]
    # the denominator event: one finding per plugin, plus a second on every fourth plugin, so the
    # denominator carries real between-plugin variance in both populations
    dn = lambda i, j: j == 0 or (i % 4 == 0 and j == 1)

    varying = [_u(f"s{i}", num=(i < 30), den=dn(i, j)) for i in range(60) for j in range(4)]
    paired = DS.boot_ratio(varying, num, den)["ci95"]
    naive = _plug_in_ci(varying, num, den)
    wp, wn = paired[1] - paired[0], naive[1] - naive[0]
    ev.show(f"numerator varies: paired [{paired[0]:.3f}, {paired[1]:.3f}] width {wp:.3f}   "
            f"plug-in [{naive[0]:.3f}, {naive[1]:.3f}] width {wn:.3f}")
    assert wn > 0, ("the plug-in interval came back with no width at all, which would make the "
                    "comparison below vacuous rather than informative.")
    assert wp > wn * 1.5, (
        f"the paired interval ({wp:.3f}) is not meaningfully wider than the plug-in one ({wn:.3f}) "
        f"on a population built so the numerator carries most of the variance. The numerator is "
        f"not being resampled.")

    # control: same denominator, numerator now flat across plugins, so the two must nearly coincide
    flat = [_u(f"s{i}", num=(j < 2), den=dn(i, j)) for i in range(60) for j in range(4)]
    fp = DS.boot_ratio(flat, num, den)["ci95"]
    fn = _plug_in_ci(flat, num, den)
    ev.show(f"numerator flat: paired [{fp[0]:.3f}, {fp[1]:.3f}] width {fp[1] - fp[0]:.3f}   "
            f"plug-in [{fn[0]:.3f}, {fn[1]:.3f}] width {fn[1] - fn[0]:.3f}")
    assert abs((fp[1] - fp[0]) - (fn[1] - fn[0])) < 0.25 * (fn[1] - fn[0]), (
        f"with a flat numerator the two constructions should nearly agree, but they gave "
        f"{fp} and [{fn[0]:.3f}, {fn[1]:.3f}]. The difference in the first half of this test is "
        f"then not attributable to resampling the numerator.")


def test_the_ratio_bootstrap_follows_the_house_draw():
    """The interval has to be comparable to every other interval in the paper, so the draw must be
    the house draw: clusters indexed by eval.analyze_v3._slug_index, one integers() call of shape
    (replicates, n_clusters) from numpy default_rng at the module seed, percentiles at 2.5 and 97.5.

    Reproducing it by hand pins all of that at once. A version that resampled findings, reseeded per
    replicate, drew a different shape, or fell back to holding the numerator fixed would not land on
    the same numbers, so the population is built with a numerator that varies across plugins.
    """
    ev = C.Evidence("AF.4 the ratio bootstrap follows the house draw")
    units = [_u(f"s{i}", num=(i < 25), den=(j == 0 and i % 3 == 0))
             for i in range(40) for j in range(5)]
    num = lambda u: u["num"]
    den = lambda u: u["den"]

    slugs, idx = _slug_index(units)
    kn = np.zeros(len(slugs))
    kd = np.zeros(len(slugs))
    for u in units:
        i = idx[u["slug"]]
        kn[i] += 1 if num(u) else 0
        kd[i] += 1 if den(u) else 0
    rng = np.random.default_rng(DS.SEED)
    picks = rng.integers(0, len(slugs), size=(DS.REPS, len(slugs)))
    Kn, Kd = kn[picks].sum(1), kd[picks].sum(1)
    ok = Kd > 0
    ratios = np.divide(Kn, Kd, out=np.full(DS.REPS, np.nan), where=ok)
    want = [round(float(x), 2) for x in np.nanpercentile(ratios, [2.5, 97.5])]

    got = DS.boot_ratio(units, num, den)
    ev.show(f"hand-rolled house draw {want}   boot_ratio {got['ci95']}")
    assert got["ci95"] == want, (
        f"boot_ratio gave {got['ci95']} where the house draw gives {want}. The cluster, the seed, "
        f"the draw shape or the percentiles differ from every other interval in this paper.")
    assert got["replicates_defined"] == int(ok.sum()), got

    # the same call twice must agree, because a fixed seed is the whole point
    assert DS.boot_ratio(units, num, den)["ci95"] == got["ci95"], "the interval is not reproducible"


def test_the_reported_macros_point_at_the_paired_interval():
    """The macros a sentence can cite must carry the paired interval, and each must be traceable to
    the paired JSON pointer. The plug-in macros stay defined, so the test also demands the two
    families hold different numbers rather than checking only that a name exists."""
    if not os.path.isfile(MANIFEST):
        raise C.MissingInput("PAPER_MACROS_V3.manifest.json (run eval.build_paper_macros_v3)")
    mac = _macros()
    man = json.load(open(MANIFEST, encoding="utf-8"))["macros"]
    of = _shipped()["overstatement_factor"]
    ev = C.Evidence("AF.5 the reported macros point at the paired interval")
    for who in ("A", "B"):
        pc = of[who][PAIRED]["ci95"]
        for end, want in (("Lo", pc[0]), ("Hi", pc[1])):
            name = f"DsFactor{who}Paired{end}"
            assert name in mac, f"\\{name} is not defined in PAPER_MACROS_V3.tex"
            assert mac[name] == f"{want:.1f}", (
                f"\\{name} = {mac[name]} but the paired interval endpoint is {want}")
            ptr = man[name]["pointer"]
            assert PAIRED in ptr, (
                f"\\{name} traces to {ptr!r}, which is not the paired interval. Every macro has to "
                f"name the JSON field it came from, and this one names the wrong field.")
        old = [mac.get(f"DsFactor{who}Lo"), mac.get(f"DsFactor{who}Hi")]
        new = [mac[f"DsFactor{who}Paired{e}"] for e in ("Lo", "Hi")]
        ev.show(f"{who}: paired macros {new}   plug-in macros {old}")
        assert None not in old, (
            f"the plug-in macros for annotator {who} were deleted. They are what the earlier prose "
            f"printed and the record of it has to survive.")
        assert old != new, (
            f"annotator {who}: the paired macros carry the same numbers as the plug-in ones, so a "
            f"sentence citing either is citing the plug-in interval.")
    assert mac.get("DsFactorBootReps") == f"{of['B'][PAIRED]['replicates']:,}", mac.get("DsFactorBootReps")
    assert mac.get("DsFactorBootSeed") == str(of["B"][PAIRED]["seed"]), mac.get("DsFactorBootSeed")


def test_the_corrected_interval_still_excludes_one():
    """A ratio interval that covers 1.0 would mean the overstatement is not established at all.

    The corrected interval does not cover it, and this test is here so that if a future relabelling
    or a wider bootstrap ever pushes it across, the build says so instead of the paper going on
    asserting a factor whose interval contains no effect.
    """
    of = _shipped()["overstatement_factor"]
    ev = C.Evidence("AF.6 the corrected interval still excludes 1.0")
    for who in ("A", "B"):
        pc = of[who][PAIRED]
        ev.show(f"{who}: {pc['ci95']}   share of replicates at or below 1.0 "
                f"{pc['share_at_or_below_one']}")
        assert pc["ci95"][0] > 1.0, (
            f"annotator {who}: the paired interval {pc['ci95']} reaches 1.0 or below. The paper "
            f"claims a patch-file endpoint overstates defect identification, and an interval that "
            f"covers 1.0 does not establish that claim.")


def test_the_documents_cite_the_paired_interval():
    """The manuscript and the supplement must not print the plug-in endpoints.

    Both documents are owned by the prose side of this revision, so the correction is not finished
    until \\DsFactorBLo and \\DsFactorBHi are replaced by \\DsFactorBPairedLo and
    \\DsFactorBPairedHi wherever the interval is printed. Until that happens the number a reader
    sees is still the plug-in one, and this test records that rather than letting a green suite
    imply otherwise.
    """
    ev = C.Evidence("AF.7 the documents cite the paired interval")
    bad = []
    for label, path in (("manuscript", MAIN), ("supplement", SUPP)):
        if not os.path.isfile(path):
            raise C.MissingInput(os.path.basename(path))
        txt = open(path, encoding="utf-8").read()
        for name in ("DsFactorALo", "DsFactorAHi", "DsFactorBLo", "DsFactorBHi"):
            n = len(re.findall(r"\\" + name + r"(?![A-Za-z])", txt))
            if n:
                bad.append(f"{label} prints \\{name} {n} time(s)")
    for b in bad:
        ev.show(b)
    assert not bad, ("the plug-in interval is still what the documents print: " + ", ".join(bad)
                     + ". Replace it with the \\DsFactor*Paired* macros.")
