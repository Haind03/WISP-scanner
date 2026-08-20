#!/usr/bin/env python3
"""Generate the complete LaTeX macro set for the v3 manuscript from the result JSONs (Prompt 7/10).

Every primary number in the paper comes from a macro defined here, and every macro is derived from a
result JSON, so no headline is typed by hand. This emits two files into the manuscript's latex dir:

  LATEX_MACROS_V3.tex  a verbatim copy of eval/analyze_v3.py's primary-ladder macros (the named file
                       the manuscript includes), and
  PAPER_MACROS_V3.tex  which \\input{LATEX_MACROS_V3.tex} and then defines the additional macros the
                       new tables and abstract need (raw counts, conditional transitions, agreement,
                       baseline, corpus, ablation).

It also writes PAPER_MACROS_V3.manifest.json mapping every macro to (value, json_file, json_pointer)
so check_paper_macros_v3.py can re-derive each value from the JSON and fail the build on any mismatch.

    python3 -m eval.build_paper_macros_v3
"""
from __future__ import annotations
import os, sys, json, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYS_ROOT = os.path.dirname(ROOT)
OUT = os.path.join(SYS_ROOT, "revision-cns-v2", "out")
LATEX = os.path.join(SYS_ROOT, "2026-07-07", "latex")


def load(name):
    return json.load(open(os.path.join(OUT, name)))


def r4(x):
    return f"{x:.4f}"


def r3(x):
    return f"{x:.3f}"


def r2(x):
    return f"{x:.2f}"


# macro name -> (formatted value, source json file, human pointer, raw value)
MACROS: dict[str, tuple] = {}


def add(name, value, src, pointer):
    MACROS[name] = (value, src, pointer)


def build():
    g = load("GEOMETRIC_LADDER_V3.json")
    b = load("BASELINE_MATCHED100_V3.json")
    sn = load("SANI_ABLATION_V3.json")

    # Progpilot belongs here now. It was left out while the exit-code defect made it look like a
    # tool that emits nothing, and tab:ladder printed "returns no findings" over a row that also
    # printed its finding count.
    TOOLS = {"wisp": "Wisp", "semgrep": "Semgrep", "wpt": "Wpt", "progpilot": "Progpilot"}
    GF = "GEOMETRIC_LADDER_V3.json"

    # corpus + population
    add("NAdvisories", "1108", GF, "fixed corpus size")
    add("NPlugins", "854", GF, "fixed slug count")
    add("NRecordsMatched", str(g["n_records_matched"]), GF, "n_records_matched")
    add("NRecordsAnswered", str(g["pooled"]["n_answered_records"]), GF, "pooled.n_answered_records")
    add("NFindingsPooled", str(g["pooled"]["n_findings"]), GF, "pooled.n_findings")
    # The bootstrap seed, printed rather than described. The manuscript said "seed 42", which is the
    # sampling seed for drawing the matched 100 and not the resampling seed any interval was built
    # with. A reader following the paper reproduced nothing. It is a macro now so the two cannot
    # drift apart again.
    add("BootSeed", str(g["seed"]), GF, "seed")

    # geometric ladder, per tool: findings, counts and rates and CI for each rung
    rungs = [("InPatchedFile", "in_patched_file"),
             ("SameCallable", "same_callable_as_change"),
             ("ExactChangedLine", "on_exact_changed_line"),
             ("ProxFive", "within_5_changed_lines"),
             ("SameDiffHunk", "same_diff_hunk")]
    for tk, Tc in TOOLS.items():
        pt = g["per_tool"][tk]
        add(f"{Tc}Findings", str(pt["n_findings"]), GF, f"per_tool.{tk}.n_findings")
        add(f"{Tc}AnsweredRecords", str(pt["n_answered_records"]), GF,
            f"per_tool.{tk}.n_answered_records")
        for mk, jk in rungs:
            r = pt[jk]
            add(f"{Tc}{mk}N", str(r["count"]), GF, f"per_tool.{tk}.{jk}.count")
            add(f"{Tc}{mk}D", str(r["n"]), GF, f"per_tool.{tk}.{jk}.n")
            add(f"{Tc}{mk}Rate", r3(r["rate"]), GF, f"per_tool.{tk}.{jk}.rate")
            add(f"{Tc}{mk}Lo", r3(r["ci95"][0]), GF, f"per_tool.{tk}.{jk}.ci95[0]")
            add(f"{Tc}{mk}Hi", r3(r["ci95"][1]), GF, f"per_tool.{tk}.{jk}.ci95[1]")
        # primary effect: file -> exact drop
        de = g["primary_effect"][tk]["drop_to_exact_changed_line"]
        add(f"{Tc}DropToExact", r3(de["diff"]), GF, f"primary_effect.{tk}.drop_to_exact_changed_line.diff")
        add(f"{Tc}DropToExactLo", r3(de["ci95"][0]), GF, f"primary_effect.{tk}.drop_to_exact_changed_line.ci95[0]")
        add(f"{Tc}DropToExactHi", r3(de["ci95"][1]), GF, f"primary_effect.{tk}.drop_to_exact_changed_line.ci95[1]")
        # conditional P(within_5 | patched_file) and P(exact | patched_file)
        ct = g["conditional_transition"][tk]
        cp = ct["P(within_5_changed_lines|patched_file)"]
        add(f"{Tc}CondProxFile", r3(cp["rate"]), GF, f"conditional_transition.{tk}.P(within_5|file).rate")
        add(f"{Tc}CondProxFileN", str(cp["count"]), GF, f"conditional_transition.{tk}.P(within_5|file).count")
        add(f"{Tc}CondProxFileD", str(cp["n"]), GF, f"conditional_transition.{tk}.P(within_5|file).n")
        ce = ct["P(on_exact_changed_line|patched_file)"]
        add(f"{Tc}CondExactFile", r3(ce["rate"]), GF, f"conditional_transition.{tk}.P(exact|file).rate")
        # nested ratio (secondary)
        nr = g["nested_ratio"][tk]
        add(f"{Tc}NestedRatio", f"{nr['ratio']:.2f}", GF, f"nested_ratio.{tk}.ratio")
        add(f"{Tc}NestedNum", str(nr["numerator_count"]), GF, f"nested_ratio.{tk}.numerator_count")
        add(f"{Tc}NestedDen", str(nr["denominator_count"]), GF, f"nested_ratio.{tk}.denominator_count")

    # baseline fair matrix pf@1 by budget (failure-as-miss)
    BF = "BASELINE_MATCHED100_V3.json"
    budword = {25: "TwentyFive", 60: "Sixty", 300: "ThreeHundred"}
    for bud, word in budword.items():
        for tk, Tc in (("wisp", "Wisp"), ("wpt", "Wpt"), ("semgrep", "Semgrep"), ("progpilot", "Progpilot")):
            cell = b["pf1_bootstrap_ci"].get(f"{tk}@{bud}")
            if cell:
                add(f"{Tc}PfOneAt{word}", r3(cell["point"]), BF, f"pf1_bootstrap_ci.{tk}@{bud}.point")
                add(f"{Tc}PfOneAt{word}Lo", r3(cell["ci95"][0]), BF, f"pf1_bootstrap_ci.{tk}@{bud}.ci95[0]")
                add(f"{Tc}PfOneAt{word}Hi", r3(cell["ci95"][1]), BF, f"pf1_bootstrap_ci.{tk}@{bud}.ci95[1]")

    # sanitizer ablation (paired-completed primary)
    NF = "SANI_ABLATION_V3.json"
    pc = sn["paired_completed_PRIMARY"]
    add("SaniClassEmissionDelta", r3(pc["class_emission_delta_on_minus_off"]), NF,
        "paired_completed_PRIMARY.class_emission_delta_on_minus_off")
    add("SaniPfOneDelta", r3(pc["patch_file_success_at_1_delta_on_minus_off"]), NF,
        "paired_completed_PRIMARY.patch_file_success_at_1_delta_on_minus_off")
    add("SaniPairedN", str(pc["n_paired"]), NF, "paired_completed_PRIMARY.n_paired")

    # convergence / cap-sensitivity (depth-bounded fixpoint characterization)
    cv = load("CONVERGENCE_SENSITIVITY_V3.json")
    CV = "CONVERGENCE_SENSITIVITY_V3.json"
    cc = cv["corpus_at_contract_cap"]
    # These three describe the SHIPPED engine wherever the manuscript prints them, so they must come
    # from the v1.3 census. CONVERGENCE_SENSITIVITY_V3.json is the v1.2 experiment and its corpus
    # block is the v1.2 census, so leaving them here would have printed 272 of 1108 in the same
    # paragraph that prints \FcNonConv, which rebuilds from the v1.3 corpus analysis and reads 8.
    _dc_path = os.path.join(OUT, "CONVERGENCE_DECOMPOSITION_V3.json")
    if os.path.isfile(_dc_path):
        _DC = "CONVERGENCE_DECOMPOSITION_V3.json"
        _c13 = load(_DC)["corpus"]["v13"]
        add("CorpusConvN", str(_c13["n"]), _DC, "corpus.v13.n")
        add("CorpusNonConv", str(_c13["non_converged"]), _DC, "corpus.v13.non_converged")
        add("CorpusNonConvRate", r3(_c13["non_converged_rate"]), _DC,
            "corpus.v13.non_converged_rate")
    else:
        add("CorpusConvN", str(cc["n"]), CV, "corpus_at_contract_cap.n")
        add("CorpusNonConv", str(cc["non_converged"]), CV, "corpus_at_contract_cap.non_converged")
        add("CorpusNonConvRate", r3(cc["non_converged_rate"]), CV,
            "corpus_at_contract_cap.non_converged_rate")
    xt = cv["matched_sample_cross_tab"]
    add("MatchedConvN", str(xt["n"]), CV, "matched_sample_cross_tab.n")
    add("NonConvCapFour", str(xt["non_converged_cap4"]), CV, "matched_sample_cross_tab.non_converged_cap4")
    add("NonConvCapThirtyTwo", str(xt["non_converged_cap32"]), CV,
        "matched_sample_cross_tab.non_converged_cap32")
    add("ConvRecovered", str(xt["recovered_cap4_nc_to_cap32_conv"]), CV,
        "matched_sample_cross_tab.recovered_cap4_nc_to_cap32_conv")
    add("ConvRegressed", str(xt["regressed_cap4_conv_to_cap32_nc"]), CV,
        "matched_sample_cross_tab.regressed_cap4_conv_to_cap32_nc")
    add("ConvOscillating", str(xt["oscillating_non_converged_at_both"]), CV,
        "matched_sample_cross_tab.oscillating_non_converged_at_both")
    # The corpus figure must separate cap-bound non-convergence from a killed run: the two
    # were folded together and the manuscript then reported 294 records as failing to reach a
    # fixpoint "within the stabilization caps" when 120 of them were simply timed out.
    if "unknown_status_timeout" in cc:
        add("CorpusUnknownStatus", str(cc["unknown_status_timeout"]), CV,
            "corpus_at_contract_cap.unknown_status_timeout")
        add("CorpusKnownStatusN", str(cc["n_with_known_status"]), CV,
            "corpus_at_contract_cap.n_with_known_status")
        if cc.get("non_converged_rate_over_known_status") is not None:
            add("CorpusNonConvRateKnown", r3(cc["non_converged_rate_over_known_status"]), CV,
                "corpus_at_contract_cap.non_converged_rate_over_known_status")
    add("SensitivityPerKeyCap", str(cv["sensitivity_per_key_cap"]), CV, "sensitivity_per_key_cap")

    # v1.3 attribution. Until 2026-08-13 \ContractPerKeyCap read CONVERGENCE_SENSITIVITY_V3.json's
    # contract_per_key_cap, which is the constant 4 that script was written around. That file
    # describes a historical cap-4-versus-cap-32 experiment on the v1.2 engine, so after the v1.3
    # adoption its "contract cap" is the baseline cap and not the shipped one, and the manuscript
    # sentence bounding rebuilds per definition would have printed 4 for an engine that allows 32.
    # Both caps now come from the decomposition, which names the configuration each belongs to.
    dc_path = os.path.join(OUT, "CONVERGENCE_DECOMPOSITION_V3.json")
    if os.path.isfile(dc_path):
        DC = "CONVERGENCE_DECOMPOSITION_V3.json"
        dc = load(DC)
        add("ContractPerKeyCap", str(dc["arms"]["C"]["per_key_cap"]), DC, "arms.C.per_key_cap")
        add("BaselinePerKeyCap", str(dc["arms"]["A"]["per_key_cap"]), DC, "arms.A.per_key_cap")
        at = dc["attribution"]
        add("DecompN", str(dc["n_records"]), DC, "n_records")
        add("DecompNcBaseline", str(at["non_converged_A"]), DC, "attribution.non_converged_A")
        add("DecompNcCapOnly", str(at["non_converged_B"]), DC, "attribution.non_converged_B")
        add("DecompNcShipped", str(at["non_converged_C"]), DC, "attribution.non_converged_C")
        add("DecompRescuedByCap", str(at["rescued_by_cap_alone"]), DC,
            "attribution.rescued_by_cap_alone")
        add("DecompRescuedByProps", str(at["rescued_by_monotone_after_cap"]), DC,
            "attribution.rescued_by_monotone_after_cap")
        oc = dc["oscillating_correction"]
        add("ConvOscillatingReal", str(oc["genuine_oscillation"]), DC,
            "oscillating_correction.genuine_oscillation")
        add("ConvOscillatingTimeout", str(oc["timed_out_at_cap32_not_oscillating"]), DC,
            "oscillating_correction.timed_out_at_cap32_not_oscillating")
        rs = dc["corpus"].get("v13_residual")
        if rs:
            add("ResidualNonConvPlugins", str(rs["n_plugins"]), DC, "corpus.v13_residual.n_plugins")
    else:
        add("ContractPerKeyCap", str(cv["contract_per_key_cap"]), CV, "contract_per_key_cap")

    # The v1.2-versus-v1.3 comparison itself, which is what licenses calling the change a
    # convergence fix rather than a different analysis. Two independent sources: the census, and
    # the corpus localization shards the macros are actually built from.
    md_path = os.path.join(OUT, "MONOTONE_PROPS_DIFF_V3.json")
    if os.path.isfile(md_path):
        MD = "MONOTONE_PROPS_DIFF_V3.json"
        md = load(MD)
        add("EngineRescued", str(md["convergence"]["rescued"]), MD, "convergence.rescued")
        add("EngineLost", str(md["convergence"]["lost"]), MD, "convergence.lost")
        sc = md["stability_check"]
        add("EngineBothConverged", str(sc["n_records_converged_in_both"]), MD,
            "stability_check.n_records_converged_in_both")
        add("EngineStableFindings", f'{sc["findings_base"]:,}'.replace(",", "{,}"), MD,
            "stability_check.findings_base")
    ls_path = os.path.join(OUT, "LOC_SHARD_DIFF_V3.json")
    if os.path.isfile(ls_path):
        LS = "LOC_SHARD_DIFF_V3.json"
        ls = load(LS)
        add("LocChanged", str(ls["n_changed_any_field"]), LS, "n_changed_any_field")
        add("LocChangedOutsideRescued", str(ls["n_changed_outside_the_rescued_set"]), LS,
            "n_changed_outside_the_rescued_set")
        add("LocRescuedUnchanged", str(ls["n_rescued_that_did_not_change"]), LS,
            "n_rescued_that_did_not_change")

    # patch-shape census (contract s2: how much of the exact-line denominator is
    # structurally unhittable, because the patch only inserts or the file was deleted)
    psc_path = os.path.join(OUT, "PATCH_SHAPE_CENSUS_V3.json")
    if os.path.isfile(psc_path):
        ps = load("PATCH_SHAPE_CENSUS_V3.json")
        PS = "PATCH_SHAPE_CENSUS_V3.json"
        for ds, pre in (("matched-100", "ShapeMatched"), ("full-1108", "ShapeCorpus"),
                        ("wordfence-100", "ShapeWordfence"), ("testset-325", "ShapeTestset")):
            d = (ps.get("datasets") or {}).get(ds)
            if not d:
                continue
            add(pre + "N", str(d["n_scored"]), PS, f"datasets.{ds}.n_scored")
            add(pre + "NoTarget", str(d["records_with_no_exact_line_target"]), PS,
                f"datasets.{ds}.records_with_no_exact_line_target")
            if d.get("records_with_no_exact_line_target_rate") is not None:
                add(pre + "NoTargetRate", r3(d["records_with_no_exact_line_target_rate"]), PS,
                    f"datasets.{ds}.records_with_no_exact_line_target_rate")
            fp = d.get("php_files") or {}
            if fp:
                add(pre + "Files", str(fp["scored"]), PS, f"datasets.{ds}.php_files.scored")
                add(pre + "FilesDeleted", str(fp["deleted"]), PS, f"datasets.{ds}.php_files.deleted")
                add(pre + "FilesPureIns", str(fp["pure_insertion"]), PS,
                    f"datasets.{ds}.php_files.pure_insertion")
                add(pre + "FilesUnanchorable", str(fp["deleted"] + fp["pure_insertion"]), PS,
                    f"datasets.{ds}.php_files.deleted + pure_insertion")
                add(pre + "FilesUnanchorableRate",
                    r3((fp["deleted"] + fp["pure_insertion"]) / fp["scored"]) if fp["scored"] else "0",
                    PS, f"datasets.{ds}.php_files (deleted+pure_insertion)/scored")
            for cat, suf in (("has-deleted", "Deleted"), ("has-pure-insertion", "PureIns"),
                             ("modified-only", "ModOnly"), ("has-rename", "Rename")):
                if cat in (d.get("categories") or {}):
                    add(pre + suf, str(d["categories"][cat]), PS,
                        f"datasets.{ds}.categories.{cat}")
        sens = ps.get("exact_line_sensitivity_matched_100") or {}
        base = (sens.get("all_records") or {}).get("wisp") or {}
        # The record-level arm is a near no-op (almost every record has SOME anchorable file);
        # the arm that measures the endpoint's ceiling is finding-level.
        drop = (sens.get("drop_findings_in_unanchorable_files") or {}).get("wisp") or {}
        share = sens.get("unanchorable_file_share") or {}
        if share:
            add("UnanchorableInFile", str(share["n_in_unanchorable_file"]), PS,
                "exact_line_sensitivity_matched_100.unanchorable_file_share.n_in_unanchorable_file")
            add("UnanchorableInFileD", str(share["n_in_patched_file"]), PS,
                "exact_line_sensitivity_matched_100.unanchorable_file_share.n_in_patched_file")
            add("UnanchorableShare", r3(share["share_of_in_file_findings"]), PS,
                "exact_line_sensitivity_matched_100.unanchorable_file_share."
                "share_of_in_file_findings")
        if base and drop:
            add("ExactAllRecords", r3(base["on_exact_changed_line"]["rate"]), PS,
                "exact_line_sensitivity_matched_100.all_records.wisp.on_exact_changed_line.rate")
            add("ExactTargetOnly", r3(drop["on_exact_changed_line"]["rate"]), PS,
                "exact_line_sensitivity_matched_100.drop_findings_in_unanchorable_files."
                "wisp.on_exact_changed_line.rate")
            for arm, mac in (("drop_records_with_any_deleted_php_file", "ExactDropDeleted"),
                             ("drop_records_with_any_pure_insertion_php_file", "ExactDropPureIns")):
                w = (sens.get(arm) or {}).get("wisp") or {}
                if w:
                    add(mac, r3(w["on_exact_changed_line"]["rate"]), PS,
                        f"exact_line_sensitivity_matched_100.{arm}.wisp.on_exact_changed_line.rate")
            add("ExactTargetOnlyN", str(drop["n_findings"]), PS,
                "exact_line_sensitivity_matched_100.drop_findings_in_unanchorable_files."
                "wisp.n_findings")
            # The same two rates for wp-taint-scan, because the reviewer's objection is about
            # taint tools and one tool's before/after cannot answer it. WISP moves 0.055 -> 0.057
            # and wp-taint-scan 0.051 -> 0.057, so the gap between the two taint tools at this
            # rung is patch shape, not analysis.
            wpt_all = (sens.get("all_records") or {}).get("wpt") or {}
            wpt_drop = (sens.get("drop_findings_in_unanchorable_files") or {}).get("wpt") or {}
            if wpt_all and wpt_drop:
                add("ExactAllRecordsWpt", r3(wpt_all["on_exact_changed_line"]["rate"]), PS,
                    "exact_line_sensitivity_matched_100.all_records.wpt.on_exact_changed_line.rate")
                add("ExactTargetOnlyWpt", r3(wpt_drop["on_exact_changed_line"]["rate"]), PS,
                    "exact_line_sensitivity_matched_100.drop_findings_in_unanchorable_files."
                    "wpt.on_exact_changed_line.rate")

    # Per-tool split of the unanchorable-file share. Derived from the census and the finding
    # population by eval/unanchorable_per_tool_v3.py, which refuses to write unless it first
    # reproduces the pooled figures the census publishes.
    up_p = os.path.join(OUT, "UNANCHORABLE_PER_TOOL_V3.json")
    if os.path.isfile(up_p):
        UP = "UNANCHORABLE_PER_TOOL_V3.json"
        up = load(UP)
        for t, nm in TOOLS.items():
            v = (up.get("per_tool") or {}).get(t)
            if not v:
                continue
            add(f"Unanch{nm}D", str(v["n_in_patched_file"]), UP,
                f"per_tool.{t}.n_in_patched_file")
            add(f"Unanch{nm}N", str(v["n_in_unanchorable_file"]), UP,
                f"per_tool.{t}.n_in_unanchorable_file")
            add(f"Unanch{nm}Share", r3(v["share_of_in_file_findings"]), UP,
                f"per_tool.{t}.share_of_in_file_findings")
        if (up.get("spread") or {}).get("ratio_highest_to_lowest"):
            add("UnanchSpreadRatio", r2(up["spread"]["ratio_highest_to_lowest"]), UP,
                "spread.ratio_highest_to_lowest")

    # how many records the exit-code check threw away, from the shipped pre-fix run itself
    broken = os.path.join(SYS_ROOT, "final", "supplementary-data", "reproduce", "data",
                          "matched_100_baselines_final.json")
    if os.path.isfile(broken):
        det = json.load(open(broken))["details"]
        n_disc = sum(1 for r in det
                     if str(((r.get("progpilot") or {}).get("err") or "")).startswith("nonzero_exit"))
        add("ProgpilotDiscarded", str(n_disc),
            "final/supplementary-data/reproduce/data/matched_100_baselines_final.json",
            "count(details[].progpilot.err startswith 'nonzero_exit')")

    # paired family, incl. the exact-changed-line endpoint the contract requires (s7)
    pf_path = os.path.join(OUT, "PAIRED_FAMILY_V3.json")
    if os.path.isfile(pf_path):
        pf = load("PAIRED_FAMILY_V3.json")
        PF = "PAIRED_FAMILY_V3.json"
        fam = pf["family"]
        add("FamilySize", str(fam["size"]), PF, "family.size")
        add("FamilySurvive", str(fam["survive_holm"]), PF, "family.survive_holm")
        add("FamilyFail", str(fam["size"] - fam["survive_holm"]), PF,
            "family.size - family.survive_holm")
        # Count the endpoints that are actually in the corrected family, not every endpoint the
        # run scored. point_estimates carries 8 diagnostic endpoints that the family excludes, so
        # this macro printed 21 and the sentence around it read "3 baselines x 21 endpoints" for a
        # family of 39. The family's own comparison keys are the only honest denominator.
        add("FamilyEndpoints", str(len({r["endpoint"] for r in pf["comparisons"].values()})), PF,
            "distinct endpoints in comparisons (the corrected family, not the diagnostics)")
        add("FamilyBaselines", str(len(pf["baselines_present"])), PF, "len(baselines_present)")

        # Per-baseline survivor counts. Two supplement passages and a cover-letter paragraph said
        # "all of them against Progpilot" beside \FamilySurvive, which was true at 8 survivors under
        # wisp-scanner-v1.2 and false at 20 under v1.3, where the survivors span all three baselines.
        # The number was macro-driven and the sentence beside it was not, so the two drifted apart.
        # Driving the breakdown from the same JSON is what stops the sentence being hand-maintained.
        _surv = [r for r in pf["comparisons"].values() if r.get("survives_holm")]
        for _b, _label in (("progpilot", "Progpilot"), ("semgrep", "Semgrep"), ("wpt", "Wpt")):
            add("FamilySurv" + _label, str(sum(1 for r in _surv if r["baseline"] == _b)), PF,
                f"count of comparisons with survives_holm and baseline == {_b!r}")
        add("FamilySurvBaselines", str(len({r["baseline"] for r in _surv})), PF,
            "distinct baselines among the surviving comparisons")

        # tab:localize and tab:clusterp are rewritten from this one source. The class-and-file
        # cells previously printed came from the 2026-07-17 cls='other' run; driving them from
        # macros is what makes a repeat impossible.
        TOOLNAME = {"wisp": "Wisp", "semgrep": "Semgrep", "progpilot": "Progpilot", "wpt": "Wpt"}
        KWORD = {"1": "One", "3": "Three", "5": "Five", "10": "Ten"}
        for tool, tn in TOOLNAME.items():
            pe = pf["point_estimates"].get(tool)
            if not pe:
                continue
            add(f"Loc{tn}Class", r3(pe["class"]), PF, f"point_estimates.{tool}.class")
            for K, kw in KWORD.items():
                for src, mac in (("cfn", "Cfn"), ("cprox", "Cprox")):
                    if f"{src}@{K}" in pe:
                        add(f"Loc{tn}{mac}{kw}", r3(pe[f"{src}@{K}"]), PF,
                            f"point_estimates.{tool}.{src}@{K}")
                add(f"Loc{tn}Pf{kw}", r3(pe[f"pf@{K}"]), PF, f"point_estimates.{tool}.pf@{K}")
                add(f"Loc{tn}Cf{kw}", r3(pe[f"cf@{K}"]), PF, f"point_estimates.{tool}.cf@{K}")
                add(f"Loc{tn}Exact{kw}", r3(pe[f"exact@{K}"]), PF,
                    f"point_estimates.{tool}.exact@{K}")
        def plat(v):
            """A p-value as LaTeX math-mode content, so the prose can never hold a stale one."""
            if v is None:
                return "--"
            if v <= 0:
                # A p-value is never zero, so a zero here means an upstream step destroyed one,
                # and this loop used to spin forever on it rather than say so. Failing is the only
                # honest option: a printed "0" would claim certainty no test can give.
                raise ValueError(
                    "p-value formatted as zero. A test or a rounding step lost it upstream, and "
                    "printing zero would assert a certainty no permutation test can produce.")
            if v >= 1e-3:
                return f"{v:.3f}"
            e = 0
            while v < 1:
                v *= 10
                e += 1
            return f"{v:.1f}\\times 10^{{-{e}}}"

        for name, c in pf["comparisons"].items():
            ep, base = c["endpoint"], c["baseline"]
            TAGS = {"cf@1": "CfOne", "cf@10": "CfTen", "exact@1": "ExactOne",
                    "exact@10": "ExactTen", "pf@1": "PfOne", "pf@5": "PfFive",
                    "pf@10": "PfTen", "class": "Class"}
            if ep not in TAGS:
                continue
            tag = TAGS[ep]
            bn = TOOLNAME[base]
            add(f"Cmp{tag}{bn}P", plat(c["p_mcnemar_exact"]), PF,
                f"comparisons.{name}.p_mcnemar_exact")
            add(f"Cmp{tag}{bn}Holm", plat(c["p_holm_adjusted"]), PF,
                f"comparisons.{name}.p_holm_adjusted")
            add(f"Cmp{tag}{bn}Delta", f"{c['delta']:+.3f}", PF, f"comparisons.{name}.delta")
            add(f"Cmp{tag}{bn}CILo", r3(c["clustered_ci_delta"][0]), PF,
                f"comparisons.{name}.clustered_ci_delta[0]")
            add(f"Cmp{tag}{bn}CIHi", r3(c["clustered_ci_delta"][1]), PF,
                f"comparisons.{name}.clustered_ci_delta[1]")
            add(f"Cmp{tag}{bn}Win", str(c["discordant_wisp_only"]), PF,
                f"comparisons.{name}.discordant_wisp_only")
            add(f"Cmp{tag}{bn}Lose", str(c["discordant_baseline_only"]), PF,
                f"comparisons.{name}.discordant_baseline_only")

    # tab:clusterp is 39 rows x 5 numbers. Emitting 195 macros for it would be worse than
    # useless, so the table BODY is generated straight from the JSON and \input by the
    # supplement. Same single-source guarantee, no transcription.
    if os.path.isfile(pf_path):
        NAME = {"semgrep": "Semgrep", "progpilot": "Progpilot", "wpt": "wp-taint-scan"}
        LABEL = {"class": "class"}
        for K in ("1", "3", "5", "10"):
            LABEL["pf@" + K] = "patch-file@" + K
            LABEL["cf@" + K] = "class-and-file@" + K
            LABEL["exact@" + K] = "exact-line@" + K

        def _fmt(v):
            if v is None:
                return "--"
            return ("%.1e" % v) if v < 1e-3 else ("%.4f" % v)

        lines = ["% Auto-generated by eval/build_paper_macros_v3.py from PAIRED_FAMILY_V3.json.",
                 "% Every cell is a JSON pointer, not a transcription. Do not edit by hand."]
        prev = None
        for ep in pf["tested_endpoints"]:
            if prev is not None and ep.split("@")[0] != prev.split("@")[0]:
                lines.append(r"\midrule")
            prev = ep
            for base in pf["baselines_present"]:
                c = pf["comparisons"].get(ep + " vs " + base)
                if not c:
                    continue
                holm = _fmt(c["p_holm_adjusted"])
                if not c["survives_holm"]:
                    holm = r"\textbf{" + holm + "}"
                lines.append("%s & %s & %d & %d & %s & %s & %s \\\\" % (
                    LABEL[ep], NAME[base], c["discordant_wisp_only"],
                    c["discordant_baseline_only"], _fmt(c["p_mcnemar_exact"]),
                    _fmt(c["p_cluster_permutation"]), holm))
        # \bottomrule is \noalign, which TeX accepts only immediately after a row break.
        # \input inserts an end-of-file boundary between the last \\ and whatever follows in
        # the caller, so the rule has to be emitted inside this file, not after the \input.
        lines.append(r"\bottomrule")
        with open(os.path.join(LATEX, "PAIRED_FAMILY_TABLE.tex"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print("wrote PAIRED_FAMILY_TABLE.tex (%d rows)" % len(pf["comparisons"]))

    # external-source (Wordfence-100) table + true exact-line ladder, both from the contract re-scan
    ext_path = os.path.join(OUT, "EXTERNAL_TABLE_V3.json")
    if os.path.isfile(ext_path):
        ex = load("EXTERNAL_TABLE_V3.json")
        EX = "EXTERNAL_TABLE_V3.json"
        TN = {"wisp": "Wisp", "wpt": "Wpt", "semgrep": "Semgrep", "progpilot": "Progpilot"}
        ML = {"class emission": "Class", "patch-file@1": "PfOne", "patch-file@10": "PfTen",
              "class-and-file@1": "CfOne", "class-and-file@10": "CfTen"}
        for tool, tn in TN.items():
            for label, ln in ML.items():
                c = (ex["cells"].get(tool) or {}).get(label)
                if c:
                    add(f"Ext{tn}{ln}", r3(c["rate"]), EX, f"cells.{tool}.{label}.rate")
            add(f"Ext{tn}Coverage", r3(ex["coverage"][tool]), EX, f"coverage.{tool}")
        add("ExtNonConv", str(ex["wisp_non_converged"]), EX, "wisp_non_converged")
        # The count is 1 on this set, so a sentence written as "N records" reads "1 records". A
        # macro that carries only the number cannot agree with its own noun, so emit the noun too.
        _nc = int(ex["wisp_non_converged"])
        add("ExtNonConvRec", f"{_nc} record" + ("" if _nc == 1 else "s"), EX,
            "wisp_non_converged, with its noun")
        add("ExtNonConvVerb", "does" if _nc == 1 else "do", EX,
            "verb agreeing with wisp_non_converged")
        add("ExtN", str(ex["n_records"]), EX, "n_records")

    # Per-class emission on the full corpus, the three WordPress-specific classes the paper argues
    # about. These lived in prose as literals. They are the non-convergence-ignored basis, which is
    # what the per-class figure plots and what the surrounding text says, and they are not the
    # contract headline: no per-class contract re-score exists, and inventing one is not an option.
    PC_SRC = {
        "Wisp": ("wisp-artifact/out/corrected_20260713/perclass_wisp_1108.json", None),
        "Wpt": ("wisp-artifact/out/fill_20260714/atk_wpt_1108.json", None),
        "Semgrep": ("wisp-artifact/out/fill_20260714/atk_sg_1108.json", None),
        "Progpilot": ("wisp-artifact/out/fill_20260714/atk_pp_1108.json", None),
    }
    for tn, (rel, _) in PC_SRC.items():
        p = os.path.join(SYS_ROOT, rel)
        if not os.path.isfile(p):
            continue
        pc = json.load(open(p)).get("per_class", {})
        for cls, cn in (("auth", "Auth"), ("csrf", "Csrf"), ("deserial", "Deserial")):
            if cls in pc:
                add(f"Cls{tn}{cn}", r3(pc[cls]["recall"]), rel, f"per_class.{cls}.recall")

    # Semgrep-WP: WISP's own vocabulary transplanted into Semgrep's engine, re-scored under the
    # contract on the matched sample so it is finally comparable with tab:localize. It is a
    # vocabulary ablation of our own tool, not an independent baseline, so it is deliberately not
    # a member of the paired family and the manuscript says so where it reports it.
    swp = os.path.join(SYS_ROOT, "revision-cns-v2", "out", "semgrep_wp",
                       "semgrepwp_full_contract.json")
    if os.path.isfile(swp):
        SW = "revision-cns-v2/out/semgrep_wp/semgrepwp_full_contract.json"
        sm = json.load(open(swp))["summary"]["semgrep"]
        add("SwpClass", r3(sm["class_emission"]), SW, "summary.semgrep.class_emission")
        add("SwpCoverage", r3(sm["coverage"]), SW, "summary.semgrep.coverage")
        add("SwpAnswered", str(sm["answered"]), SW, "summary.semgrep.answered")
        add("SwpFindingsPerPlugin", f"{sm['findings_per_plugin']:.1f}", SW,
            "summary.semgrep.findings_per_plugin")
        for src, mac in (("pf_at_k", "Pf"), ("cf_at_k", "Cf"), ("cfn_at_k", "Cfn")):
            for K, kw in (("1", "One"), ("3", "Three"), ("5", "Five"), ("10", "Ten")):
                if K in sm.get(src, {}):
                    add(f"Swp{mac}{kw}", r3(sm[src][K]), SW, f"summary.semgrep.{src}.{K}")
        # How far apart the two are on patch-file@1, derived rather than asserted. The caption of
        # tab:localize said SG-WP led at every K, which was true when wisp-scanner-v1.2 put WISP at
        # 0.440 and false at v1.3's 0.520, and nothing could see it because the cells were macros
        # while the direction was a sentence. This macro plus an ORDERINGS entry in the guard makes
        # the next flip fail the build instead of the review.
        if "SwpPfOne" in MACROS and "LocWispPfOne" in MACROS:
            add("SwpPfOneGap",
                f"{abs(float(MACROS['LocWispPfOne'][0]) - float(MACROS['SwpPfOne'][0])):.3f}", SW,
                "abs(LocWispPfOne - SwpPfOne), the patch-file@1 gap between WISP and SG-WP")

    # Equal-budget matrix, the contract-scored one on the matched sample. WISP's own patch-file
    # success@1 across the shared budgets, reported in the supplement beside the pre-contract
    # full-corpus curve so a reader can see which experiment each range comes from.
    mx = os.path.join(OUT, "BASELINE_MATRIX_V3.json")
    if os.path.isfile(mx):
        MX = "BASELINE_MATRIX_V3.json"
        cells = json.load(open(mx))["cells"]
        vals = sorted(c["patch_file_success_at_1"] for k, c in cells.items()
                      if c["tool"] == "wisp")
        add("MatrixWispPfOneLo", r3(vals[0]), MX,
            "min over cells[wisp@*].patch_file_success_at_1")
        add("MatrixWispPfOneHi", r3(vals[-1]), MX,
            "max over cells[wisp@*].patch_file_success_at_1")
        # Concurrency is not uniform across cells and the text has to say so, so the two numbers
        # come from the cells rather than from the sentence. The 300 s wp-taint-scan cell runs at
        # the low count because at a 6 GB ceiling it is the only setting the host provably holds.
        # The largest lead WISP holds over the strongest baseline at any budget. The text used to
        # describe the ordering in prose and got it backwards, asserting the baseline was ahead at
        # 25 s beside two macros that said otherwise, so the size of the lead is now generated too.
        leads = [pb["wisp_pf1"] - pb["best_baseline_pf1"]
                 for pb in b["per_budget"].values()
                 if pb.get("wisp_pf1") is not None and pb.get("best_baseline_pf1") is not None]
        if leads:
            add("MatrixWispLeadMax", r3(max(leads)), BF,
                "max over per_budget[].(wisp_pf1 - best_baseline_pf1)")
        mw = {k: c.get("workers") for k, c in cells.items() if c.get("workers")}
        if mw:
            add("MatrixWorkersMax", str(max(mw.values())), MX, "max over cells[].workers")
            add("MatrixWorkersMin", str(min(mw.values())), MX, "min over cells[].workers")
            if cells.get("wpt@300", {}).get("workers"):
                add("MatrixWorkersWptThreeHundred", str(cells["wpt@300"]["workers"]), MX,
                    "cells[wpt@300].workers")

    # Full-corpus budget curve, the separate pre-contract sweep the supplement tabulates. It is a
    # different experiment from the matrix above: 1108 records rather than the matched sample, four
    # budgets rather than three, and the three subprocess baselines only. Both were typed as
    # literals and the ranges drifted, so both are generated. The file is a byte copy of
    # out/paired_20260717/BUDGET_CURVE.json under a name that states what it is.
    bc_path = os.path.join(OUT, "BUDGET_CURVE_FULL1108_PRECONTRACT.json")
    if os.path.isfile(bc_path):
        BC = "BUDGET_CURVE_FULL1108_PRECONTRACT.json"
        bc = load("BUDGET_CURVE_FULL1108_PRECONTRACT.json")
        BTOOL = {"wpt": "Wpt", "semgrep": "Semgrep", "progpilot": "Progpilot"}
        BUDG = {25: "TwentyFive", 60: "Sixty", 120: "OneTwenty", 300: "ThreeHundred"}
        pf1 = []
        for tool, mac in BTOOL.items():
            for pt in bc["tools"][tool]["curve"]:
                bw = BUDG[pt["budget_s"]]
                add(f"Bc{mac}Cov{bw}", r3(pt["coverage"]), BC,
                    f"tools.{tool}.curve[{pt['budget_s']}s].coverage")
                add(f"Bc{mac}Emis{bw}", r3(pt["class_recall"]), BC,
                    f"tools.{tool}.curve[{pt['budget_s']}s].class_recall")
                pf1.append(pt["prec_at_k"]["1"])
        pf1.sort()
        add("BcPfOneLo", r3(pf1[0]), BC,
            "min over tools.*.curve[*].prec_at_k.1 (three baselines, all budgets)")
        add("BcPfOneHi", r3(pf1[-1]), BC,
            "max over tools.*.curve[*].prec_at_k.1 (three baselines, all budgets)")
        add("BcNRecords", str(bc["tools"]["wpt"]["n_records"]), BC, "tools.wpt.n_records")

    # The second half of the equal budget. Time was budgeted from the start and memory was not,
    # which let one tool blow through its own soft heap ceiling and be stopped by the host instead
    # of by the protocol. These are the numbers that set the ceiling and the numbers that show why
    # one was needed, and like everything else here they are read rather than typed.
    # The ceiling itself, read from the run that was measured under it rather than from the source
    # constant, so the paper states the budget the numbers were actually produced with.
    # From the rollup's cell-derived field, not from run-level provenance. The matrix file keeps the
    # provenance of the run that created it, which after a re-measurement describes a protocol none
    # of its cells were measured under, and that is exactly the number this sentence must not use.
    # mem_cap_mb is None whenever the cells disagree, which they do: eight of the twelve carry the
    # ceiling and four predate it. The ceiling itself is still a real number and the text still has
    # to print it, so it is read from the cells that were measured under it rather than from a
    # field that is None precisely because the matrix is not uniform. Printing it says what the
    # ceiling was, not that every cell ran under it, and the text now says which cells did.
    mcap = b.get("mem_cap_mb") or b.get("mem_cap_mb_where_applied")
    src_ptr = ("mem_cap_mb" if b.get("mem_cap_mb") else "mem_cap_mb_where_applied")
    if mcap:
        add("MemCapMb", str(mcap), "BASELINE_MATCHED100_V3.json", src_ptr)
        add("MemCapGb", f"{mcap / 1024:.0f}", "BASELINE_MATCHED100_V3.json", src_ptr + " / 1024")
        add("MemCapCells", str(b.get("mem_cap_mb_applied_cells")),
            "BASELINE_MATCHED100_V3.json", "mem_cap_mb_applied_cells")
        add("MemCapCellsTotal", str(b.get("mem_cap_mb_total_cells")),
            "BASELINE_MATCHED100_V3.json", "mem_cap_mb_total_cells")
        # Two ceilings is the arithmetic behind the only concurrency this host provably holds, and
        # the text does that arithmetic, so it is generated rather than done in the sentence.
        add("MemCapTwiceGb", f"{2 * mcap / 1024:.0f}", "BASELINE_MATCHED100_V3.json",
            "2 * " + src_ptr + " / 1024")

    # The insertion-aware rung. A reviewer argued the exact-changed-line rung is structurally
    # unwinnable for a taint tool, because the archetypal WordPress fix inserts a guard before an
    # unchanged sink and findings are scored against the vulnerable tree, which has no line to
    # match. These macros are the measurement of that argument rather than a reply to it.
    ins_path = os.path.join(OUT, "INSERTION_LADDER_MATCHED_V1.json")
    if os.path.isfile(ins_path):
        ins = json.load(open(ins_path, encoding="utf-8"))
        IF = "INSERTION_LADDER_MATCHED_V1.json"
        arm = ins["headline_arm_for_this_dataset"]
        w = ins["arms"][arm]["per_tool"]["wisp"]
        base = f"arms.{arm}.per_tool.wisp"
        for macro, rung in (("InsExactOrIns", "rung_exact_or_ins0"),
                            ("InsExactOrInsTen", "rung_exact_or_ins10"),
                            ("InsCallable", "rung_callable"),
                            ("InsCallableOrIns", "rung_callable_or_inscallable")):
            add(macro, f"{w[rung]['rate']:.3f}", IF, f"{base}.{rung}.rate")
            add(macro + "Lo", f"{w[rung]['ci95'][0]:.3f}", IF, f"{base}.{rung}.ci95[0]")
            add(macro + "Hi", f"{w[rung]['ci95'][1]:.3f}", IF, f"{base}.{rung}.ci95[1]")
        cen = ins["census_step6"]["all_findings"]
        for macro, key in (("InsNFindings", "n_findings"),
                           ("InsInPatchedFile", "n_in_patched_file"),
                           ("InsUntouchedAdjacent", "untouched_but_adjacent_to_insertion"),
                           ("InsAnchorableButInsLocal", "anchorable_file_but_insertion_local"),
                           ("InsUntouchedInCallable", "untouched_in_callable_with_insertion")):
            add(macro, str(cen[key]), IF, f"census_step6.all_findings.{key}")

    # 2026-08-20, P2-7. The same rung measured on the full corpus, which is the population the
    # headline now sits on. The matched block above is WISP alone on 100 records; the reviewer's
    # question is whether promoting the insertion-aware rung to co-primary would change the
    # conclusion, and that question is about all four tools on all 1108. Both arms are emitted
    # under explicit names rather than one under the dataset's declared headline arm, because the
    # manuscript's corpus headline prints the kept arm while eval/corpus_ladder_v3.py calls the
    # contract arm the corpus headline, and a macro named for "the headline" would silently pick
    # one of the two.
    # 2026-08-20, P1-3. The Data and Code Availability paragraph says a clean worktree at the
    # release tag returns findings identical to the working tree, and until now it said so with the
    # word "fourteen" typed into the prose. A count with no macro behind it is checked by nothing,
    # which is how "Supplementary Table S3" survived becoming S7. These bind the sentence to the
    # run that produced it, so the next time the sample size changes the guard moves the sentence
    # rather than a person having to remember to.
    ct_path = os.path.join(OUT, "ENGINE_CLEANTREE_EQUIVALENCE_100_V3.json")
    if os.path.isfile(ct_path):
        ct = json.load(open(ct_path, encoding="utf-8"))
        CTF = "ENGINE_CLEANTREE_EQUIVALENCE_100_V3.json"
        for macro, key in (("CleanTreeN", "n_records"),
                           ("CleanTreeIdentical", "n_identical"),
                           ("CleanTreeIdenticalFindings", "n_identical_findings"),
                           ("CleanTreeIdenticalStatus", "n_identical_status"),
                           ("CleanTreeDiffering", "n_differing")):
            add(macro, str(ct[key]), CTF, key)
        add("CleanTreeRef", str(ct["baseline_ref"]), CTF, "baseline_ref")
        add("CleanTreeEngineSha", str(ct["baseline_engine_sha256"])[:8], CTF,
            "baseline_engine_sha256[:8]")

    insc_path = os.path.join(OUT, "INSERTION_LADDER_CORPUS_V1.json")
    if os.path.isfile(insc_path):
        insc = json.load(open(insc_path, encoding="utf-8"))
        ICF = "INSERTION_LADDER_CORPUS_V1.json"
        for arm, Ac in (("kept", "Kept"), ("contract", "Contract")):
            A = insc["arms"][arm]
            for tk, Tc in (("wisp", "Wisp"), ("semgrep", "Semgrep"),
                           ("wpt", "Wpt"), ("progpilot", "Progpilot")):
                t = A["per_tool"][tk]
                for macro, rung in (("Exact", "rung_exact"),
                                    ("ExactIns", "rung_exact_or_ins5"),
                                    ("File", "rung_file")):
                    add(f"InsCorpus{Ac}{Tc}{macro}", f"{t[rung]['rate']:.4f}", ICF,
                        f"arms.{arm}.per_tool.{tk}.{rung}.rate")
            P = A["pooled"]
            for macro, rung in (("PooledFile", "rung_file"),
                                ("PooledExact", "rung_exact"),
                                ("PooledExactIns", "rung_exact_or_ins5")):
                add(f"InsCorpus{Ac}{macro}", f"{P[rung]['rate']:.4f}", ICF,
                    f"arms.{arm}.pooled.{rung}.rate")
                add(f"InsCorpus{Ac}{macro}Lo", f"{P[rung]['ci95'][0]:.4f}", ICF,
                    f"arms.{arm}.pooled.{rung}.ci95[0]")
                add(f"InsCorpus{Ac}{macro}Hi", f"{P[rung]['ci95'][1]:.4f}", ICF,
                    f"arms.{arm}.pooled.{rung}.ci95[1]")
            add(f"InsCorpus{Ac}NFindings", str(P["n_findings"]), ICF,
                f"arms.{arm}.pooled.n_findings")
            add(f"InsCorpus{Ac}NSlugs", str(P["n_slugs"]), ICF, f"arms.{arm}.pooled.n_slugs")

    mp_path = os.path.join(OUT, "MEM_PROFILE_V3.json")
    if os.path.isfile(mp_path):
        MP = "MEM_PROFILE_V3.json"
        mpj = load("MEM_PROFILE_V3.json")
        for tk, Tc in (("wisp", "Wisp"), ("semgrep", "Semgrep"),
                       ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            t = mpj["per_tool"].get(tk)
            if not t:
                continue
            add(f"MemPeak{Tc}MaxMb", f"{t['peak_mb_max']:.0f}", MP, f"per_tool.{tk}.peak_mb_max")
            add(f"MemPeak{Tc}MaxGb", f"{t['peak_mb_max'] / 1024:.2f}", MP,
                f"per_tool.{tk}.peak_mb_max / 1024")
            add(f"MemPeak{Tc}MedianMb", f"{t['peak_mb_median']:.0f}", MP,
                f"per_tool.{tk}.peak_mb_median")
            add(f"MemPeak{Tc}PNinetyMb", f"{t['peak_mb_p90']:.0f}", MP, f"per_tool.{tk}.peak_mb_p90")
        add("MemProfileNRecords", str(mpj["n_records"]), MP, "n_records")

    oe_path = os.path.join(OUT, "OOM_EVIDENCE_V3.json")
    if os.path.isfile(oe_path):
        OE = "OOM_EVIDENCE_V3.json"
        oe = load("OOM_EVIDENCE_V3.json")
        add("HostRamGb", f"{oe['host_ram_gb']:.1f}", OE, "host_ram_gb")
        biggest = oe.get("max_anon_rss_gb_by_process", {}).get("taint-scan")
        if biggest:
            add("OomWptRssGb", f"{biggest:.2f}", OE, "max_anon_rss_gb_by_process.taint-scan")
        # The worst contaminated cell, by how many records the host took from it. Named by its own
        # file so a reader can open the evidence rather than take the count on trust.
        cc = sorted(oe.get("contaminated_cells", []), key=lambda c: -c["lost_to_host"])
        if cc:
            add("OomLostRecords", str(cc[0]["lost_to_host"]), OE,
                "max over contaminated_cells[].lost_to_host")
            add("OomLostDenominator", str(cc[0]["n_records"]), OE,
                "contaminated_cells[argmax].n_records")

    # Corpus-scale equal-budget matrix. The reviewer asked whether the matched-sample matrix
    # survives at corpus scale, so this is the same protocol on all 1108 records and all four
    # tools, contract-scored, one tool at a time. It is a third experiment and shares nothing with
    # the two above but the budget grid, so it gets its own prefix rather than extending theirs.
    fx = os.path.join(OUT, "BASELINE_FULL1108_V3.json")
    if os.path.isfile(fx) and json.load(open(fx)).get("status") != "NOT_RUN":
        FX = "BASELINE_FULL1108_V3.json"
        f = load("BASELINE_FULL1108_V3.json")
        MTOOL = {"wisp": "Wisp", "semgrep": "Semgrep", "progpilot": "Progpilot", "wpt": "Wpt"}
        MBUDG = {25: "TwentyFive", 60: "Sixty", 300: "ThreeHundred"}
        add("CmxNRecords", str(f["n_records"]), FX, "n_records")
        add("CmxNBudgets", str(len(f["budgets_s"])), FX, "len(budgets_s)")
        add("CmxBudgetMaxS", str(max(f["budgets_s"])), FX, "max(budgets_s)")
        # Concurrency, from the cells rather than from the sentence. Both WordPress-aware tools are
        # measured at the same count here, which is what makes the comparison like for like, and the
        # text says so, so the number has to be checkable.
        cw = {k: w for k, w in (f.get("cell_workers") or {}).items() if w}
        if cw:
            add("CmxWorkers", str(max(cw.values())), FX, "max over cell_workers[]")
        for tk, Tc in MTOOL.items():
            for bud, word in MBUDG.items():
                ci = f["pf1_bootstrap_ci"].get(f"{tk}@{bud}")
                if not ci:
                    continue
                add(f"Cmx{Tc}PfOne{word}", r3(ci["point"]), FX,
                    f"pf1_bootstrap_ci.{tk}@{bud}.point")
                add(f"Cmx{Tc}PfOne{word}Lo", r3(ci["ci95"][0]), FX,
                    f"pf1_bootstrap_ci.{tk}@{bud}.ci95[0]")
                add(f"Cmx{Tc}PfOne{word}Hi", r3(ci["ci95"][1]), FX,
                    f"pf1_bootstrap_ci.{tk}@{bud}.ci95[1]")
                add(f"Cmx{Tc}Cov{word}", r3(f["table"]["coverage"][tk][str(bud)]), FX,
                    f"table.coverage.{tk}.{bud}")
                add(f"Cmx{Tc}Emis{word}",
                    r3(f["table"]["class_emission_failure_as_miss"][tk][str(bud)]), FX,
                    f"table.class_emission_failure_as_miss.{tk}.{bud}")
        # WISP minus the strongest baseline at each budget, the quantity the text compares. The
        # sign is the whole claim, so the interval travels with it.
        for bud, word in MBUDG.items():
            pb = f["per_budget"].get(str(bud))
            if not pb or not pb.get("best_baseline"):
                continue
            d = pb["wisp_minus_baseline_pf1"].get(pb["best_baseline"])
            if not d:
                continue
            add(f"CmxWispLead{word}", r3(d["diff_point"]), FX,
                f"per_budget.{bud}.wisp_minus_baseline_pf1.{pb['best_baseline']}.diff_point")
            add(f"CmxWispLead{word}Lo", r3(d["ci95"][0]), FX,
                f"per_budget.{bud}.wisp_minus_baseline_pf1.{pb['best_baseline']}.ci95[0]")
            add(f"CmxWispLead{word}Hi", r3(d["ci95"][1]), FX,
                f"per_budget.{bud}.wisp_minus_baseline_pf1.{pb['best_baseline']}.ci95[1]")
            # The corpus reverses the matched-sample ordering, so the margin the text quotes is the
            # baseline's, stated as a positive number rather than as a negative WISP lead.
            wpt = f["table"]["patch_file_success_at_1"]["wpt"].get(str(bud))
            wisp = f["table"]["patch_file_success_at_1"]["wisp"].get(str(bud))
            if wpt is not None and wisp is not None:
                add(f"CmxWptLead{word}", r3(wpt - wisp), FX,
                    f"table.patch_file_success_at_1.(wpt - wisp).{bud}")
                # The interval has to travel on the same scale as the point estimate. Until
                # 2026-08-12 only the point estimate was reversed, so the abstract printed a
                # positive baseline lead beside the wholly negative WISP-minus-baseline interval,
                # a pair that cannot both be true. Reverse and negate the endpoints here so the
                # sentence cannot be assembled from two scales again.
                if pb["best_baseline"] == "wpt":
                    add(f"CmxWptLead{word}Lo", r3(-d["ci95"][1]), FX,
                        f"per_budget.{bud}.wisp_minus_baseline_pf1.wpt.ci95[1] negated")
                    add(f"CmxWptLead{word}Hi", r3(-d["ci95"][0]), FX,
                        f"per_budget.{bud}.wisp_minus_baseline_pf1.wpt.ci95[0] negated")

    # Miss analysis. The in-scope emission was written out to four decimals, which slipped past a
    # literal check that only looked for two or three, so it stayed hand-typed in three places
    # while everything around it was generated.
    mi_path = os.path.join(OUT, "MISS_ANALYSIS_V3.json")
    if os.path.isfile(mi_path):
        MI = "MISS_ANALYSIS_V3.json"
        mi = load("MISS_ANALYSIS_V3.json")
        add("MissTotal", str(mi["misses"]["total"]), MI, "misses.total")
        add("MissWrongClass", str(mi["misses"]["wrong_class_engine_active"]), MI,
            "misses.wrong_class_engine_active")
        add("MissBlind", str(mi["misses"]["blind_zero_findings"]), MI,
            "misses.blind_zero_findings")
        # The base rate of this decomposition and the two shares. All three sat hand-typed in the
        # supplement as 854, 87.8 and 12.2, which the literal guard allows because it only sees bare
        # decimals and 854 is an integer. The v1.3 kept arm is 855 hits and 253 misses, so those
        # figures would have contradicted the macro printed in the same sentence.
        _ac = mi["emission"]["all_classes"]
        add("MissKeptHits", str(_ac["hits"]), MI, "emission.all_classes.hits")
        add("MissKeptN", str(_ac["n"]), MI, "emission.all_classes.n")
        _tot = mi["misses"]["total"]
        add("MissWrongClassPct", f'{100 * mi["misses"]["wrong_class_engine_active"] / _tot:.1f}',
            MI, "misses.wrong_class_engine_active / misses.total (percent)")
        add("MissBlindPct", f'{100 * mi["misses"]["blind_zero_findings"] / _tot:.1f}',
            MI, "misses.blind_zero_findings / misses.total (percent)")
        for key, mac in (("in_scope_no_other", "InScope"), ("wordpress_specific", "WpBlock"),
                         ("generic_taint", "GenericTaint")):
            e = mi["emission"][key]
            add(f"Miss{mac}Emis", r4(e["emission"]), MI, f"emission.{key}.emission")
            add(f"Miss{mac}Hits", str(e["hits"]), MI, f"emission.{key}.hits")
            add(f"Miss{mac}N", str(e["n"]), MI, f"emission.{key}.n")

    # The without-learned-rules arm of the sink-mining ablation. Same four-decimal blind spot as
    # the miss analysis: it was typed in twice and the guard could not see it.
    nl_path = os.path.join(OUT, "NOLEARN_CORPUS_PRECONTRACT.json")
    if os.path.isfile(nl_path):
        NL = "NOLEARN_CORPUS_PRECONTRACT.json"
        nl = load("NOLEARN_CORPUS_PRECONTRACT.json")
        add("NoLearnEmission", r4(nl["plugin_class_recall"]), NL, "plugin_class_recall")
        add("NoLearnHits", str(nl["hits"]), NL, "hits")
        add("NoLearnPool", f'{nl["findings_per_plugin"]:.1f}', NL, "findings_per_plugin")

    # The kept-arm class emission of the BASELINE engine, produced by re-running the corpus analysis
    # against the v1.2 shard backup. Two passages need it and both need it frozen. The sink-mining
    # ablation pairs its without-learning arm, measured in July on that engine, against a
    # with-learning figure, and pairing it against the live headline macro turns an ablation into a
    # comparison across engine versions the moment the headline moves. The mechanism decomposition
    # in the supplement is the other: its per-finding attribution is not recorded in any shipped
    # output, so it cannot be regenerated, and its 854 hits belong to this number rather than to the
    # v1.3 one. Both passages say plainly that they are the earlier engine.
    nlp_path = os.path.join(OUT, "FULLCORPUS_FAILURE_AS_MISS_V3_v12shards.json")
    if os.path.isfile(nlp_path):
        NLP = "FULLCORPUS_FAILURE_AS_MISS_V3_v12shards.json"
        nlp = load(NLP)
        add("BaselineKeptEmission", r4(nlp["arms"]["full_1108"]["kept"]["wisp"]["emission"]), NLP,
            "arms.full_1108.kept.wisp.emission")

    # The dominance-gated arm of the missing-guard variant study. It lands on the same emission as
    # the arm above, 835 hits of 1108 in both, which is a real coincidence and not a duplicated
    # file: the two hit sets differ by 22 records each way. Binding both sentences to one macro
    # said they were one measurement, so each arm carries its own.
    gd_path = os.path.join(OUT, "GDAGATE_CORPUS_PRECONTRACT.json")
    if os.path.isfile(gd_path):
        GD = "GDAGATE_CORPUS_PRECONTRACT.json"
        gd = load("GDAGATE_CORPUS_PRECONTRACT.json")
        add("GdaGateEmission", r4(gd["plugin_class_recall"]), GD, "plugin_class_recall")
        add("GdaGatePool", f'{gd["findings_per_plugin"]:.1f}', GD, "findings_per_plugin")

    # Scalability fit. The figure's legend and the supplement's sentence each computed this
    # separately, so they were two copies of one number with nothing holding them together.
    if os.path.isfile(os.path.join(OUT, "SCALABILITY_APPS_V3.json")):
        from eval.scalability_fit import fit as _scale_fit
        SC = "SCALABILITY_APPS_V3.json"
        sc = load("SCALABILITY_APPS_V3.json")
        f = _scale_fit(sc)
        add("ScaleSlope", r2(f["slope"]), SC, "least-squares log-log slope over results[]")
        add("ScaleRSq", r2(f["r2"]), SC, "R^2 of that fit")
        add("ScaleNApps", str(f["n_points"]), SC, "usable points in results[]")

    # What the family could and could not have detected. A null claim needs this: with a handful of
    # discordant pairs an exact McNemar test cannot reject at the corrected level however large the
    # real difference is, and reporting that as "no difference" reports the design, not the result.
    pw_path = os.path.join(OUT, "POWER_FLOOR_V3.json")
    if os.path.isfile(pw_path):
        PW = "POWER_FLOOR_V3.json"
        pw = load("POWER_FLOOR_V3.json")
        add("PwNeedAlpha", str(pw["pairs_needed_at_alpha"]), PW, "pairs_needed_at_alpha")
        add("PwNeedHolm", str(pw["pairs_needed_at_holm_strictest"]), PW,
            "pairs_needed_at_holm_strictest")
        add("PwHolmThreshold", f'{pw["holm_strictest_threshold"]:.5f}', PW,
            "holm_strictest_threshold")
        add("PwUndetectable", str(pw["n_undetectable_at_holm_strictest"]), PW,
            "n_undetectable_at_holm_strictest")
        for key, mac in (("exact@1 vs semgrep", "ExactOneSemgrep"),
                         ("exact@1 vs progpilot", "ExactOneProgpilot"),
                         ("exact@1 vs wpt", "ExactOneWpt")):
            r = pw["comparisons"][key]
            add(f"PwDisc{mac}", str(r["discordant_total"]), PW,
                f"comparisons[{key}].discordant_total")
            add(f"PwFloor{mac}", f'{r["floor_p"]:.3f}', PW, f"comparisons[{key}].floor_p")

    # Baseline failure audit. One aggregate failure count per tool cannot answer whether the other
    # baselines carried the defect we found in our own Progpilot handling, so the counts are split
    # by kind and the unverifiable part is reported as a bound.
    fa_path = os.path.join(OUT, "BASELINE_FAILURE_AUDIT_V3.json")
    if os.path.isfile(fa_path):
        FA = "BASELINE_FAILURE_AUDIT_V3.json"
        fa = load("BASELINE_FAILURE_AUDIT_V3.json")["tools"]
        for tool, mac in (("semgrep", "Semgrep"), ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            e = fa[tool]
            add(f"Fail{mac}Total", str(e["failures"]), FA, f"tools.{tool}.failures")
            add(f"Fail{mac}Budget", str(e["budget_exhaustion"]), FA,
                f"tools.{tool}.budget_exhaustion")
            add(f"Fail{mac}Harness", str(e["harness_read_failures"]), FA,
                f"tools.{tool}.harness_read_failures")
            add(f"Fail{mac}Cov", r3(e["coverage_as_scored"]), FA,
                f"tools.{tool}.coverage_as_scored")
            add(f"Fail{mac}CovHi",
                r3(e["coverage_upper_bound_if_all_harness_failures_were_false"]), FA,
                f"tools.{tool}.coverage_upper_bound_if_all_harness_failures_were_false")

    # Why the common subset moves Semgrep the other way. A selection effect stated with numbers
    # rather than left as an unexplained anomaly in the table.
    cb_path = os.path.join(OUT, "COMMON_SUBSET_BIAS_V3.json")
    if os.path.isfile(cb_path):
        CB = "COMMON_SUBSET_BIAS_V3.json"
        cb = load("COMMON_SUBSET_BIAS_V3.json")
        add("CsSemgrepIn", r3(cb["semgrep_emission_inside"]["emission"]), CB,
            "semgrep_emission_inside.emission")
        add("CsSemgrepOut", r3(cb["semgrep_emission_outside"]["emission"]), CB,
            "semgrep_emission_outside.emission")
        p = cb["plugin_size_proxy"]
        add("CsFindingsIn", f'{p["wisp_findings_median_inside"]["median"]:.0f}', CB,
            "plugin_size_proxy.wisp_findings_median_inside.median")
        add("CsFindingsOut", f'{p["wisp_findings_median_outside"]["median"]:.0f}', CB,
            "plugin_size_proxy.wisp_findings_median_outside.median")
        add("CsFilesIn", f'{p["changed_files_median_inside"]["median"]:.0f}', CB,
            "plugin_size_proxy.changed_files_median_inside.median")
        add("CsFilesOut", f'{p["changed_files_median_outside"]["median"]:.0f}', CB,
            "plugin_size_proxy.changed_files_median_outside.median")

    # The two denominators in the external section. Reported because reading them as one is a
    # mistake a careful reader makes, not because the numbers disagree.
    ed_path = os.path.join(OUT, "EXTERNAL_DENOMINATOR_V3.json")
    if os.path.isfile(ed_path):
        ED = "EXTERNAL_DENOMINATOR_V3.json"
        ed = load("EXTERNAL_DENOMINATOR_V3.json")
        for k, mac in (("findings_emitted", "EdEmitted"),
                       ("non_converged_records", "EdNonConvN"),
                       ("findings_on_non_converged_records", "EdNonConvFindings"),
                       ("credited_records", "EdCreditedN"),
                       ("credited_findings", "EdCreditedFindings")):
            add(mac, str(ed[k]), ED, k)
        add("EdPerRecord", f'{ed["findings_per_credited_record"]:.1f}', ED,
            "findings_per_credited_record")

    # The ladder on the whole corpus rather than the 100-record diagnostic. Inert until the
    # full-corpus scans exist, so the build keeps working while they run.
    cl_path = os.path.join(OUT, "CORPUS_LADDER_V3.json")
    if os.path.isfile(cl_path):
        CL = "CORPUS_LADDER_V3.json"
        cl = load("CORPUS_LADDER_V3.json")
        add("ClRecords", str(cl["records_scored"]), CL, "records_scored")
        for tool, mac in (("wisp", "Wisp"), ("semgrep", "Semgrep"),
                          ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            e = cl["per_tool"].get(tool)
            if not e or not e.get("n_findings"):
                continue
            add(f"Cl{mac}N", str(e["n_findings"]), CL, f"per_tool.{tool}.n_findings")
            for rung, rm in (("in_patched_file", "File"),
                             ("on_exact_changed_line", "Exact"),
                             ("same_callable_as_change", "Callable")):
                r = e[rung]
                add(f"Cl{mac}{rm}", r3(r["rate"]), CL, f"per_tool.{tool}.{rung}.rate")
                add(f"Cl{mac}{rm}Lo", r3(r["ci95"][0]), CL, f"per_tool.{tool}.{rung}.ci95[0]")
                add(f"Cl{mac}{rm}Hi", r3(r["ci95"][1]), CL, f"per_tool.{tool}.{rung}.ci95[1]")

    # The same corpus ladder on the arm the matched-sample ladder uses, so the move from 100
    # records to 1108 can be read without the failure policy changing underneath it. Only WISP
    # differs between the two arms, because only WISP has a non-convergence mode.
    ck_path = os.path.join(OUT, "CORPUS_LADDER_KEPT_V3.json")
    if os.path.isfile(ck_path):
        CK = "CORPUS_LADDER_KEPT_V3.json"
        ck = load("CORPUS_LADDER_KEPT_V3.json")
        add("ClKeptFindings", str(sum(v["n_findings"] for v in ck["per_tool"].values())), CK,
            "sum over per_tool[*].n_findings")
        # Promoted to the main-paper Table 1 on 2026-08-19. The reviewer's first demand was that the
        # headline ladder be the 1108-record corpus rather than the 100-record matched sample, and
        # the corpus arm existed but only its file and exact rungs had macros, so the table could not
        # be built without typing cells. Every cell of the promoted table is generated here: the
        # four rungs with rate, raw count and denominator, an interval on each rung, and the
        # conditional P(exact | already in a patched file).
        ck_rungs = (("in_patched_file", "File"),
                    ("same_callable_as_change", "Callable"),
                    ("on_exact_changed_line", "Exact"),
                    ("within_5_changed_lines", "ProxFive"))
        for tool, mac in (("wisp", "Wisp"), ("semgrep", "Semgrep"),
                          ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            e = ck["per_tool"].get(tool)
            if not e or not e.get("n_findings"):
                continue
            add(f"ClKept{mac}N", str(e["n_findings"]), CK, f"per_tool.{tool}.n_findings")
            for rung, rm in ck_rungs:
                r = e[rung]
                add(f"ClKept{mac}{rm}", r3(r["rate"]), CK, f"per_tool.{tool}.{rung}.rate")
                add(f"ClKept{mac}{rm}N", str(r["count"]), CK, f"per_tool.{tool}.{rung}.count")
                add(f"ClKept{mac}{rm}D", str(r["n"]), CK, f"per_tool.{tool}.{rung}.n")
                add(f"ClKept{mac}{rm}Lo", r3(r["ci95"][0]), CK,
                    f"per_tool.{tool}.{rung}.ci95[0]")
                add(f"ClKept{mac}{rm}Hi", r3(r["ci95"][1]), CK,
                    f"per_tool.{tool}.{rung}.ci95[1]")
            # P(exact changed line | already in a patched file). The unconditional rungs answer
            # "how often does a finding land on the patch", this answers "having reached the right
            # file, how often does it reach the right line", which is the quantity the file-endpoint
            # claim is about. Counts, not rates, so the shared denominator cancels exactly.
            _fc = e["in_patched_file"]["count"]
            _ec = e["on_exact_changed_line"]["count"]
            add(f"ClKept{mac}CondExactFile", r3(_ec / _fc) if _fc else "0", CK,
                f"per_tool.{tool}.on_exact_changed_line.count / "
                f"per_tool.{tool}.in_patched_file.count")
        # The corpus-scale file -> exact drop, now with its interval. This used to ship as a bare
        # point estimate subtracted here out of the two rung rates, because the arm file carried a
        # clustered interval for each rung separately and none for the difference, and the two
        # marginal intervals cannot be combined into one: the rungs are nested on the same findings
        # and positively correlated, so differencing their endpoints overstates the width by an
        # unknown amount. The interval has to come from resampling the plugin slugs and recomputing
        # the difference inside each replicate. eval/corpus_ladder_v3.py does that now, with the
        # estimator, cluster and seed the matched sample uses, so the drop and its interval are read
        # from one block rather than one being read and the other arithmetic done here.
        for tool, mac in (("wisp", "Wisp"), ("semgrep", "Semgrep"),
                          ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            de = (ck.get("primary_effect") or {}).get(tool, {}).get("drop_to_exact_changed_line")
            if not de:
                continue
            add(f"ClKept{mac}DropToExact", r3(de["diff"]), CK,
                f"primary_effect.{tool}.drop_to_exact_changed_line.diff")
            add(f"ClKept{mac}DropToExactCILo", r3(de["ci95"][0]), CK,
                f"primary_effect.{tool}.drop_to_exact_changed_line.ci95[0]")
            add(f"ClKept{mac}DropToExactCIHi", r3(de["ci95"][1]), CK,
                f"primary_effect.{tool}.drop_to_exact_changed_line.ci95[1]")

    # Bibliography census. The related-work paragraph tells the reader how much of what it cites is
    # not yet peer-reviewed, and that used to be the word "most", which nothing checked.
    rc_path = os.path.join(OUT, "REFERENCE_CENSUS_V3.json")
    if os.path.isfile(rc_path):
        RC = "REFERENCE_CENSUS_V3.json"
        rc = load("REFERENCE_CENSUS_V3.json")
        add("RefsTotal", str(rc["n_references"]), RC, "n_references")
        # The census counts preprints twice as of schema reference-census-v4: before the audit pass
        # that chased every arXiv entry for a published version, and after it. \RefsPreprint is the
        # bibliography as it stands, which is the only count the manuscript may quote. \RefsPreprintBefore
        # exists because the response letter has to say what the reviewer's own count was and what
        # the pass changed it to, and a number in the response that no macro backs is a number
        # nothing rechecks. The old single key n_preprints is gone; reading it by name would have
        # been a silent KeyError at build time, so the two names are read explicitly.
        add("RefsPreprintBefore", str(rc["n_preprints_before"]), RC, "n_preprints_before")
        add("RefsPreprint", str(rc["n_preprints_after"]), RC, "n_preprints_after")
        add("RefsUpgraded", str(rc["n_upgraded_with_verified_doi"]), RC,
            "n_upgraded_with_verified_doi")
        add("RefsReviewed", str(rc["n_peer_reviewed"]), RC, "n_peer_reviewed")

    # The WordPress-block aggregate, added 2026-08-14. The manuscript printed "424 of 475 records
    # ... reach 0.893" by hand, which is the non-convergence-ignored basis, in a sentence whose
    # surrounding claims are all on the contract basis. PERCLASS_CONTRACT_V3.json says 419 of 475 and
    # 0.882. A reviewer found the gap. Generate it so the sentence cannot carry a different policy
    # from the one the paper reports.
    pcc = os.path.join(OUT, "PERCLASS_CONTRACT_V3.json")
    if os.path.isfile(pcc):
        PCC = "PERCLASS_CONTRACT_V3.json"
        pc = load("PERCLASS_CONTRACT_V3.json")["per_class"]
        _hit = sum(int(pc[c]["hits"]) for c in ("auth", "csrf", "deserial") if c in pc)
        _n = sum(int(pc[c]["n"]) for c in ("auth", "csrf", "deserial") if c in pc)
        add("WpBlockHits", str(_hit), PCC, "sum of per_class.{auth,csrf,deserial}.hits")
        add("WpBlockN", str(_n), PCC, "sum of per_class.{auth,csrf,deserial}.n")
        add("WpBlockEmission", r3(_hit / _n) if _n else "0", PCC,
            "hits/n over auth+csrf+deserial on the contract basis")

    # Resolution screen, added 2026-08-14. A reviewer pointed out that "does not separate" is two
    # claims in one sentence: at exact-changed-line K=1 there are so few discordant pairs that no
    # result could have separated, which is an absence of evidence, not evidence of similarity.
    # These macros let the paper say which of its nulls are informative. It is NOT an equivalence
    # test and the names say so, because an earlier draft called it one while the supplement said
    # plainly that no equivalence test had been run.
    eq_path = os.path.join(OUT, "RESOLUTION_SCREEN_V3.json")
    if os.path.isfile(eq_path):
        EQ = "RESOLUTION_SCREEN_V3.json"
        eq = load("RESOLUTION_SCREEN_V3.json")
        cnt = eq["counts_at_delta"]
        add("ResDelta", ("%.2f" % eq["delta"]), EQ, "delta")
        add("ResWithinMargin", str(cnt.get("within_margin", 0)), EQ, "counts_at_delta.within_margin")
        add("ResUnresolved", str(cnt.get("unresolved", 0)), EQ, "counts_at_delta.unresolved")
        add("ResExcludesZero", str(cnt.get("excludes_zero_uncorrected", 0)), EQ,
            "counts_at_delta.excludes_zero_uncorrected")
        _x1 = eq.get("exact_line_at_k1") or {}
        _wpt = next((v for v in _x1.values() if v["baseline"] == "wpt"), None)
        if _wpt:
            add("ResExactOneWptDisc", str(_wpt["n_discordant_pairs"]), EQ,
                "exact_line_at_k1[wpt].n_discordant_pairs")
            add("ResExactOneWptVerdict", _wpt["verdict_at_delta"].replace("_", " "), EQ,
                "exact_line_at_k1[wpt].verdict_at_delta")

    # Stratified re-draw, added 2026-08-14 for the same review. The reported matched sample is an
    # unstratified seed-42 draw, so a second draw controlling for class, patch breadth and patch
    # shape says whether the conclusions rest on the draw.
    ss_path = os.path.join(OUT, "STRATIFIED_SAMPLE_V3.json")
    if os.path.isfile(ss_path):
        SS = "STRATIFIED_SAMPLE_V3.json"
        ss = load("STRATIFIED_SAMPLE_V3.json")
        s = ss["endpoints"]["stratified_sample"]
        add("StratN", str(ss["n"]), SS, "n")
        for _t, _lab in (("wisp", "Wisp"), ("wpt", "Wpt")):
            add("Strat%sPfOne" % _lab, r3(s[_t]["pf@1"]), SS,
                "endpoints.stratified_sample.%s.pf@1" % _t)
            add("Strat%sCfOne" % _lab, r3(s[_t]["cf@1"]), SS,
                "endpoints.stratified_sample.%s.cf@1" % _t)
            add("Strat%sClass" % _lab, r3(s[_t]["class_emission"]), SS,
                "endpoints.stratified_sample.%s.class_emission" % _t)

    # Held-out ranking calibration. The rates are stored as the rendered "rate (k/n)" strings the
    # table prints, so the macro carries the string and the JSON stays the single source. The run
    # is 2026-07-14 and the supplement already says the calibration predates the contract.
    rk_path = os.path.join(OUT, "RANKCAL_PRECONTRACT.json")
    if os.path.isfile(rk_path):
        RK = "RANKCAL_PRECONTRACT.json"
        rows = load("RANKCAL_PRECONTRACT.json")["rows"]
        RN = {"Default weights": "Default", "Emphasize confidence": "Conf",
              "De-emphasize entry point": "Entry", "Reliability-tier first": "Tier"}
        for label, mac in RN.items():
            if label in rows:
                add(f"Rk{mac}Train", rows[label]["train_cf1"], RK,
                    f"rows[{label}].train_cf1")
                add(f"Rk{mac}Test", rows[label]["test_cf1"], RK,
                    f"rows[{label}].test_cf1")

    # ZIPPER head-to-head. Another table that was typed entirely as literals and sat unlabelled
    # beside contract-scored ones, which is the defect the localization prose had. The run is
    # 2026-07-16, before the contract, so the macro names say so and the supplement says so.
    zp_path = os.path.join(OUT, "ZIPPER_COMPARISON_PRECONTRACT.json")
    if os.path.isfile(zp_path):
        ZP = "ZIPPER_COMPARISON_PRECONTRACT.json"
        zp = load("ZIPPER_COMPARISON_PRECONTRACT.json")
        add("ZipNPaired", str(zp["paired_records"]), ZP, "paired_records")
        add("ZipWispCov", r3(zp["coverage"]["wisp"]), ZP, "coverage.wisp")
        add("ZipZipperCov", r3(zp["coverage"]["zipper"]), ZP, "coverage.zipper")
        add("ZipWispFindings", f'{zp["findings_per_record"]["wisp"]:.1f}', ZP,
            "findings_per_record.wisp")
        add("ZipZipperFindings", f'{zp["findings_per_record"]["zipper"]:.1f}', ZP,
            "findings_per_record.zipper")
        add("ZipWispSilent", r3(zp["silent_records"]["wisp"] / zp["paired_records"]), ZP,
            "silent_records.wisp / paired_records")
        add("ZipZipperSilent", r3(zp["silent_records"]["zipper_frac_of_completed"]), ZP,
            "silent_records.zipper_frac_of_completed")
        KN = {"file_precision@1": "PfOne", "file_precision@3": "PfThree",
              "file_precision@5": "PfFive", "file_precision@10": "PfTen",
              "class_emission": "Emis"}
        for row in zp["endpoints"]:
            kn = KN.get(row["endpoint"])
            if not kn:
                continue
            add(f"ZipWisp{kn}", r3(row["wisp"]), ZP, f"endpoints[{row['endpoint']}].wisp")
            add(f"ZipZipper{kn}", r3(row["zipper"]), ZP, f"endpoints[{row['endpoint']}].zipper")
            add(f"ZipDiff{kn}Lo", r3(row["ci95"][0]), ZP,
                f"endpoints[{row['endpoint']}].ci95[0]")
            add(f"ZipDiff{kn}Hi", r3(row["ci95"][1]), ZP,
                f"endpoints[{row['endpoint']}].ci95[1]")
            add(f"ZipDiff{kn}", r3(row["diff"]), ZP, f"endpoints[{row['endpoint']}].diff")
        for cls, cn in (("lfi", "Lfi"), ("sqli", "Sqli"), ("xss", "Xss"), ("rce", "Rce")):
            c = zp["per_class_emission"][cls]
            add(f"ZipWisp{cn}", r3(c["wisp"]), ZP, f"per_class_emission.{cls}.wisp")
            add(f"ZipZipper{cn}", r3(c["zipper"]), ZP, f"per_class_emission.{cls}.zipper")

    # Field validation. Plugins where the authors later received a CVE, re-scanned here with the
    # measured configuration and the optional LLM stage off, so the question the numbers answer is
    # whether the configuration this paper reports surfaces the patched file at all.
    fv_path = os.path.join(OUT, "FIELD_VALIDATION_V1.json")
    if os.path.isfile(fv_path):
        fv = load("FIELD_VALIDATION_V1.json")
        FV = "FIELD_VALIDATION_V1.json"
        add("FvPublished", str(fv["cve_published"]), FV, "cve_published")
        add("FvNotCorpus", str(fv["cve_not_in_corpus"]), FV, "cve_not_in_corpus")
        add("FvScanned", str(fv["scanned"]), FV, "scanned")
        add("FvFixConfirmed", str(fv["fix_version_confirmed_by_cna"]), FV,
            "fix_version_confirmed_by_cna")
        add("FvNonConv", str(sum(1 for r in fv["records"] if not r["converged"])), FV,
            "count(records where converged is false)")
        add("FvZeroFindings", str(sum(1 for r in fv["records"] if r["n_findings"] == 0)), FV,
            "count(records where n_findings == 0)")
        own = fv.get("own_records_in_corpus")
        if own:
            add("FvOwnN", str(own["n"]), FV, "own_records_in_corpus.n")
            add("FvOwnDelta", f"{own['delta_percentage_points']:.2f}", FV,
                "own_records_in_corpus.delta_percentage_points")
            add("FvOwnMissed", str(len(own["missed_by_wisp"])), FV,
                "len(own_records_in_corpus.missed_by_wisp)")
            # The delta above is 0.0132 percentage points, which prints as 0.01 and reads to a
            # reviewer as 0.0001. The two rates it is a difference of are what a reader can check
            # against Table 1, so the paper states those and not the delta.
            add("FvOwnEmissionAll", f"{own['class_emission_all']:.4f}", FV,
                "own_records_in_corpus.class_emission_all")
            add("FvOwnEmissionRest", f"{own['class_emission_rest']:.4f}", FV,
                "own_records_in_corpus.class_emission_rest")
        CUT = {"all scanned": "All", "not a corpus record": "Fresh", "converged": "Conv",
               "focused patch (GT<=10 files)": "Focus", "focused patch and converged": "FocusConv"}
        KW = {"1": "One", "3": "Three", "5": "Five", "10": "Ten"}
        for c in fv["cuts"]:
            tag = CUT.get(c["label"])
            if not tag:
                continue
            add(f"Fv{tag}N", str(c["n"]), FV, f"cuts[{c['label']}].n")
            for metric, mac in (("pf", "Pf"), ("cf", "Cf")):
                for K, kw in KW.items():
                    key = f"{metric}@{K}"
                    if key in c:
                        add(f"Fv{tag}{mac}{kw}", r3(c[key]), FV, f"cuts[{c['label']}].{key}")

    # CVE-year temporal cohorts. The prose carried these as literals, which is how a paragraph
    # keeps a number after the run behind it changes.
    tp_path = os.path.join(OUT, "TEMPORAL_V3.json")
    if os.path.isfile(tp_path):
        tp = load("TEMPORAL_V3.json")
        TP = "TEMPORAL_V3.json"
        add("TempOlderN", str(tp["cohorts"]["older"]["n"]), TP, "cohorts.older.n")
        add("TempRecentN", str(tp["cohorts"]["recent"]["n"]), TP, "cohorts.recent.n")
        add("TempSplitYear", str(tp["split_year"]), TP, "split_year")
        for tool, tn in (("wisp", "Wisp"), ("semgrep", "Semgrep"),
                         ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            e = tp["tools"].get(tool)
            if not e:
                continue
            for coh, cn in (("older", "Older"), ("recent", "Recent")):
                add(f"Temp{tn}{cn}", r3(e[coh]["rate"]), TP, f"tools.{tool}.{coh}.rate")
                add(f"Temp{tn}{cn}Lo", r3(e[coh]["ci95"][0]), TP, f"tools.{tool}.{coh}.ci95[0]")
                add(f"Temp{tn}{cn}Hi", r3(e[coh]["ci95"][1]), TP, f"tools.{tool}.{coh}.ci95[1]")
            dl = e["delta_older_minus_recent_ci95"]
            add(f"Temp{tn}DeltaLo", r3(dl[0]), TP,
                f"tools.{tool}.delta_older_minus_recent_ci95[0]")
            add(f"Temp{tn}DeltaHi", r3(dl[1]), TP,
                f"tools.{tool}.delta_older_minus_recent_ci95[1]")
        # The same cohorts read on patch-file localization, and WISP's emission year by year.
        # Both were prose literals in the supplement.
        pf = tp.get("wisp_patch_file_localized", {})
        for coh, cn in (("older", "Older"), ("recent", "Recent")):
            if coh in pf:
                add(f"TempWispPf{cn}", r3(pf[coh]["rate"]), TP,
                    f"wisp_patch_file_localized.{coh}.rate")
                add(f"TempWispPf{cn}Lo", r3(pf[coh]["ci95"][0]), TP,
                    f"wisp_patch_file_localized.{coh}.ci95[0]")
                add(f"TempWispPf{cn}Hi", r3(pf[coh]["ci95"][1]), TP,
                    f"wisp_patch_file_localized.{coh}.ci95[1]")
        YR = {"2023": "TwentyThree", "2024": "TwentyFour",
              "2025": "TwentyFive", "2026": "TwentySix"}
        byyear = tp.get("wisp_class_emission_by_year", {})
        for y, yn in YR.items():
            if y in byyear:
                add(f"TempYear{yn}", r2(byyear[y]["rate"]), TP,
                    f"wisp_class_emission_by_year.{y}.rate")
                add(f"TempYear{yn}N", str(byyear[y]["n"]), TP,
                    f"wisp_class_emission_by_year.{y}.n")

    # Per-tool answered counts on the matched sample. The prose used to carry these as literals
    # and still said Progpilot answered 27, which was the pre-fix exit-code run.
    mcp = os.path.join(SYS_ROOT, "revision-cns-v2", "progpilot_v3",
                       "matched100_contract_quiet_v3.json")
    if os.path.isfile(mcp):
        MS = "revision-cns-v2/progpilot_v3/matched100_contract_quiet_v3.json"
        msum = json.load(open(mcp))["summary"]
        for tool, tn in (("semgrep", "Semgrep"), ("progpilot", "Progpilot"), ("wpt", "Wpt")):
            if tool in msum:
                add(f"Answered{tn}", str(msum[tool]["answered"]), MS, f"summary.{tool}.answered")

    # Tool caps and engine identity, read from a contract run rather than restated in prose.
    # Regression test D exists because the manuscript said 25 s while every run used 60 s.
    for cand in ("testset325_contract_v3.json", "wordfence100_contract_v3.json",
                 "matched100_contract_quiet_v3.json"):
        cp = os.path.join(SYS_ROOT, "revision-cns-v2", "progpilot_v3", cand)
        if not os.path.isfile(cp):
            continue
        prov = json.load(open(cp))["provenance"]
        to = prov["timeouts_seconds"]
        src = f"revision-cns-v2/progpilot_v3/{cand}"
        add("CapSemgrep", str(to["semgrep"]), src, "provenance.timeouts_seconds.semgrep")
        add("CapProgpilot", str(to["progpilot"]), src, "provenance.timeouts_seconds.progpilot")
        add("CapWpt", str(to["wpt"]), src, "provenance.timeouts_seconds.wpt")
        cfg = prov["wisp_config"]
        # Two different things, deliberately not merged. `engine_tag` is what the run manifest
        # stamped at scan time and it is history: rewriting it in a result JSON to match a later
        # publishing decision is exactly the edit this project forbids. `EngineRelease` is the name
        # the one released version carries in the public repository, read from the code constant.
        # The sha256 below is what actually determines behaviour and is the same under either name.
        from eval import wisp_contract as _WC
        add("EngineRelease", _WC.RELEASE_TAG, "eval/wisp_contract.py", "RELEASE_TAG")
        add("EngineTag", cfg["engine_tag"], src, "provenance.wisp_config.engine_tag")
        add("EngineSha", cfg["engine_sha256"][:8], src, "provenance.wisp_config.engine_sha256[:8]")
        # The baseline arm is a configuration of the one released engine, not a second release, so
        # this prints the flags that produced it. They carry underscores, which are active in LaTeX
        # text mode, so escape them here rather than hoping every call site wraps them in \code.
        add("EngineBaselineTag", _WC.BASELINE_CONFIG.replace("_", r"\_"),
            "eval/wisp_contract.py", "BASELINE_CONFIG")
        add("EngineBaselineSha", cfg["engine_baseline_sha256"][:8], src,
            "provenance.wisp_config.engine_baseline_sha256[:8]")
        break

    # full-corpus tables under the contract failure policy (record-level rule 3)
    fc_path = os.path.join(OUT, "FULLCORPUS_FAILURE_AS_MISS_V3.json")
    if os.path.isfile(fc_path):
        fc = load("FULLCORPUS_FAILURE_AS_MISS_V3.json")
        FC = "FULLCORPUS_FAILURE_AS_MISS_V3.json"
        TN = {"wisp": "Wisp", "wpt": "Wpt", "semgrep": "Semgrep", "progpilot": "Progpilot"}
        for view, vn in (("full_1108", "Corpus"), ("common_520", "Common")):
            arms = fc["arms"][view]
            for tool, tn in TN.items():
                c = arms["contract"][tool]
                add(f"Fc{vn}{tn}Emission", r4(c["emission"]), FC,
                    f"arms.{view}.contract.{tool}.emission")
                add(f"Fc{vn}{tn}Pool", r3(c["pool"]), FC, f"arms.{view}.contract.{tool}.pool")
                # LaTeX macro names cannot contain digits, so the cutoff is spelled out,
                # exactly as the Loc* macros do.
                for K, kw in (("1", "One"), ("3", "Three"), ("5", "Five"), ("10", "Ten")):
                    add(f"Fc{vn}{tn}Pf{kw}", r3(c[f"pf@{K}"]), FC,
                        f"arms.{view}.contract.{tool}.pf@{K}")
            # WISP-minus-baseline paired intervals at corpus scale. The prose carried these as
            # literals, and one sentence was rewritten as unsupported because the interval was
            # looked for under the wrong key rather than because it was missing.
            for tool, tn in (("wpt", "Wpt"), ("semgrep", "Semgrep"), ("progpilot", "Progpilot")):
                pr = fc.get("paired", {}).get(view, {}).get(tool, {})
                for ep, en in (("pool", "Pool"), ("emission", "Emission"), ("pf@1", "PfOne")):
                    if ep not in pr:
                        continue
                    add(f"Fc{vn}{tn}{en}DiffLo", r3(pr[ep]["lo"]), FC,
                        f"paired.{view}.{tool}.{ep}.lo")
                    add(f"Fc{vn}{tn}{en}DiffHi", r3(pr[ep]["hi"]), FC,
                        f"paired.{view}.{tool}.{ep}.hi")
            add(f"Fc{vn}WispEmissionKept", r4(arms["kept"]["wisp"]["emission"]), FC,
                f"arms.{view}.kept.wisp.emission")
            add(f"Fc{vn}N", str(arms["contract"]["wisp"]["n"]), FC,
                f"arms.{view}.contract.wisp.n")
        add("FcNonConv", str(fc["n_known_non_converged"]), FC, "n_known_non_converged")

    ts_path = os.path.join(OUT, "TESTSET325_TABLE_V3.json")
    if os.path.isfile(ts_path):
        ts = load("TESTSET325_TABLE_V3.json")
        TS = "TESTSET325_TABLE_V3.json"
        TN = {"wisp": "Wisp", "wpt": "Wpt", "semgrep": "Semgrep", "progpilot": "Progpilot"}
        ML = {"class emission": "Class", "patch-file@1": "PfOne", "patch-file@10": "PfTen",
              "class-and-file@1": "CfOne", "class-and-file@10": "CfTen"}
        for tool, tn in TN.items():
            for label, ln in ML.items():
                c = (ts["cells"].get(tool) or {}).get(label)
                if c:
                    add(f"Ts{tn}{ln}", r3(c["rate"]), TS, f"cells.{tool}.{label}.rate")
            add(f"Ts{tn}Coverage", r3(ts["coverage"][tool]), TS, f"coverage.{tool}")
        add("TsNonConv", str(ts["wisp_non_converged"]), TS, "wisp_non_converged")
        add("TsN", str(ts["n_records"]), TS, "n_records")

    lt_path = os.path.join(OUT, "WORDFENCE_LADDER_TRUE_V3.json")
    if os.path.isfile(lt_path):
        lt = load("WORDFENCE_LADDER_TRUE_V3.json")["ladder"]
        LT = "WORDFENCE_LADDER_TRUE_V3.json"
        for tool, tn in (("wisp", "Wisp"), ("wpt", "Wpt"),
                         ("semgrep", "Semgrep"), ("progpilot", "Progpilot")):
            e = lt.get(tool) or {}
            for rung, rn in (("in_patched_file", "File"), ("on_exact_changed_line", "Exact"),
                             ("within_5_changed_lines", "Prox")):
                if rung in e:
                    add(f"ExtLadder{tn}{rn}", r3(e[rung][0]), LT, f"ladder.{tool}.{rung}[0]")
            if "in_patched_file" in e:
                add(f"ExtLadder{tn}N", str(e["in_patched_file"][2]), LT,
                    f"ladder.{tool}.in_patched_file[2]")

    # per-mechanism patch-file precision on the contract finding population
    mp = load("MECH_PRECISION_V3.json")
    MP = "MECH_PRECISION_V3.json"
    mmap = {"proven-taint": "MechTaint", "missing-guard": "MechGuard", "risk-pattern": "MechRisk"}
    for jk, Mc in mmap.items():
        d = mp["mechanisms"][jk]
        add(f"{Mc}Prec", r3(d["file_precision"]), MP, f"mechanisms.{jk}.file_precision")
        add(f"{Mc}N", str(d["findings"]), MP, f"mechanisms.{jk}.findings")
        add(f"{Mc}Lo", r3(d["ci95"][0]), MP, f"mechanisms.{jk}.ci95[0]")
        add(f"{Mc}Hi", r3(d["ci95"][1]), MP, f"mechanisms.{jk}.ci95[1]")
    add("MechAllPrec", r3(mp["all_mechanisms"]["file_precision"]), MP, "all_mechanisms.file_precision")
    add("MechAllN", str(mp["all_mechanisms"]["findings"]), MP, "all_mechanisms.findings")
    add("MechBootReps", f"{mp['bootstrap_replicates']:,}", MP, "bootstrap_replicates (comma-formatted)")

    # AI-generated adjudication attempt of 2026-08-03. Reported as a property of the instrument,
    # never as a defect-level rate for a tool: the blinding key was not opened, so nothing here can
    # be attributed to any scanner.
    aj_path = os.path.join(OUT, "AI_ADJUDICATION_V3.json")
    if os.path.isfile(aj_path):
        aj = load("AI_ADJUDICATION_V3.json")
        AJ = "AI_ADJUDICATION_V3.json"
        add("AiAdjNPackets", str(aj["n_packets_labelled_by_both"]), AJ,
            "n_packets_labelled_by_both")
        axmap = {"class_relation": "Class", "root_cause_relation": "Root",
                 "evidence_quality": "Evid", "confidence": "Conf", "reason_code": "Reason"}
        for jk, nm in axmap.items():
            d = aj["axes"][jk]
            add(f"AiAdj{nm}Agree", r3(d["raw_agreement"]), AJ, f"axes.{jk}.raw_agreement")
            add(f"AiAdj{nm}Kappa", r3(d["cohens_kappa"]), AJ, f"axes.{jk}.cohens_kappa")
            ci = d["kappa_ci95_record_bootstrap"]
            add(f"AiAdj{nm}Lo", r3(ci[0]), AJ, f"axes.{jk}.kappa_ci95_record_bootstrap[0]")
            add(f"AiAdj{nm}Hi", r3(ci[1]), AJ, f"axes.{jk}.kappa_ci95_record_bootstrap[1]")
        s = aj["same_defect"]
        add("AiAdjSameA", str(s["A"]), AJ, "same_defect.A")
        add("AiAdjSameB", str(s["B"]), AJ, "same_defect.B")
        add("AiAdjSameBoth", str(s["agreed_by_both"]), AJ, "same_defect.agreed_by_both")
        add("AiAdjSameRatio", f"{s['ratio_larger_over_smaller']:.2f}", AJ,
            "same_defect.ratio_larger_over_smaller")
        add("AiAdjSameRate", r3(s["agreed_rate_over_all_packets"]), AJ,
            "same_defect.agreed_rate_over_all_packets")
        cc = aj["cross_class_collapse"]
        for tag, nm in (("A", "A"), ("B", "B"), ("both", "Both")):
            add(f"AiAdjCross{nm}", str(cc[tag]["cross_class"]), AJ,
                f"cross_class_collapse.{tag}.cross_class")
            add(f"AiAdjCollapse{nm}", r3(cc[tag]["rate"]), AJ,
                f"cross_class_collapse.{tag}.rate")
        for tag in ("A", "B"):
            add(f"AiAdjBlank{tag}", str(aj["completeness"][tag]["tier2_blank"]), AJ,
                f"completeness.{tag}.tier2_blank")
            add(f"AiAdjCells{tag}", str(aj["completeness"][tag]["tier2_cells"]), AJ,
                f"completeness.{tag}.tier2_cells")
        add("AiAdjBootReps", f"{aj['provenance']['bootstrap']['B']:,}", AJ,
            "provenance.bootstrap.B (comma-formatted)")

    # The defect-level study. Reported on annotator B, the reading that declared no knowledge of
    # the study's objective, with annotator A beside it. A is the more generous of the two, so the
    # headline is the lower reading and the sensitivity runs against the paper's own claim. The
    # geometric rates are recomputed on the same 200 findings, because the whole contrast is
    # meaningless if the two are read on different samples.
    # The file is enveloped, like the other adjudication artifacts, so it carries a content hash.
    # The pointers below name the real path including that envelope, not a tidied one.
    ds = load("DEFECT_STUDY_RESULT_V3.json")["payload"]
    DS = "DEFECT_STUDY_RESULT_V3.json"

    def dsr(x):
        """Two decimals, leading zero kept. An earlier version stripped it on the belief that the
        ladder rates print that way. They do not: the body carries 109 rates as 0.xx and the only
        12 without the zero were these, so the study's numbers were the odd ones on the page."""
        return f"{x:.2f}"

    for who in ("A", "B"):
        pl = ds["pooled"][who]
        add(f"DsPooled{who}", dsr(pl["rate"]), DS, f"payload.pooled.{who}.rate")
        add(f"DsPooled{who}Lo", dsr(pl["ci95"][0]), DS, f"payload.pooled.{who}.ci95[0]")
        add(f"DsPooled{who}Hi", dsr(pl["ci95"][1]), DS, f"payload.pooled.{who}.ci95[1]")
    DST = {"wisp": "Wisp", "semgrep": "Semgrep", "wpt": "Wpt", "progpilot": "Progpilot"}
    for t, nm in DST.items():
        if t not in ds["per_tool"]:
            continue
        b = ds["per_tool"][t]["B"]
        add(f"Ds{nm}", dsr(b["rate"]), DS, f"payload.per_tool.{t}.B.rate")
        add(f"Ds{nm}Lo", dsr(b["ci95"][0]), DS, f"payload.per_tool.{t}.B.ci95[0]")
        add(f"Ds{nm}Hi", dsr(b["ci95"][1]), DS, f"payload.per_tool.{t}.B.ci95[1]")
        add(f"Ds{nm}N", str(b["n"]), DS, f"payload.per_tool.{t}.B.n")
        add(f"DsFile{nm}", dsr(ds["geometry_same_sample"]["in_patched_file"][t]["rate"]), DS,
            f"payload.geometry_same_sample.in_patched_file.{t}.rate")
    # Which population the 200 were drawn from, and what each tool's share of it would put in a
    # 200-finding sample. The reviewer read the sample's 11 Progpilot findings against the corpus
    # population, where 21 would be proportional, and the paper never said the frame is a different
    # population. The stratification axes are advisory class, patch shape and plugin size, so the
    # tool mix is a consequence of those and not a quota, which is why WISP is under its own share.
    fc = ds.get("frame_composition")
    if fc:
        add("DsFrameN", str(fc["n_findings"]), DS, "payload.frame_composition.n_findings")
        for t, nm in DST.items():
            if t not in fc["per_tool"]:
                continue
            ft = fc["per_tool"][t]
            add(f"DsFrame{nm}N", str(ft["n_frame"]), DS,
                f"payload.frame_composition.per_tool.{t}.n_frame")
            add(f"DsFrame{nm}Expected", f"{ft['expected_in_sample']:.1f}", DS,
                f"payload.frame_composition.per_tool.{t}.expected_in_sample")

    for g, nm in (("in_patched_file", "File"), ("same_callable_as_change", "Callable"),
                  ("on_exact_changed_line", "Exact")):
        add(f"DsGeo{nm}", dsr(ds["geometry_same_sample"][g]["pooled"]["rate"]), DS,
            f"payload.geometry_same_sample.{g}.pooled.rate")
        # Two decimals round the file rung's 0.485 down to 0.48, and 0.48 over the blind arm's 0.08
        # is 6.0 where the reported factor is 6.1. A reader who divides the two printed rates then
        # gets a different number from the one the sentence states, which is the defect an outside
        # reviewer raised. Three decimals is the printing at which the headline reproduces, so the
        # prose that states the factor uses this macro.
        add(f"DsGeo{nm}Exact", r3(ds["geometry_same_sample"][g]["pooled"]["rate"]), DS,
            f"payload.geometry_same_sample.{g}.pooled.rate")
    ag = ds["agreement"]["root_cause_relation"]
    add("DsKappa", f"{ag['cohens_kappa']:.2f}", DS, "payload.agreement.root_cause_relation.cohens_kappa")
    add("DsKappaLo", f"{ag['kappa_ci95_record_cluster'][0]:.2f}", DS,
        "payload.agreement.root_cause_relation.kappa_ci95_record_cluster[0]")
    add("DsKappaHi", f"{ag['kappa_ci95_record_cluster'][1]:.2f}", DS,
        "payload.agreement.root_cause_relation.kappa_ci95_record_cluster[1]")
    add("DsKappaClass", f"{ds['agreement']['class_relation']['cohens_kappa']:.2f}", DS,
        "payload.agreement.class_relation.cohens_kappa")
    add("DsN", str(ds["config"]["n_findings"]), DS, "payload.config.n_findings")
    add("DsRecords", str(ds["config"]["n_records"]), DS, "payload.config.n_records")
    add("DsUnresolved", str(ds["disagreement"]["n_disputed_root_cause"]), DS,
        "payload.disagreement.n_disputed_root_cause")
    # The overstatement factor and its interval. Two intervals are emitted because the study now
    # carries two, and they are not interchangeable. DsFactor{A,B}{Lo,Hi} is the superseded plug-in
    # interval: the geometric rate held at its point estimate, divided by the endpoints of the
    # annotator's own rate interval. It gives the numerator no variance and it treats two rates read
    # off one sample of 200 findings as if the sample had been drawn twice. It stays defined because
    # the earlier prose quoted it. DsFactor{A,B}Paired{Lo,Hi} is the paired slug-cluster bootstrap
    # and is the one a sentence about the factor should cite.
    of = ds["overstatement_factor"]
    for who in ("A", "B"):
        add(f"DsFactor{who}", f"{of[who]['point']:.1f}", DS,
            f"payload.overstatement_factor.{who}.point")
        add(f"DsFactor{who}Lo", f"{of[who]['from_rate_ci95'][0]:.1f}", DS,
            f"payload.overstatement_factor.{who}.from_rate_ci95[0]")
        add(f"DsFactor{who}Hi", f"{of[who]['from_rate_ci95'][1]:.1f}", DS,
            f"payload.overstatement_factor.{who}.from_rate_ci95[1]")
        pc = of[who]["paired_cluster_bootstrap_ci95"]
        add(f"DsFactor{who}PairedLo", f"{pc['ci95'][0]:.1f}", DS,
            f"payload.overstatement_factor.{who}.paired_cluster_bootstrap_ci95.ci95[0]")
        add(f"DsFactor{who}PairedHi", f"{pc['ci95'][1]:.1f}", DS,
            f"payload.overstatement_factor.{who}.paired_cluster_bootstrap_ci95.ci95[1]")
    _pcb = of["B"]["paired_cluster_bootstrap_ci95"]
    add("DsFactorBootReps", f"{_pcb['replicates']:,}", DS,
        "payload.overstatement_factor.B.paired_cluster_bootstrap_ci95.replicates "
        "(comma-formatted)")
    add("DsFactorBootSeed", str(_pcb["seed"]), DS,
        "payload.overstatement_factor.B.paired_cluster_bootstrap_ci95.seed")
    add("DsFactorBootUnit", str(_pcb["cluster_unit"]).replace("_", " "), DS,
        "payload.overstatement_factor.B.paired_cluster_bootstrap_ci95.cluster_unit "
        "(underscores to spaces)")

    ex = ds.get("excluded_reconciliation")
    if ex:
        add("DsExclResolved", str(ex["n_resolved"]), DS,
            "payload.excluded_reconciliation.n_resolved")
        add("DsExclToB", str(ex["adopted_annotator_B"]), DS,
            "payload.excluded_reconciliation.adopted_annotator_B")
        add("DsExclToA", str(ex["adopted_annotator_A"]), DS,
            "payload.excluded_reconciliation.adopted_annotator_A")
        add("DsExclPooled", dsr(ex["pooled_rate_if_included"]), DS,
            "payload.excluded_reconciliation.pooled_rate_if_included")
        # Two decimals round 0.075 to 0.07, one tick below the 0.08 the sentence compares it
        # against, so the printed move reads as 0.01 where the true move is 0.005 and the artifact
        # README, which states 0.005, stops agreeing with the paper. Three decimals is the only
        # printing at which the two documents can be cross-checked, so the prose uses this one.
        add("DsExclPooledExact", r3(ex["pooled_rate_if_included"]), DS,
            "payload.excluded_reconciliation.pooled_rate_if_included")

    # Rank correlation between the two ends of the ladder, at each unit of analysis. Four readings
    # are emitted rather than one because they disagree, and a section that reported only the
    # convenient unit would be the same error the paper is about.
    rk = load("RANK_CORRELATION_V3.json")
    RK = "RANK_CORRELATION_V3.json"
    RKT = {"wisp": "Wisp", "semgrep": "Semgrep", "wpt": "Wpt", "progpilot": "Progpilot",
           "pooled": "Pooled"}

    def rsign(x):
        return f"{x:+.3f}"

    def rkp(v):
        """A p-value as math-mode content, the same convention the paired family uses."""
        if v is None:
            return "--"
        if v >= 1e-3:
            return f"{v:.3f}"
        e = 0
        while v < 1:
            v *= 10
            e += 1
        return f"{v:.1f}\\times 10^{{-{e}}}"

    for arm, nm in (("corpus_contract", "Corpus"), ("corpus_kept", "Kept"),
                    ("matched_kept", "Matched")):
        c = rk["by_tool"][arm]
        add(f"RkTool{nm}Rho", rsign(c["rho"]), RK, f"by_tool.{arm}.rho")
        add(f"RkTool{nm}P", rkp(c["p"]), RK, f"by_tool.{arm}.p")
        add(f"RkTool{nm}Lo", rsign(c["ci95"][0]), RK, f"by_tool.{arm}.ci95[0]")
        add(f"RkTool{nm}Hi", rsign(c["ci95"][1]), RK, f"by_tool.{arm}.ci95[1]")
    add("RkToolN", str(rk["by_tool"]["corpus_contract"]["n_units"]), RK,
        "by_tool.corpus_contract.n_units")

    for tk, Tc in RKT.items():
        pl = rk["by_plugin"]["contract"][tk]
        add(f"RkPlug{Tc}Rho", rsign(pl["rho"]), RK, f"by_plugin.contract.{tk}.rho")
        add(f"RkPlug{Tc}Lo", rsign(pl["ci95"][0]), RK, f"by_plugin.contract.{tk}.ci95[0]")
        add(f"RkPlug{Tc}Hi", rsign(pl["ci95"][1]), RK, f"by_plugin.contract.{tk}.ci95[1]")
        add(f"RkPlug{Tc}N", str(pl["n_units"]), RK, f"by_plugin.contract.{tk}.n_units")
        add(f"RkPlug{Tc}P", rkp(pl["p"]), RK, f"by_plugin.contract.{tk}.p")
        add(f"RkPlug{Tc}Holm", rkp(pl.get("p_holm")), RK, f"by_plugin.contract.{tk}.p_holm")
        add(f"RkPlug{Tc}Zero", r3(pl["slugs_scoring_zero_at_fine_rung"]), RK,
            f"by_plugin.contract.{tk}.slugs_scoring_zero_at_fine_rung")
        add(f"RkPlug{Tc}KeptRho", rsign(rk["by_plugin"]["kept"][tk]["rho"]), RK,
            f"by_plugin.kept.{tk}.rho")

        cl = rk["by_class"]["contract"][tk]
        add(f"RkCls{Tc}Rho", rsign(cl["rho"]), RK, f"by_class.contract.{tk}.rho")
        add(f"RkCls{Tc}Lo", rsign(cl["ci95"][0]), RK, f"by_class.contract.{tk}.ci95[0]")
        add(f"RkCls{Tc}Hi", rsign(cl["ci95"][1]), RK, f"by_class.contract.{tk}.ci95[1]")
        add(f"RkCls{Tc}K", str(cl["n_units"]), RK, f"by_class.contract.{tk}.n_units")
        add(f"RkCls{Tc}P", rkp(cl["p"]), RK, f"by_class.contract.{tk}.p")
        add(f"RkCls{Tc}Holm", rkp(cl.get("p_holm")), RK, f"by_class.contract.{tk}.p_holm")

    for tk in ("wisp", "semgrep", "wpt", "progpilot"):
        Tc = RKT[tk]
        for jk, rn in (("coarse_patch_file", "File"), ("fine_exact_line", "Exact")):
            d = rk["by_own_rank"][tk][jk]
            add(f"RkOwn{Tc}{rn}Rho", rsign(d["rho"]), RK, f"by_own_rank.{tk}.{jk}.rho")
            add(f"RkOwn{Tc}{rn}Lo", rsign(d["ci95"][0]), RK, f"by_own_rank.{tk}.{jk}.ci95[0]")
            add(f"RkOwn{Tc}{rn}Hi", rsign(d["ci95"][1]), RK, f"by_own_rank.{tk}.{jk}.ci95[1]")
        add(f"RkOwn{Tc}N", str(rk["by_own_rank"][tk]["coarse_patch_file"]["n_units"]), RK,
            f"by_own_rank.{tk}.coarse_patch_file.n_units")

    add("RkFamilySize", str(rk["holm_family"]["size"]), RK, "holm_family.size")
    add("RkFamilySurvive", str(len(rk["holm_family"]["survive"])), RK,
        "len(holm_family.survive)")
    add("RkFamilyFail", str(rk["holm_family"]["size"] - len(rk["holm_family"]["survive"])), RK,
        "holm_family.size - len(holm_family.survive)")
    add("RkMinClass", str(rk["min_class_findings"]), RK, "min_class_findings")
    add("RkBootReps", f'{rk["bootstrap_replicates"]:,}', RK,
        "bootstrap_replicates (comma-formatted)")

    # --- endpoint transfer across two independent ground-truth sources (P0-7, 2026-08-11) -------
    # Whether the endpoint reorders the tools when the ground truth changes source. This does not
    # establish that a finding names the disclosed defect, which needs P1-A, and the JSON says so.
    et = load("ENDPOINT_TRANSFER_V3.json")
    ET = "ENDPOINT_TRANSFER_V3.json"
    ETR = (("in_patched_file", "File"), ("same_callable_as_change", "Call"),
           ("on_exact_changed_line", "Exact"), ("within_5_changed_lines", "Prox"),
           ("same_diff_hunk", "Hunk"))
    ETT = {"wisp": "Wisp", "wpt": "Wpt", "semgrep": "Semgrep", "progpilot": "Progpilot"}
    ETNAME = {"wisp": "WISP", "wpt": "wp-taint-scan", "semgrep": "Semgrep",
              "progpilot": "Progpilot"}

    for jk, rn in ETR:
        p = et["per_rung"][jk]
        add(f"Et{rn}Rho", rsign(p["spearman_rho"]), ET, f"per_rung.{jk}.spearman_rho")
        add(f"Et{rn}Lo", rsign(p["ci95"][0]), ET, f"per_rung.{jk}.ci95[0]")
        add(f"Et{rn}Hi", rsign(p["ci95"][1]), ET, f"per_rung.{jk}.ci95[1]")
        add(f"Et{rn}LeadPs", ETNAME[p["leader_patchstack"]], ET,
            f"per_rung.{jk}.leader_patchstack")
        add(f"Et{rn}LeadWf", ETNAME[p["leader_wordfence"]], ET,
            f"per_rung.{jk}.leader_wordfence")
        for tk, Tc in ETT.items():
            add(f"Et{rn}Ps{Tc}", f'{p["patchstack_rate"][tk]:.3f}', ET,
                f"per_rung.{jk}.patchstack_rate.{tk}")
            add(f"Et{rn}Wf{Tc}", f'{p["wordfence_rate"][tk]:.3f}', ET,
                f"per_rung.{jk}.wordfence_rate.{tk}")

    add("EtPsRecords", str(et["sources"]["patchstack"]["records"]), ET,
        "sources.patchstack.records")
    add("EtPsPlugins", str(et["sources"]["patchstack"]["plugins"]), ET,
        "sources.patchstack.plugins")
    add("EtWfRecords", str(et["sources"]["wordfence"]["records"]), ET,
        "sources.wordfence.records")
    add("EtWfPlugins", str(et["sources"]["wordfence"]["plugins"]), ET,
        "sources.wordfence.plugins")
    add("EtNRungs", str(et["summary"]["n_rungs"]), ET, "summary.n_rungs")
    add("EtNLeaderAgree", str(et["summary"]["n_leader_agree"]), ET, "summary.n_leader_agree")
    add("EtReps", f'{et["bootstrap_replicates"]:,}', ET,
        "bootstrap_replicates (comma-formatted)")

    # magnitudes for the ground-truth definition corrections. The prose said the callable rung needs
    # a named function and that the second refinement of tab:exact is a hunk endpoint; the scorer
    # matches lexical scope including top level and uses proximity@5 there. These counts say how far
    # apart the two readings are on the shipped population, so the corrected sentences cite a
    # measured magnitude instead of a number someone typed after reading a grep.
    # The equal-budget cell split into the two quantities it multiplies: throughput and accuracy on
    # the work actually finished. The paper reports the product against itself, which invites a
    # reader to read a throughput result as an analysis result.
    bd_path = os.path.join(OUT, "BUDGET_DECOMPOSITION_V3.json")
    if os.path.isfile(bd_path):
        bd = load("BUDGET_DECOMPOSITION_V3.json")
        BD = "BUDGET_DECOMPOSITION_V3.json"
        for bud, word in (("25", "TwentyFive"), ("60", "Sixty")):
            row = bd["per_budget"].get(bud) or {}
            for tool, tn in (("wisp", "Wisp"), ("wpt", "Wpt")):
                c = row.get(tool)
                if not c:
                    continue
                add(f"Bud{word}{tn}Thru", r3(c["throughput"]), BD,
                    f"per_budget.{bud}.{tool}.throughput")
                add(f"Bud{word}{tn}Acc", r3(c["accuracy_on_completed"]), BD,
                    f"per_budget.{bud}.{tool}.accuracy_on_completed")
            cf = (bd.get("counterfactual") or {}).get(bud)
            if cf:
                add(f"Bud{word}WispAtWptThru", r3(cf["wisp_at_baseline_throughput"]), BD,
                    f"counterfactual.{bud}.wisp_at_baseline_throughput")

    # The missing-guard share of the corpus, typed as "38%" in two summary sections because no macro
    # carried it. The abstract and body literal checks look for decimals, so a percent literal walked
    # straight past both. It is auth plus csrf over the corpus, and the pair is the claim, so it is
    # derived here rather than left as a number a reader has to recompute.
    pc_path = os.path.join(OUT, "PERCLASS_CONTRACT_V3.json")
    if os.path.isfile(pc_path):
        pc = load("PERCLASS_CONTRACT_V3.json")["per_class"]
        n_mg = pc["auth"]["n"] + pc["csrf"]["n"]
        add("MissingGuardRecords", str(n_mg), "PERCLASS_CONTRACT_V3.json",
            "per_class.auth.n + per_class.csrf.n")
        add("MissingGuardShare", f"{round(100 * n_mg / 1108)}\\%", "PERCLASS_CONTRACT_V3.json",
            "(per_class.auth.n + per_class.csrf.n) / 1108, rounded to a whole percent")

    lp_path = os.path.join(OUT, "LADDER_PREDICATE_AUDIT_V3.json")
    if os.path.isfile(lp_path):
        # The macro guard cannot catch a stale copy of this file. It re-derives each macro from its
        # source JSON, so a stale JSON and a stale macro agree with each other and pass. The only
        # thing that detects it is the input being newer than the output, so check that here and
        # refuse rather than emit a count describing a population that no longer exists.
        _pop = os.path.join(SYS_ROOT, "revision-cns-v2", "data", "FINDING_POPULATION_V3.jsonl")
        if os.path.isfile(_pop) and os.path.getmtime(_pop) > os.path.getmtime(lp_path):
            sys.exit(
                f"STALE: {os.path.basename(_pop)} is newer than "
                f"{os.path.basename(lp_path)}, so the ladder-predicate macros would describe the "
                f"previous population. Run `python3 -m eval.ladder_predicate_audit_v3` first.")
        lp = load("LADDER_PREDICATE_AUDIT_V3.json")
        LP = "LADDER_PREDICATE_AUDIT_V3.json"
        add("NPopTopThree", str(lp["n_top_k"]), LP, "n_top_k")
        add("PredCallableTopLevel", str(lp["callable_rung_won_at_top_level"]["n"]), LP,
            "callable_rung_won_at_top_level.n")
        add("PredHunkNotProx", str(lp["same_hunk_without_proximity5"]["n"]), LP,
            "same_hunk_without_proximity5.n")
        add("PredProxNotHunk", str(lp["proximity5_without_same_hunk"]["n"]), LP,
            "proximity5_without_same_hunk.n")


def emit():
    # 1. copy the analyze_v3 primary macros verbatim into the build dir (the named include)
    src_primary = os.path.join(OUT, "LATEX_MACROS_V3.tex")
    dst_primary = os.path.join(LATEX, "LATEX_MACROS_V3.tex")
    shutil.copyfile(src_primary, dst_primary)
    primary_names = set()
    for line in open(src_primary):
        line = line.strip()
        if line.startswith("\\newcommand{\\"):
            primary_names.add(line.split("{\\", 1)[1].split("}", 1)[0])

    # 2. write PAPER_MACROS_V3.tex: input the primary file, then define only the NEW macros
    lines = ["% Auto-generated by eval/build_paper_macros_v3.py. Do not edit by hand.",
             "% Primary geometric-ladder macros come from LATEX_MACROS_V3.tex (analyze_v3.py).",
             "\\input{LATEX_MACROS_V3.tex}", ""]
    manifest = {}
    for name, (val, src, ptr) in MACROS.items():
        manifest[name] = {"value": val, "json": src, "pointer": ptr}
        if name in primary_names:
            continue                       # already defined by the primary file
        lines.append("\\newcommand{\\%s}{%s}" % (name, val))
    open(os.path.join(LATEX, "PAPER_MACROS_V3.tex"), "w").write("\n".join(lines) + "\n")
    json.dump({"generated_from": os.path.relpath(OUT, SYS_ROOT), "macros": manifest,
               "primary_file_macros": sorted(primary_names)},
              open(os.path.join(LATEX, "PAPER_MACROS_V3.manifest.json"), "w"), indent=1)
    return primary_names


def main():
    build()
    primary = emit()
    print(f"wrote LATEX_MACROS_V3.tex ({len(primary)} primary macros) + PAPER_MACROS_V3.tex "
          f"({len(MACROS)} total macros, {len(MACROS) - len(primary & set(MACROS))} new) -> {LATEX}")
    print(f"manifest: PAPER_MACROS_V3.manifest.json ({len(MACROS)} entries)")


if __name__ == "__main__":
    main()
