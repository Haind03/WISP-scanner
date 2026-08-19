"""Run the revision-v2 regression tests and report each against its expected state.

The suite began as seven tests written to FAIL while their bug was present (a red
pre-fix baseline). As staged fixes land, a bug's test is moved from PENDING (still
expected to fail) to FIXED (now expected to pass). Prompt 6 fixed bugs E (sanitizer
default: manuscript corrected to match the engine) and F (silent non-convergence:
structured status surfaced), and added the Prompt-6 formalism/convergence module.

    python3 -m eval.tests.revision_v2.run_all

Exit 0 = every PENDING test still fails as expected, every FIXED test passes, and
the Prompt-6 module passes. Exit 1 = anything is off (a pending bug vanished
without a recorded fix, a fixed test regressed, or a new test failed).
"""
from __future__ import annotations
import importlib, traceback
from . import _common  # noqa: F401  (adds repo root to sys.path)

# Bugs whose fix has NOT landed: each test must still FAIL, so a bug cannot quietly vanish.
# Empty as of 2026-08-03: A, B and C were the last three, and all three were closed by moving
# the property under test onto the live v3 protocol rather than by repairing the retired v2
# builder that no longer feeds any claim. Add an entry here the moment a new bug is found and
# not yet fixed; an empty list is a statement, not a default.
# AF was opened here on 2026-08-19 and closed the same day. It was listed while the JSON and the
# macros carried a paired slug-cluster interval and the manuscript still printed the superseded
# plug-in endpoints, which is a half-landed correction and was recorded as one. The manuscript now
# prints the paired interval in the defect-study paragraph, so the entry moved to FIXED rather than
# being deleted, because a pending bug that disappears without a recorded fix is indistinguishable
# from one that was quietly dropped.
PENDING = [
]
# bugs FIXED by a landed prompt: each test must now PASS
FIXED = [
    ("AF. documents cite the paired interval", ".test_af_paired_ratio_interval",
     "test_the_documents_cite_the_paired_interval"),
    ("E. sanitizer default (Prompt 6)", ".test_e_sanitizer_default", "test_sanitizer_default_matches_manuscript"),
    ("F. fixpoint completion status (Prompt 6)", ".test_f_fixpoint_completion", "test_nonconvergence_is_surfaced"),
    ("A. reviewer context shows the changed line (v3)", ".test_a_patch_truncation",
     "test_reviewer_context_shows_the_changed_line"),
    ("A. retired v2 builder unreachable", ".test_a_patch_truncation",
     "test_retired_v2_builder_is_not_reachable_from_the_pipeline"),
    ("A. no length cap in the v3 context", ".test_a_patch_truncation",
     "test_v3_context_builder_has_no_length_cap"),
    ("B. finding_uid separates rows v2 merged", ".test_b_identifier_collision",
     "test_finding_id_is_unique_per_row"),
    ("C. v2 contamination still on record", ".test_c_construct_contamination",
     "test_v2_contamination_is_still_on_record"),
    ("C. v3 axes allow a location-only verdict", ".test_c_construct_contamination",
     "test_v3_schema_lets_a_cross_class_finding_be_judged_on_location"),
    ("C. validator guards the collapse", ".test_c_construct_contamination",
     "test_validator_guards_against_the_collapse_recurring"),
    ("D. Progpilot cap: stated == what ran", ".test_d_timeout_provenance",
     "test_progpilot_timeout_matches_manuscript"),
    ("G. generated-bundle provenance (shipped script)", ".test_g_bundle_provenance",
     "test_no_posthoc_provenance_rewrite"),
    ("H. Progpilot exit-code discard (path B)", ".test_h_progpilot_exit_code",
     "test_progpilot_runners_agree_on_nonzero_exit"),
    ("I. scan_testset contract env (path B)", ".test_i_scan_testset_contract",
     "test_scan_testset_applies_the_canonical_contract_env"),
    ("I. scan_testset rule 3 (path B)", ".test_i_scan_testset_contract",
     "test_scan_testset_records_and_enforces_non_convergence"),
    ("I. one changed-line ground truth (path B)", ".test_i_scan_testset_contract",
     "test_one_ground_truth_module_for_changed_lines"),
    # J. Rewritten 2026-08-12 for the v1.3 engine. v1.3 is deliberately NOT behaviour-preserving, so
    # the old "identical to v1.1" assertions were retired by declaring a version rather than by
    # relaxing them. What replaces them is stricter in the ways that still matter: the diff against
    # v1.2 is attributed block by block, the two new defaults must be recoverable, and the
    # no-regression claim must rest on a stored 1108-record comparison instead of on a comment.
    ("J. engine stamp is the file that ran (path B)", ".test_j_engine_identity",
     "test_contract_stamps_the_engine_that_actually_ran"),
    ("J. contract declares v1.3 against v1.2", ".test_j_engine_identity",
     "test_the_contract_declares_v13_against_the_v12_baseline"),
    ("J. engine diff confined to declared blocks", ".test_j_engine_identity",
     "test_the_v13_defaults_are_the_only_engine_difference_from_v12"),
    ("J. v1.2 behaviour is recoverable", ".test_j_engine_identity",
     "test_v12_behaviour_is_recoverable"),
    ("J. recovered cap reproduces the v1.1 bound", ".test_j_engine_identity",
     "test_global_cap_at_the_recovered_cap_matches_v11_exactly"),
    ("J. trace instrumentation is inert", ".test_j_engine_identity",
     "test_the_trace_instrumentation_is_inert_by_default"),
    ("J. no-regression claim has stored evidence", ".test_j_engine_identity",
     "test_the_no_regression_claim_rests_on_a_stored_comparison"),
    ("K. class-and-file cells are contract values", ".test_k_broken_class_in_tables",
     "test_class_and_file_cells_are_not_the_broken_class_run"),
    ("K. no claim rests on broken-class cells", ".test_k_broken_class_in_tables",
     "test_no_claim_rests_on_the_broken_class_numbers"),
    ("H-data. contract runs keep every Progpilot record", ".test_h_progpilot_exit_code",
     "test_no_progpilot_record_is_dropped_for_its_exit_code"),
    ("I-data. contract runs stamp the contract", ".test_i_scan_testset_contract",
     "test_shipped_scan_testset_results_stamp_the_contract"),
    ("L. sensitivity override survives _wisp_ranked", ".test_l_env_override_clobber",
     "test_caller_env_override_survives_wisp_ranked"),
    ("L. the two ablation arms differ", ".test_l_env_override_clobber",
     "test_ablation_arms_are_not_identical_by_construction"),
    ("M. contract arm withholds, kept arm does not", ".test_m_corpus_ladder_arms",
     "test_contract_withholds_and_kept_does_not"),
    ("M. arms coincide with nothing withheld", ".test_m_corpus_ladder_arms",
     "test_arms_coincide_when_nothing_is_withheld"),
    ("M. shipped corpus population is unmasked", ".test_m_corpus_ladder_arms",
     "test_shipped_population_is_unmasked"),
    ("M. shipped arms reproduce from the population", ".test_m_corpus_ladder_arms",
     "test_shipped_arms_agree_with_the_population"),
    ("M. the drop is the paired difference", ".test_m_corpus_ladder_arms",
     "test_primary_effect_is_the_paired_difference"),
    ("M. every tool carries the drop and its interval", ".test_m_corpus_ladder_arms",
     "test_primary_effect_ships_for_every_tool_in_both_arms"),
    ("M. drop interval is not the marginal difference", ".test_m_corpus_ladder_arms",
     "test_primary_effect_interval_is_not_the_marginal_difference"),
    ("M. the drop follows the failure policy", ".test_m_corpus_ladder_arms",
     "test_primary_effect_follows_the_arm"),
    ("N. an out-of-memory kill is refused", ".test_n_host_failure_audit",
     "test_sigkill_is_refused"),
    ("N. ordinary tool failures stay clean", ".test_n_host_failure_audit",
     "test_ordinary_tool_failures_are_clean"),
    ("N. burst refused, stray archive error kept", ".test_n_host_failure_audit",
     "test_archive_error_burst_is_refused_but_a_stray_one_is_not"),
    ("N. host memory floor invalidates a cell", ".test_n_host_failure_audit",
     "test_host_memory_floor_is_refused"),
    # Both closed 2026-08-10 by re-measurement under the declared memory budget, not by relaxing
    # the rule: every shipped cell now audits clean, and an unreported budget must carry its reason.
    ("N. shipped matched-100 cells are clean", ".test_n_host_failure_audit",
     "test_shipped_matched100_cells_are_clean"),
    ("N. corpus cells clean, missing row explained", ".test_n_host_failure_audit",
     "test_shipped_corpus_matrix_is_clean_and_any_missing_row_is_explained"),
    # O. Added 2026-08-10 with the rank-correlation section. Four readings that disagree make it
    # cheap to compute one and label it another, so the statistic is driven with populations whose
    # true ordering is known, and the pooled rows are kept out of the correction.
    ("O. group reading recovers a known ordering", ".test_o_rank_correlation_units",
     "test_group_reading_recovers_a_known_ordering"),
    ("O. contract arm withholds, kept credits", ".test_o_rank_correlation_units",
     "test_contract_arm_withholds_where_the_kept_arm_credits"),
    ("O. plugin reading ranks slugs, not findings", ".test_o_rank_correlation_units",
     "test_plugin_reading_is_ranked_on_slugs_not_findings"),
    ("O. pooled rows stay out of the Holm family", ".test_o_rank_correlation_units",
     "test_pooled_rows_are_excluded_from_the_holm_family"),
    ("O. every reported cell carries an interval", ".test_o_rank_correlation_units",
     "test_every_reported_cell_carries_an_interval"),
    ("O. no tool-level sign is licensed", ".test_o_rank_correlation_units",
     "test_no_tool_level_sign_is_licensed_by_its_own_p_value"),
    # P. Added 2026-08-11 with the endpoint-transfer analysis. Both counting bugs guarded here were
    # live in its first draft and both inflate rates, so they are exactly the kind that ship quietly.
    ("P. denominator is every declared record", ".test_p_endpoint_transfer",
     "test_denominator_is_every_declared_record"),
    ("P. rates are record-level, not plugin-level", ".test_p_endpoint_transfer",
     "test_rates_are_record_level_not_plugin_level"),
    ("P. contract withholding is applied", ".test_p_endpoint_transfer",
     "test_contract_withholding_is_applied"),
    ("P. Wordfence side matches the published table", ".test_p_endpoint_transfer",
     "test_wordfence_side_reproduces_the_published_external_table"),
    ("P. a leader flip is reported, not smoothed", ".test_p_endpoint_transfer",
     "test_a_leader_flip_is_reported_not_smoothed"),
    ("P. construct validity is not claimed", ".test_p_endpoint_transfer",
     "test_construct_validity_is_not_claimed"),
    # Q. Added 2026-08-11 with the WISP_MONOTONE_PROPS convergence work. Accumulating the property
    # table has no deletion path, so the danger is a sanitized property that stays raw. These run
    # the engine twice, with the flag off and on, over a fixture whose sanitizer sits behind a
    # wrapper chain in a second file so it cannot be seen on the first build.
    ("Q. fixture is clean with the flag off", ".test_q_monotone_props",
     "test_deferred_sanitizer_is_not_reported_with_the_flag_off"),
    ("Q. accumulation does not resurrect taint", ".test_q_monotone_props",
     "test_accumulation_does_not_resurrect_a_sanitized_property"),
    ("Q. the real flow survives the flag", ".test_q_monotone_props",
     "test_the_real_flow_is_still_found_with_the_flag_on"),
    # R. Added 2026-08-12. Q asks whether the flag is safe on a fixture. R asks whether the audit
    # that answers the same question over all 1108 records can report a failure at all, because a
    # guard that cannot fail is not evidence.
    ("R. an unchanged record reads as unchanged", ".test_r_monotone_diff",
     "test_a_clean_case_is_reported_clean"),
    ("R. a changed count on a stable record fails", ".test_r_monotone_diff",
     "test_b_a_changed_finding_count_on_a_stable_record_fails_the_audit"),
    ("R. a swapped finding fails even at equal count", ".test_r_monotone_diff",
     "test_c_same_count_but_different_findings_still_fails"),
    ("R. lost convergence fails", ".test_r_monotone_diff",
     "test_d_a_lost_convergence_fails_the_audit"),
    ("R. a rescue is not an instability", ".test_r_monotone_diff",
     "test_e_a_rescue_is_not_counted_as_an_instability"),
    ("R. unstored findings are not an empty result", ".test_r_monotone_diff",
     "test_f_a_record_with_no_stored_findings_is_not_read_as_an_empty_result"),
    # S. Added 2026-08-12 with the ground-truth definition corrections. Three counts the corrected
    # prose quotes are derived from the finding population, and the macro guard structurally cannot
    # notice when they go stale, because it compares each macro against the same stale JSON.
    ("S. macro build refuses a stale predicate count", ".test_s_predicate_staleness",
     "test_macro_build_refuses_a_population_newer_than_its_derived_counts"),
    ("S. the guard does not fire on a clean tree", ".test_s_predicate_staleness",
     "test_a_fresh_tree_builds"),
    ("S. shipped counts match the population", ".test_s_predicate_staleness",
     "test_the_shipped_counts_match_a_recomputation"),
    # T. Added 2026-08-12. Test I pinned scan_testset to the contract because that is where the
    # unpinned-configuration defect was found. eval/localize.py had the same defect and produced the
    # corpus cache behind the headline corpus class emission. This widens the guard by surface: every
    # module that imports the engine must pin the contract or be listed with a reason.
    ("T. every engine caller pins the contract", ".test_t_contract_env_surface",
     "test_every_engine_running_module_pins_the_contract_or_says_why_not"),
    ("T. localize pins it before importing", ".test_t_contract_env_surface",
     "test_localize_applies_it_before_importing_the_engine"),
    ("T. the exemption list stays honest", ".test_t_contract_env_surface",
     "test_the_exemption_list_is_not_a_dumping_ground"),
    ("T. the contract pins the engine knobs", ".test_t_contract_env_surface",
     "test_the_contract_pins_the_two_engine_defining_flags"),
    ("T. it overrides a shell asking for v1.2", ".test_t_contract_env_surface",
     "test_the_contract_overrides_a_shell_that_asks_for_v12"),
    ("T. no module names a census by hand", ".test_t_contract_env_surface",
     "test_no_module_picks_a_convergence_census_by_filename"),
    ("T. the resolver returns the shipped census", ".test_t_contract_env_surface",
     "test_the_resolver_returns_the_shipped_census_not_the_baseline"),
    # U. Added 2026-08-12. The corpus localization cache is ten independently written shards behind 89
    # macros, with no provenance in the files at all. An interrupted rerun leaves some shards on one
    # engine and some on another, and the consumer globs them together without noticing.
    ("U. all ten corpus shards present", ".test_u_shard_coherence",
     "test_all_ten_shards_are_present"),
    ("U. the shards are one run", ".test_u_shard_coherence",
     "test_the_shards_come_from_one_run"),
    ("U. no shard is truncated", ".test_u_shard_coherence",
     "test_no_shard_is_empty_or_truncated"),
    # V. Added 2026-08-13. v1.3 flipped two engine defaults at once, so the convergence gain has to
    # stay attributable to each of them separately or the version is claiming a change it cannot
    # justify. The same decomposition found that one of the twelve plugins the paper calls
    # oscillating had in fact timed out, which is a different failure with a different meaning.
    ("V. both v1.3 defaults are load-bearing", ".test_v_convergence_decomposition",
     "test_neither_default_alone_explains_the_convergence_gain"),
    ("V. arms paired by record not plugin", ".test_v_convergence_decomposition",
     "test_the_arms_are_paired_by_record_and_not_by_plugin"),
    ("V. a timeout is not an oscillation", ".test_v_convergence_decomposition",
     "test_the_oscillating_count_excludes_the_record_that_timed_out"),
    ("V. corpus counts need no separation", ".test_v_convergence_decomposition",
     "test_the_corpus_headline_needs_no_timeout_separation"),
    ("V. the classifier separates a killed run", ".test_v_convergence_decomposition",
     "test_the_classifier_separates_a_killed_run_from_a_bounded_one"),
    ("V. cross-tab pairs records not plugins", ".test_v_convergence_decomposition",
     "test_the_sensitivity_cross_tab_pairs_records_and_not_plugins"),
    ("V. decomposition agrees with sensitivity", ".test_v_convergence_decomposition",
     "test_the_sensitivity_file_and_the_decomposition_agree_on_the_shipped_count"),
    # W. Added 2026-08-13. The census diff can only compare the records that converge under both
    # engines. The corpus localization shards close it from the other side, across all 1108 records
    # and through the pipeline the macros are actually built from.
    ("W. v1.3 moved only what it rescued", ".test_w_loc_shard_diff",
     "test_no_record_changed_outside_the_set_v13_rescued"),
    ("W. the shard comparison is live", ".test_w_loc_shard_diff",
     "test_the_comparison_is_live_rather_than_vacuous"),
    ("W. July env agreed with the contract", ".test_w_loc_shard_diff",
     "test_the_unpinned_july_environment_agreed_with_the_contract"),
    ("W. most rescued records did not move", ".test_w_loc_shard_diff",
     "test_most_rescued_records_did_not_move_either"),
    # X. Added 2026-08-13 after stages 3 and 4 of the re-measurement pipeline printed
    # "skip (already done)" five times, exited rc=0 in fifteen seconds, and measured nothing. The
    # matrix resumes by cell key and its file-level provenance names only the engine that wrote the
    # file first, so a matrix holding two engines carries one stamp. The per-cell files do not.
    ("X. matrix WISP cells name the shipped engine", ".test_x_matrix_cell_engine",
     "test_every_wisp_matrix_cell_names_the_shipped_engine"),
    ("X. the WISP arm of each matrix is complete", ".test_x_matrix_cell_engine",
     "test_the_wisp_arm_of_each_matrix_is_complete"),
    ("X. baseline cells survive a WISP re-run", ".test_x_matrix_cell_engine",
     "test_baseline_cells_are_present_and_left_alone"),
    # Y. Added 2026-08-13. The engine reads its flags at import, eval/localize.py pins the contract
    # at module scope so that it does, and eval/testset/scan_testset.py imports localize. A worker
    # that declared an arm lost it one import later and ran the default. Two engine controls came
    # back byte-identical before anyone read them closely enough to notice.
    ("Y. engine default is the shipped config", ".test_y_declared_arm_survives",
     "test_the_engine_default_is_the_shipped_configuration"),
    ("Y. a declared arm reaches the engine", ".test_y_declared_arm_survives",
     "test_a_declared_arm_reaches_the_engine"),
    ("Y. the arm survives scan_testset import", ".test_y_declared_arm_survives",
     "test_the_arm_survives_importing_scan_testset"),
    ("Y. the arm survives localize import", ".test_y_declared_arm_survives",
     "test_the_arm_survives_importing_localize_directly"),
    ("Y. the stamp reports the arm", ".test_y_declared_arm_survives",
     "test_the_stamp_reports_the_arm_and_not_the_callers_environment"),
    ("Y. reset is explicit and works", ".test_y_declared_arm_survives",
     "test_reset_is_explicit_and_still_works"),
    # Z. Added 2026-08-13. eval/ladder_v3.py defaulted its baselines to the pre-Progpilot-fix scan,
    # which holds zero Progpilot findings. Rebuilding the population from it dropped Progpilot out of
    # the paired family, 39 comparisons down to 26, with a zero exit everywhere.
    ("Z. ladder baselines carry Progpilot", ".test_z_baselines_are_post_progpilot_fix",
     "test_the_ladders_default_baselines_carry_progpilot_findings"),
    ("Z. no exit-code discard in the baselines", ".test_z_baselines_are_post_progpilot_fix",
     "test_no_progpilot_record_was_discarded_for_its_exit_code"),
    ("Z. population holds all four tools", ".test_z_baselines_are_post_progpilot_fix",
     "test_the_population_built_from_it_holds_all_four_tools"),
    ("Z. the paired family keeps Progpilot", ".test_z_baselines_are_post_progpilot_fix",
     "test_the_paired_family_still_contains_progpilot"),
    # AB. Added 2026-08-13. The bibliography is outside the macro system, so @misc{wispsoftware} kept
    # naming wisp-scanner-v1.2 while the availability paragraph said v1.3, one line apart, with every
    # check passing. Correcting the .bib was not enough: the build never ran bibtex, so the PDF went
    # on printing v1.2 out of a .bbl nothing regenerated.
    ("AB. guard is quiet on a clean tree", ".test_ab_software_citation_engine",
     "test_the_guard_passes_on_the_tree_as_it_stands"),
    ("AB. stale tag in the bib fails", ".test_ab_software_citation_engine",
     "test_a_stale_tag_in_the_bib_fails_the_guard"),
    ("AB. stale sha in the bib fails", ".test_ab_software_citation_engine",
     "test_a_stale_sha_in_the_bib_fails_the_guard"),
    ("AB. stale compiled bibliography fails", ".test_ab_software_citation_engine",
     "test_a_stale_compiled_bibliography_fails_the_guard"),
    ("AB. pre-LaTeX gate cannot deadlock", ".test_ab_software_citation_engine",
     "test_the_pre_latex_gate_skips_the_bbl_so_the_build_cannot_deadlock"),
    ("AB. build runs bibtex then rechecks", ".test_ab_software_citation_engine",
     "test_the_build_runs_bibtex_and_checks_the_bibliography_after_latex"),
    # AC. Added 2026-08-13. Under v1.3 exact@10 against Progpilot survives Holm, so the paper's
    # absolute "nothing separates at line granularity" became false. The threats section had already
    # been scoped to Semgrep and wp-taint-scan while the abstract and the contributions list had not,
    # so the manuscript contradicted itself with every check passing. The macro guard cannot see a
    # sentence, so the sentence needs its own guard.
    ("AC. no false null at line granularity", ".test_ac_family_prose_matches_json",
     "test_no_document_asserts_an_absolute_null_at_line_granularity_when_one_survives"),
    ("AC. no invented line-granularity survivor", ".test_ac_family_prose_matches_json",
     "test_no_document_concedes_a_line_granularity_survivor_when_none_survives"),
    ("AC. survivor count matches the JSON", ".test_ac_family_prose_matches_json",
     "test_the_surviving_count_matches_the_family_json"),
    ("AC. every line survivor is disclosed", ".test_ac_family_prose_matches_json",
     "test_every_baseline_with_a_line_granularity_survivor_is_named_where_the_claim_is_made"),
    # The general form, added after the 2026-08-14 reject. The line-granularity checks above were too
    # narrow: the manuscript also said "No class-and-file comparison against either Semgrep or
    # wp-taint-scan survives at any cutoff" while cf@5 and cf@10 against Semgrep both survive.
    ("AC. no denied survivor at any endpoint", ".test_ac_family_prose_matches_json",
     "test_no_document_denies_a_survivor_that_the_family_actually_has"),
    # AD. Added 2026-08-13. The packaging copy list was hand-typed while the gate beside it derived
    # its expectation from the manifest, so they drifted. Sweeping the whole manifest fixed that and
    # broke the other end, shipping the AI annotators' agreement summary into a bundle whose
    # integrity rule is that the adjudication was removed. Both directions are held here.
    ("AD. validator refuses the AI summary", ".test_ad_bundle_ships_only_what_the_paper_reads",
     "test_the_validator_refuses_the_ai_adjudication_summary"),
    ("AD. sweep scoped to printed macros", ".test_ad_bundle_ships_only_what_the_paper_reads",
     "test_the_packaging_sweep_is_scoped_to_macros_the_documents_print"),
    ("AD. no AI artifact in the bundle", ".test_ad_bundle_ships_only_what_the_paper_reads",
     "test_no_ai_adjudication_artifact_sits_in_the_built_bundle"),
    ("AD. every printed source is shipped", ".test_ad_bundle_ships_only_what_the_paper_reads",
     "test_every_source_behind_a_printed_macro_is_in_the_bundle"),
    ("AD. both READMEs agree on skip counts", ".test_ad_bundle_ships_only_what_the_paper_reads",
     "test_the_two_bundle_readmes_agree_on_the_reproduction_counts"),
    # AE. Added 2026-08-14 after the second reject. Two of its P0s were provenance: the roll-ups
    # published a file-level stamp saying wisp-scanner-v1.2 over v1.3 numbers, and
    # OLD-VS-NEW-RESULTS.csv still called v1.2 values "new". A third was that reproduction reported
    # REGENERATED for fourteen targets it never compared to anything.
    ("AE. every matrix cell names its engine", ".test_ae_provenance_is_per_cell",
     "test_every_matrix_cell_names_the_engine_that_produced_it"),
    ("AE. baseline cell disclaims the WISP engine", ".test_ae_provenance_is_per_cell",
     "test_a_baseline_cell_does_not_claim_a_wisp_engine"),
    ("AE. rollups drop the first-run stamp", ".test_ae_provenance_is_per_cell",
     "test_the_rollups_do_not_republish_the_first_run_stamp_as_their_own"),
    ("AE. shipped results are on the shipped engine", ".test_ae_provenance_is_per_cell",
     "test_the_wisp_cells_of_every_live_artifact_agree_with_the_shipped_engine"),
    ("AE. tool manifest reads the contract", ".test_ae_provenance_is_per_cell",
     "test_the_tool_manifest_reads_its_config_from_the_contract"),
    ("AE. old-vs-new derived from JSON", ".test_ae_provenance_is_per_cell",
     "test_old_vs_new_is_derived_from_the_canonical_jsons"),
    ("AG. mixed memory matrix is not uniform", ".test_ag_mem_cap_uniformity",
     "test_mixed_matrix_is_not_uniform"),
    ("AG. uniform matrix still reports its value", ".test_ag_mem_cap_uniformity",
     "test_truly_uniform_matrix_still_reports_its_value"),
    ("AG. two ceilings are not uniform", ".test_ag_mem_cap_uniformity",
     "test_two_different_ceilings_are_not_uniform"),
    ("AG. shipped rollup matches its own cells", ".test_ag_mem_cap_uniformity",
     "test_shipped_rollup_tells_the_truth_about_its_own_cells"),
    ("AE. reproduction compares, not just runs", ".test_ae_provenance_is_per_cell",
     "test_reproduction_never_passes_a_target_it_did_not_compare"),
    # AF. Added 2026-08-19. The overstatement factor is a ratio of two rates read off one sample of
    # 200 findings, and its shipped interval was built by holding the numerator at its point
    # estimate and dividing by the endpoints of the denominator's interval. That gives the numerator
    # no variance and never sees the correlation between the two. The replacement resamples plugin
    # slugs and recomputes both rates inside each replicate. These guard the construction rather
    # than the value, because the regression that matters is the new field filled from the old
    # formula, not the new field deleted.
    ("AF. shipped result carries a paired interval", ".test_af_paired_ratio_interval",
     "test_the_shipped_result_carries_a_paired_cluster_interval"),
    ("AF. paired interval is not the plug-in one", ".test_af_paired_ratio_interval",
     "test_the_paired_interval_is_not_the_plug_in_interval"),
    ("AF. the bootstrap resamples the numerator", ".test_af_paired_ratio_interval",
     "test_a_paired_bootstrap_moves_the_numerator_too"),
    ("AF. ratio bootstrap follows the house draw", ".test_af_paired_ratio_interval",
     "test_the_ratio_bootstrap_follows_the_house_draw"),
    ("AF. macros point at the paired interval", ".test_af_paired_ratio_interval",
     "test_the_reported_macros_point_at_the_paired_interval"),
    ("AF. corrected interval still excludes 1.0", ".test_af_paired_ratio_interval",
     "test_the_corrected_interval_still_excludes_one"),
]
# data-level invariants that only go green once the contract re-scans have landed
PENDING_DATA = [
]
# extra behavioral modules that must fully pass (each exposes a run() -> exit code)
MODULES = [
    ("Prompt-6 formalism/convergence (8 cases)", ".test_formalism_convergence"),
    ("Patch geometry (Prompt 2, 8 cases)", ".test_patch_geometry"),
]


from ._common import MissingInput


def _run_one(mod, fn):
    m = importlib.import_module(mod, __package__)
    getattr(m, fn)()


def _skip_reason(e):
    """A test whose input is absent is skipped, never failed.

    The bundle ships this suite but not the plugin corpus or the legacy sheets, so two tests cannot
    run from inside it. Printing those as failures tells a reviewer the artifact's own tests are
    broken. The distinction is the same one the reproduction runner already draws between a missing
    download and a broken reproduction."""
    if isinstance(e, MissingInput):
        return str(e)
    if isinstance(e, FileNotFoundError):
        return f"input not present: {e.filename}"
    return None


def main() -> int:
    ok = True

    print("\n" + "=" * 78)
    print("PENDING bugs (each SHOULD FAIL = bug still reproduced)")
    print("=" * 78)
    if not PENDING:
        print("  (none open)")
    for title, mod, fn in PENDING:
        try:
            _run_one(mod, fn)
            print(f"  [PASSED] {title:42} UNEXPECTED ✗ (bug vanished without a recorded fix)")
            ok = False
        except AssertionError as e:
            print(f"  [FAILED] {title:42} reproduced ✓")
            d = str(e).splitlines()[0] if str(e) else ""
            if d:
                print(f"           -> {d[:110]}")
        except Exception as e:
            why = _skip_reason(e)
            if why:
                print(f"  [SKIP  ] {title:42} {why[:90]}")
                continue
            traceback.print_exc()
            print(f"  [ERROR ] {title:42} {type(e).__name__}: {e}")
            ok = False

    print("\n" + "=" * 78)
    print("FIXED bugs (each SHOULD PASS = fix verified)")
    print("=" * 78)
    for title, mod, fn in FIXED:
        try:
            _run_one(mod, fn)
            print(f"  [PASSED] {title:42} fixed ✓")
        except AssertionError as e:
            print(f"  [FAILED] {title:42} REGRESSED ✗")
            d = str(e).splitlines()[0] if str(e) else ""
            if d:
                print(f"           -> {d[:110]}")
            ok = False
        except Exception as e:
            why = _skip_reason(e)
            if why:
                print(f"  [SKIP  ] {title:42} {why[:90]}")
                continue
            traceback.print_exc()
            print(f"  [ERROR ] {title:42} {type(e).__name__}: {e}")
            ok = False

    if PENDING_DATA:
        print("\n" + "=" * 78)
        print("DATA invariants (still red until the contract re-scans land)")
        print("=" * 78)
    for title, mod, fn in PENDING_DATA:
        try:
            _run_one(mod, fn)
            print(f"  [PASSED] {title:42} data regenerated \u2713")
        except AssertionError as e:
            print(f"  [FAILED] {title:42} awaiting re-scan")
            d = str(e).splitlines()[0] if str(e) else ""
            if d:
                print(f"           -> {d[:110]}")
        except Exception as e:
            why = _skip_reason(e)
            if why:
                print(f"  [SKIP  ] {title:42} {why[:90]}")
                continue
            print(f"  [ERROR ] {title:42} {type(e).__name__}: {e}")
            ok = False

    print("\n" + "=" * 78)
    print("Behavioral modules (each SHOULD fully PASS)")
    print("=" * 78)
    for title, mod in MODULES:
        try:
            m = importlib.import_module(mod, __package__)
            if hasattr(m, "run"):
                rc = m.run()
            else:                       # pytest-style: collect and run every test_*
                fns = [getattr(m, n) for n in dir(m)
                       if n.startswith("test_") and callable(getattr(m, n))]
                fails = 0
                for fn in fns:
                    try:
                        fn()
                    except Exception:
                        traceback.print_exc()
                        fails += 1
                print(f"    {len(fns) - fails}/{len(fns)} PASS")
                rc = 0 if fails == 0 else 1
            status = "PASSED" if rc == 0 else "FAILED"
            print(f"  [{status:6}] {title}")
            if rc != 0:
                ok = False
        except Exception as e:
            traceback.print_exc()
            print(f"  [ERROR ] {title}: {type(e).__name__}: {e}")
            ok = False

    print("-" * 78)
    print("  SUITE OK: pending bugs reproduced, fixed bugs pass, modules pass." if ok
          else "  SUITE NOT AS EXPECTED (see above).")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
