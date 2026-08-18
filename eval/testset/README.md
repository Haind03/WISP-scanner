# Slug-disjoint robustness set

This directory scores the released 325-plugin set. It is post-development and
slug-disjoint from WISP-1108, but it comes from the same Patchstack source. Treat
it as a robustness check, not as an independent-source test set.

Supported path:

1. Extract `testset-plugins.zip` from the Zenodo record DOI
   `10.5281/zenodo.21627535`.
2. Convert the released CSV:

   ```bash
   python -m eval.testset.manifest_from_csv WISP-testset-325.csv \
     --plugins-dir /path/to/extracted/plugins --out testset_manifest.json
   ```
3. Run `python -m eval.testset.scan_testset` with explicit `--manifest`,
   `--plugins-dir`, `--progpilot-bin`, and `--wpt-bin` arguments.
4. Run `python -m eval.testset.stats_testset` on the normalized JSON output.

`scan_testset.py` records provenance and all normalized findings. Missing
archives, tool errors, timeouts, and empty outputs remain in the denominator.
wp-taint-scan is normalized by `eval.wpt_adapter`, including nested line fields,
multi-class rules, and access-tier ranking.

`build_adjudication_sheet.py` only creates a blank blinded-review protocol. It
does not imply that reviewers completed the sheet. No completed human labels for
this 325-plugin set are claimed by the artifact.

The collection scripts are historical and depend on changing WordPress.org and
Patchstack web interfaces. The released manifest and archives, rather than a
fresh web crawl, define the evaluated set.
