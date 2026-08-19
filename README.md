# WISP: WordPress-Aware Static Analysis for Plugin Triage

WISP is a WordPress-aware, inter-procedural taint engine for PHP plugins. It runs
entirely on CPU with no per-scan model cost. This is a research triage artifact:
its ranked findings can shortlist patch-relevant files, but the accompanying
evaluation shows that neither WISP nor the compared WordPress-aware baseline
reliably identifies the exact disclosed defect. Do not interpret a finding as a
confirmed vulnerability without manual validation.

WISP is short for WordPress-aware Interprocedural Symbolic Pipeline.

All datasets are released together in one Zenodo record:
**[doi.org/10.5281/zenodo.21627535](https://doi.org/10.5281/zenodo.21627535)**.
That single record bundles three sets. The first is the 1108-CVE benchmark, with
vulnerable and patched plugin sources, class labels, and diff-based ground truth.
The second is a post-development, slug-disjoint set of 325 plugins with its
original four-tool scan, a robustness set from the same Patchstack source rather
than an independent-source benchmark, for which no completed human adjudication is
claimed. The portable scanner and statistics scripts for that set are in
`eval/testset/`. The third is a 100-CVE external-validation set drawn from
WordPress plugin advisories published by Wordfence and independent of Patchstack,
with plugin source taken from the official repository.

## What is here

```
wisp/engine/     the six-layer engine (L1 ingest ... L6 optional LLM verify)
wisp/rules/      declarative source/sink/sanitizer/guard vocabulary (YAML)
eval/           granularity-ladder metrics and offline regression tests
eval/data/      the fixed matched-100 comparison keys
eval/testset/   portable scanner/statistics harness for the 325-plugin set
eval/independent/  runs on three third-party PHP corpora (no re-tuning)
stage4/         the recall-growth rule-mining loop
scripts/scan.py       scan one plugin from the command line
scripts/reproduce_paper.sh   regenerate the engine-side results
examples/       a minimal vulnerable handler (Fig. 1 of the paper)
paper/          reserved for the published paper PDF
```

The detection engine is CPU-only and needs no network or API key. The LLM stage
(`wisp/engine/l4_verify.py`) and the learning loop are optional and clearly
separated. Nothing in the core detection path calls a model.

## Install

```bash
pip install -r requirements.txt        # tree-sitter, tree-sitter-php, pyyaml
```

Python 3.10+ is expected. The only hard dependencies are the tree-sitter PHP
grammar and PyYAML.

## Quickstart

The command-line entry point is the script `scripts/scan.py`. WISP is not
installed as a package and it exposes no module entry point, so
`python -m wisp.cli` and `python -m wisp` do not exist and will fail with
`No module named wisp.cli`. Run the script from the repository root.

Scan the bundled example (the five-line handler from the paper):

```bash
python scripts/scan.py examples/vuln_handler.php
```

Expected output - three candidates in exploitability-ranked order:

```
  1. CSRF      vuln_handler.php:17  (conf 0.50)  [ajax_nopriv]
      request  ->  update_option
  2. AUTH      vuln_handler.php:17  (conf 0.50)  [ajax_nopriv]
      request  ->  update_option
  3. XSS       vuln_handler.php:18  (conf 0.60)  [ajax_nopriv]
      $_POST  ->  echo
```

The CSRF and access-control findings are the ones general-purpose analyzers miss:
they are the *absence* of a nonce and a capability check, not a dangerous line of
code. Scan a real plugin the same way:

```bash
python scripts/scan.py path/to/plugin.zip --json findings.json
python scripts/scan.py path/to/plugin_dir/ --top 10
```

## Self-test

The 122-case regression test encodes the exact engine behaviors the results rely
on (class-scoped sanitizers, branch-join, inter-procedural summaries, the
missing-guard rules). It runs offline in a second and is also the gate the
learning loop must pass before admitting any new rule.

```bash
python -m eval.selftest_engine          # engine: 122 cases
python -m eval.selftest_gda             # guard-flow analysis: 7 cases
python -m eval.selftest_wpt_adapter     # baseline JSON normalization/ranking
```

## Matched-100 WordPress plugin corpus

The matched-100 sample contains 100 vulnerability records across 98 unique plugin
slugs. Ninety-seven records have CVE identifiers; the other three retain `-`
because no CVE was assigned in the comparison source. The canonical `slug|CVE`
list is [`eval/data/matched_100.txt`](eval/data/matched_100.txt).

GitHub contains the scanner, evaluation harness, and selection list. It does not
contain the third-party plugin archives: `plugins/`, `*.zip`, and generated
`out/` results are excluded by `.gitignore`. Download the matched-100 archive
from Zenodo and extract it outside the repository. The extraction root must use
the dataset-adapter layout:

```text
WISP-matched-100/
├── WISP-1108-CVE-Dataset.csv
├── metadata/
│   └── archive-manifest.csv
└── plugins/
    └── <plugin-slug>/
        ├── <vulnerable-archive>.zip
        └── <patched-archive>.zip
```

`archive-manifest.csv` may be omitted only when the main CSV already contains
the exact `Vulnerable File` and `Patched File` values. Run the archive audit
before scanning; it checks all 100 vulnerable/patched pairs and can emit their
SHA-256 identities:

```bash
export PS_DIR=/path/to/WISP-matched-100
export PYTHONHASHSEED=0
mkdir -p out

python -m eval.selftest_dataset_adapter \
  --data-dir "$PS_DIR" \
  --expected 100 \
  --audit-out out/matched100-archive-audit.json

python -m eval.recall \
  --sample eval/data/matched_100.txt \
  --workers 4 \
  --out out/matched100-recall.json

python -m eval.localize \
  --sample eval/data/matched_100.txt \
  --window 5 \
  --out out/matched100-localize.json
```

The audit must print `DATASET ADAPTER PASS: 100 exact vulnerable/patched archive
pairs` before the evaluation commands are run.

## Reproduce the paper

Download the benchmark from Zenodo, extract `plugins.zip` so `plugins/` sits next
to `WISP-1108-CVE-Dataset.csv`, and point the adapter at that directory. Corrected
metadata must include `Patched File` per row (either in the main CSV or in
`metadata/archive-manifest.csv`). The adapter fails closed instead of guessing a
patched ZIP from its filename or version:

```bash
export PS_DIR=/path/to/WISP-1108-extracted
export PYTHONHASHSEED=0                                       # see note below
python -m eval.selftest_dataset_adapter --data-dir "$PS_DIR"  # must load 1108
bash scripts/reproduce_paper.sh
```

Pin `PYTHONHASHSEED`. Python randomizes string hashing per process, which
reorders set iteration, which in turn changes which items a bounded worklist
reaches on plugins large enough for a bound to bind. Without the pin, two of the
1108 records vary by a few findings between runs (6 out of 72,807 findings, too
small to move any number in the paper, but enough that a strict diff of two runs
will not be empty). With the pin the engine is deterministic:
`eval/determinism_probe.sh` demonstrates both halves.

The script records engine-side class emission, localization, and ablations. The
paper's cross-tool tables additionally require the pinned third-party binaries
and normalized outputs listed in the paper. They are not silently substituted by
whatever happens to be installed.

For the released 325-plugin set, use explicit inputs and binaries. The output
records the engine commit, engine/rule hash, manifest hash, archive hashes, and
failure-as-miss status, and retains every normalized finding:

```bash
python -m eval.testset.scan_testset \
  --manifest /path/to/testset_manifest.json \
  --plugins-dir /path/to/plugins \
  --progpilot-bin /path/to/progpilot.phar \
  --wpt-bin /path/to/taint-scan \
  --out eval/testset/out/testset_scored.json
python -m eval.testset.stats_testset \
  --input eval/testset/out/testset_scored.json
```

Ablations are plain environment-variable toggles, so any single mechanism can be
switched off in isolation:

| Toggle | Effect |
|---|---|
| `WISP_NO_BRANCH_JOIN=1` | disable branch-join (linear fall-through) |
| `WISP_NO_RANK=1` | emit findings in discovery order, not ranked |
| `WISP_NO_LEARNED=1` | drop the Stage-4 learned sink/source blocks |

## Independent datasets

`eval/independent/` runs WISP unchanged on three third-party PHP corpora
(SAST-PHP, stivalet PVts, PSAbench), and for stivalet runs Semgrep and Progpilot
head-to-head. These need the datasets and baseline tools installed separately.
See [`eval/independent/README-independent.md`](eval/independent/README-independent.md).

## Optional LLM verification and the learning loop

`wisp/engine/l4_verify.py` re-checks individual findings with an LLM behind a
local agent CLI in headless mode, using the CLI's own login so no metered API key
is required. `stage4/stage4_recall_growth.py` mines the engine's own near-misses
for candidate sinks and keeps only the batches that raise gold-set recall while
the 122-case self-test still passes. Both are reported in the paper as smaller
studies, and neither is needed to scan or to reproduce the core taint results.
Configure the CLI through environment variables (see the docstrings). No key is
committed.

## Release identity

The paper cites this artifact by git tag, not by branch. The reported numbers
come from the engine as it stands at that tag.

| Field | Value |
|---|---|
| Tag | `wisp-scanner-v1.0` |
| Commit | `6074bb4dc4e3053ee278833978d4ee87045285c6` |
| Tag date | 2026-08-18 |
| `wisp/engine/taint_engine.py` sha256 | `d07a4bbc573dbd6855f390f223b93b069b2d33654a56972f4730c53e50d87c2f` |
| `wisp/rules/wisp-rules.yaml` sha256 | `50f73df6f93a3d68235880b4773953ca5d8ea3dee96e3dd601ccf8cc738e95ad` |
| `wisp/rules/wordpress-security.yaml` sha256 | `f872f475d07571e6866c57b1df2e9d7a2ee1051f99f3eeb9fce73effc8a7590a` |

Check that you have the cited engine before running anything:

```bash
git checkout wisp-scanner-v1.0
sha256sum wisp/engine/taint_engine.py
# expect d07a4bbc573dbd6855f390f223b93b069b2d33654a56972f4730c53e50d87c2f
```

Later tags exist in this repository for internal revision rounds. Only
`wisp-scanner-v1.0` is the released artifact for the paper.

## License and citation

MIT (see [LICENSE](LICENSE)). If you use WISP or the benchmark, please cite the
paper and the Zenodo dataset (see [CITATION.cff](CITATION.cff)).
