# Independent-dataset evaluation

These scripts run WISP (and, for the three-way comparison, Semgrep and Progpilot)
on third-party PHP corpora that WISP was **not** developed on. They need the
datasets and the baseline tools installed separately, so point the scripts at them
with environment variables.

## eval_sastphp.py — SAST-PHP capability benchmark (XAST / YASA)

Labelled taint-engine capability cases (`*_T` should fire, `*_F` should stay
silent). The harness injects the benchmark's synthetic source marker
`$__taint_src` into the engine source set so the flow-capability cases are scored
fairly.

```bash
WISP_SASTPHP_DIR=/path/to/sast-php/case \
  python3 eval/independent/eval_sastphp.py --out out/out_sastphp.json
```

Current revision result: TPR 0.763, TNR 0.595, accuracy 0.679 (262 cases). The
recall-first branch join raises detection but also leaves high FPR on path/object-field
capabilities. The exact counts and source hash are in the independent rerun manifest.

## eval_stivalet_3way.py — stivalet PVts (SARD), WISP vs Semgrep vs Progpilot

Runs all three tools on a balanced sample of the SARD stivalet Injection cases,
away from WISP's WordPress home turf.

```bash
WISP_STIVALET_DIR=/path/to/php02_stivalet/Injection \
PROGPILOT_PHAR=/path/to/progpilot.phar \
  python3 eval/independent/eval_stivalet_3way.py --n 150 --out out/out_stivalet_3way.json
```

Requires `semgrep` on `PATH` (rulesets `p/php`, `p/security-audit`) and a
Progpilot phar (>= 1.1). The current 600-file result is WISP TPR/FPR/precision
0.167/0.167/0.500, Semgrep 0.153/0.170/0.474, and Progpilot
0.697/0.607/0.535. Progpilot flags about 65% of the balanced sample.

## eval_psabench.py — PSAbench A2/A3 capability check

```bash
WISP_NO_GDA=1 python3 eval/independent/eval_psabench.py \
  --dataset /path/to/php25_psabench --out out/out_psabench.json
```

The current rerun has pooled A2/A3 TPR 0.413 (62/150 positives), and A2
flow/context/procedural subcases each reach TPR 1.00.

`scripts/reproduce_paper.sh` runs this check when `WISP_PSABENCH_DIR` is set.

## Where to get the datasets

- **stivalet PVts** is the SARD PHP Vulnerability Test Suite (NIST SARD).
- **SAST-PHP** is the PHP subtree of the XAST/YASA capability benchmark.
- **PSAbench** (inter-procedural reachability, reported in the paper) is at
  `github.com/xjzzzxx/PSAbench`.
