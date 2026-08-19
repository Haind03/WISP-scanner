#!/bin/bash
# One TIMED pass per baseline at a generous cap. eval/budget_curve.py then derives
# every smaller budget from the recorded per-record tool time, so this is one pass
# per tool instead of one per (tool, budget).
#
# 300s for Semgrep and wp-taint-scan. Progpilot times out on ~half the corpus even
# at 60s, so capping it at 300 would burn hours on records that cannot finish;
# 120s already covers the 25/60/120 points the paper reports for it.
set -u
# Paths are derived rather than hardcoded. This script shipped with the author machine
# baked in, which made it unrunnable for anyone who cloned the public repository, and the
# reviewer who tries it is the person the artifact exists for.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1
PY="${PY:-python3}"
OUT=out/budget_20260717
mkdir -p "$OUT"
export PYTHONHASHSEED=0
# same binaries the published runs used, recorded in their tool_identity blocks
export PROGPILOT_BIN="${PROGPILOT_BIN:-$REPO/../baselines/progpilot_ok.phar}"
export WPT_BIN="${WPT_BIN:-$REPO/../external/wp-taint-scan/bin/taint-scan}"
# semgrep is expected on PATH. Set SEMGREP_BIN or prepend your own shim directory.

run () {  # $1=tool $2=cap
  [ -f "$OUT/atk_$1.json" ] && { echo "== $1 already done"; return 0; }
  echo "== $1 cap=$2s  $(date +%H:%M:%S)"
  "$PY" -m eval.fullcorpus_atk --tool "$1" --workers "${WORKERS:-6}" --cap "$2" \
      --out "$OUT/atk_$1.json" > "$OUT/$1.log" 2>&1
  echo "== $1 rc=$?  $(date +%H:%M:%S)"
}
WORKERS=6 run semgrep 300
WORKERS=4 run progpilot 120
# wp-taint-scan's memory grows unbounded with scan time: a single large-plugin
# scan peaks at 13.5 GB RSS at a 60 s cap and 15 GB (the whole box) by ~120 s, so
# it cannot be run above one worker or much past a 60 s budget on this 15 GB host.
# One worker, 55 s cap keeps peak RSS under the ceiling; this is the tool's own
# suggested operating point, and the ceiling itself is a reported scalability result.
WORKERS=1 run wpt 55
echo "BUDGET PASSES DONE $(date +%H:%M:%S)"
