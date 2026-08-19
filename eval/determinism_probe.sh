#!/bin/bash
# Does the engine return the same findings twice on the same input?
#
# The 2026-07-17 rerun reproduced 9 of 10 shards counter-for-counter but wobbled
# on two large plugins (gamipress 271 vs 273 findings, wp-photo-album-plus 1341
# vs 1333). Both are big enough for the engine's worklist bounds to bind, and
# Python randomises string hashing per process, so set iteration order - and thus
# which items are reached before a bound trips - can differ run to run.
#
# Hypothesis: PYTHONHASHSEED explains it. Three runs at the default (random) seed
# should vary; three at a pinned seed should not.
set -u
# Paths are derived rather than hardcoded. This script shipped with the author machine
# baked in, which made it unrunnable for anyone who cloned the public repository, and the
# reviewer who tries it is the person the artifact exists for.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1
PY="${PY:-python3}"
OUT=out/paired_20260717/determinism
mkdir -p "$OUT"
export WISP_NO_GDA=1

REC="$OUT/rec.txt"
echo "gamipress|CVE-2026-48874" > "$REC"

run () {  # $1=tag  $2=hashseed ("" = default random)
  if [ -n "$2" ]; then export PYTHONHASHSEED="$2"; else unset PYTHONHASHSEED; fi
  "$PY" -m eval.localize --sample "$REC" --out "$OUT/$1.json" > "$OUT/$1.log" 2>&1
  n=$($PY -c "import json;print(json.load(open('$OUT/$1.json'))['details'][0]['findings'])" 2>/dev/null)
  echo "$1 seed=${2:-random} findings=${n:-ERROR}"
}

echo "=== default (random hash seed) ==="
for i in 1 2 3; do run "rand_$i" ""; done
echo "=== pinned PYTHONHASHSEED=0 ==="
for i in 1 2 3; do run "pin_$i" "0"; done
echo "PROBE DONE"
