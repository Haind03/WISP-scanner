#!/bin/bash
# Reruns WISP localization over the full 1108-record corpus, 10-way sharded, to
# capture the per-record top-K counters that eval/localize.py records in
# "details" but the 2026-07-14 snapshot predates. Aggregates must reproduce the
# published ones exactly: same engine hashes, same WISP_NO_GDA=1, same shards.
set -u
# Paths are derived rather than hardcoded. This script shipped with the author machine
# baked in, which made it unrunnable for anyone who cloned the public repository, and the
# reviewer who tries it is the person the artifact exists for.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1
# systemd inherits neither the pyenv shim nor its PATH, and the stock
# /usr/bin/python3 is a different minor version without openpyxl. Pin the same
# interpreter the published numbers were produced under.
PY="${PY:-python3}"
OUT=out/paired_20260717/loc_full
mkdir -p "$OUT"
export WISP_NO_GDA=1
pids=()
for i in $(seq 0 9); do
  "$PY" -m eval.localize \
      --sample out/fill_20260714/shards/sh_${i}.txt \
      --out "${OUT}/loc_${i}.json" > "${OUT}/sh_${i}.log" 2>&1 &
  pids+=($!)
done
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
echo "ALL SHARDS DONE fail=${fail}"
exit "$fail"
