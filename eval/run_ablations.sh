#!/bin/bash
# The five engine passes the C&S reviewer's P0 #4 and #7 need, back to back.
#
# None of these can be derived from an existing run: each asks what the engine
# does under a configuration it has never been run under, and only running it
# answers that.
#
#   #4 guard semantics. The reviewer says the missing-guard predicate is
#      presence-based and intra-procedural: a guard after the mutation counts, and
#      one in the caller/route/registration is missed. Both refinements already
#      exist as toggles and have never been measured.
#        guardorder  WISP_GUARD_ORDER=1  guard must precede the first mutation
#        gdaemit     WISP_GDA_EMIT=1     dominance + caller/REST/admin credits decide
#                                       emission, not just ranking
#   #7 taint approximations, isolated on the CURRENT revision. The published
#      ablations predate the engine revision, so they describe a different engine.
#        nobj        WISP_NO_BRANCH_JOIN=1
#        noprops     WISP_NO_PROPS=1
#        sani        WISP_SANI_CLASS=0   assignment-side sanitizer propagation off
#
# Every pass is class recall (eval.recall), which is the endpoint the ablation
# table reports. 10-way sharded like every other full-corpus pass here.
set -u
cd /mnt/d/System-ScanInfosec/wisp-artifact || exit 1
# systemd inherits neither the pyenv shim nor its PATH.
PY=/home/haipanda/.pyenv/versions/3.11.9/bin/python3
SHARDS=out/fill_20260714/shards
BASE=out/ablations_20260717
mkdir -p "$BASE"

# Pinned so a rerun of any of these is bit-reproducible; unpinned, set iteration
# order varies and two large plugins wobble by a few findings.
export PYTHONHASHSEED=0
export WISP_NO_GDA=1          # headline config: the deficit is a ranking signal only

run_pass () {   # $1 = tag, rest = VAR=VAL toggles for this pass
  local tag="$1"; shift
  local out="$BASE/$tag"
  if [ -f "$out/DONE" ]; then echo "== $tag already done, skipping"; return 0; fi
  mkdir -p "$out"
  echo "== $tag  toggles: $*  $(date +%H:%M:%S)"
  local pids=()
  for i in $(seq 0 9); do
    env "$@" "$PY" -m eval.recall --only-present \
        --sample "$SHARDS/sh_${i}.txt" --out "$out/recall_${i}.json" \
        > "$out/sh_${i}.log" 2>&1 &
    pids+=($!)
  done
  local fail=0
  for p in "${pids[@]}"; do wait "$p" || fail=1; done
  if [ "$fail" -eq 0 ]; then touch "$out/DONE"; echo "== $tag OK $(date +%H:%M:%S)"
  else echo "== $tag FAILED $(date +%H:%M:%S)"; fi
}

# #4 first: cheapest in risk, both toggles already exist and only change the
# guard predicate, and it feeds the paper's new framing directly.
run_pass guardorder WISP_GUARD_ORDER=1
run_pass gdaemit    WISP_GDA_EMIT=1 WISP_NO_GDA=0
# #7: isolate each taint approximation on this revision.
run_pass nobj       WISP_NO_BRANCH_JOIN=1
run_pass noprops    WISP_NO_PROPS=1
run_pass sani       WISP_SANI_CLASS=0

echo "ALL PASSES DONE $(date +%H:%M:%S)"
