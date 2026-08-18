#!/usr/bin/env bash
# Reproduce the WISP engine-side results of the paper (recall, localization /
# precision@K, ablations, and the independent-dataset checks).
#
# Prerequisites:
#   * pip install -r requirements.txt
#   * the 1108-CVE benchmark unpacked so the dataset adapter can find it:
#       export PS_DIR=/path/to/patchstack_bugbounty       # Zenodo DOI 10.5281/zenodo.21627535
#     (default location is a sibling dir named patchstack_bugbounty/)
#
# Heavy steps are sharded for a commodity multicore host. Lower N for a small box.
set -e

# Pin the hash seed here rather than asking the reader to remember it. Python
# randomises string hashing per process, which reorders set iteration, which
# changes which items a bounded worklist reaches on plugins large enough for a
# bound to bind. Unpinned, two of the 1108 records vary by a few findings between
# runs. Too small to move any number in the paper, large enough to make a strict
# diff of two runs non-empty.
export PYTHONHASHSEED=0
cd "$(dirname "$0")/.."          # artifact root
N="${N:-16}"
mkdir -p out/shards out/abl_nobj out/abl_norank

echo "== 0. engine self-test (must print ALL 122 CASES PASS) =="
python3 -m eval.selftest_engine | tail -1

echo "== 1. build shard key files from the corpus =="
python3 - <<PY
import sys; sys.path.insert(0, '.')
from eval.datasets.patchstack import load_rows
ks = [r['slug'] + '|' + r['cve'] for r in load_rows()]
N = $N
for i in range(N):
    open(f'out/shards/keys_{i}.txt', 'w').write(chr(10).join(ks[i::N]))
open('out/shards/all_keys.txt', 'w').write(chr(10).join(ks))
print('wrote shard files for', len(ks), 'CVEs')
PY

echo "== 2. plugin-class recall, full corpus (RQ1/RQ2 + error analysis) =="
for i in $(seq 0 $((N-1))); do
  python3 -m eval.recall --only-present --sample out/shards/keys_$i.txt \
    --out out/shards/recall_$i.json > out/shards/recall_$i.log 2>&1 &
done; wait
python3 eval/merge_recall.py                        # -> out/recall_full.json (recall 0.7708)

echo "== 3. localization + precision@K, full corpus (RQ3) =="
for i in $(seq 0 $((N-1))); do
  python3 -m eval.localize --window 5 --sample out/shards/keys_$i.txt \
    --out out/shards/localize_$i.json > out/shards/localize_$i.log 2>&1 &
done; wait
python3 eval/merge_localize.py                      # -> out/localize_full.json (prec@1 0.431)

echo "== 4. ablations (branch-join, ranking) =="
for i in $(seq 0 $((N-1))); do
  WISP_NO_BRANCH_JOIN=1 python3 -m eval.recall --only-present --sample out/shards/keys_$i.txt \
    --out out/abl_nobj/recall_$i.json > out/abl_nobj/recall_$i.log 2>&1 &
done; wait
for i in $(seq 0 $((N-1))); do
  WISP_NO_RANK=1 python3 -m eval.localize --window 5 --sample out/shards/keys_$i.txt \
    --out out/abl_norank/localize_$i.json > out/abl_norank/localize_$i.log 2>&1 &
done; wait
for i in $(seq 0 $((N-1))); do
  WISP_NO_LEARNED=1 python3 -m eval.recall --only-present --sample out/shards/keys_$i.txt \
    --out out/abl_nobj/recall_nl_$i.json > out/abl_nobj/recall_nl_$i.log 2>&1 &
done; wait

echo "== 5. independent datasets (run automatically when their env vars are set) =="
echo "   see eval/independent/README-independent.md for dataset paths and env vars"
if [ -n "${WISP_SASTPHP_DIR:-}" ]; then
  python3 eval/independent/eval_sastphp.py --out out/out_sastphp.json
else
  echo "   [skip] WISP_SASTPHP_DIR not set"
fi
if [ -n "${WISP_STIVALET_DIR:-}" ] && [ -n "${PROGPILOT_PHAR:-}" ]; then
  python3 eval/independent/eval_stivalet_3way.py --n 150 --out out/out_stivalet_3way.json
else
  echo "   [skip] WISP_STIVALET_DIR / PROGPILOT_PHAR not set"
fi
if [ -n "${WISP_PSABENCH_DIR:-}" ]; then
  python3 eval/independent/eval_psabench.py --dataset "$WISP_PSABENCH_DIR" --out out/out_psabench.json
else
  echo "   [skip] WISP_PSABENCH_DIR not set"
fi

echo "== 6. fixpoint-convergence measurement (reviewer item 2.1) =="
python3 -m eval.measure_convergence --cap 6 --sample out/shards/all_keys.txt \
  --out out/convergence.json || echo "   [warn] convergence measurement failed"

echo "DONE. Key outputs: out/recall_full.json, out/localize_full.json, out/convergence.json"
