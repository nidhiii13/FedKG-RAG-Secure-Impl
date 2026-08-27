#!/usr/bin/env bash
# Stage 5 ablations for the CWQ evaluation: bound, top-k, neighbourhood cap,
# owner count, and partition method.  Runs sequentially to bound peak memory.
# Usage: scripts/run_cwq_ablations.sh [results_root]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTROOT="${1:-$ROOT/results}"
PY="$ROOT/.venv/bin/python"
STAMP() { date -u +%Y%m%dT%H%M%SZ; }

run_one() {
  local name="$1"; shift
  local dir="$OUTROOT/cwq_cleartext_full1267_${name}_$(STAMP)"
  if ls "$OUTROOT" | grep -q "cwq_cleartext_full1267_${name}_"; then
    echo "SKIP ${name}: already present"
    return 0
  fi
  mkdir -p "$dir"
  echo "=== ${name} -> ${dir}"
  PYTHONUNBUFFERED=1 /usr/bin/time -v "$PY" -u "$ROOT/scripts/run_cwq_eval.py" \
    --questions 0 --seed 4242 --batch-size 200 "$@" --out "$dir" \
    2>&1 | tee "$dir/terminal.log" | grep -E "retrieval:|plaintext" || true
}

# bound sweep (k=32, c=50, 3 owners, subject-hash)
run_one b3_k32_c50_o3_subj  --bound 3  --topk 32 --neighbourhood-cap 50
run_one b16_k32_c50_o3_subj --bound 16 --topk 32 --neighbourhood-cap 50
# top-k sweep
run_one b8_k4_c50_o3_subj   --bound 8 --topk 4  --neighbourhood-cap 50
run_one b8_k16_c50_o3_subj  --bound 8 --topk 16 --neighbourhood-cap 50
# neighbourhood-cap sweep
run_one b8_k32_c10_o3_subj  --bound 8 --topk 32 --neighbourhood-cap 10
run_one b8_k32_c100_o3_subj --bound 8 --topk 32 --neighbourhood-cap 100
# strict baseline config for cross-dataset comparison
run_one b3_k4_c10_o3_subj   --bound 3 --topk 4  --neighbourhood-cap 10
# owner-count sweep (b=8, k=32, c=50, subject-hash)
run_one b8_k32_c50_o1_subj  --bound 8 --topk 32 --neighbourhood-cap 50 --owners 1
run_one b8_k32_c50_o2_subj  --bound 8 --topk 32 --neighbourhood-cap 50 --owners 2
run_one b8_k32_c50_o4_subj  --bound 8 --topk 32 --neighbourhood-cap 50 --owners 4
run_one b8_k32_c50_o8_subj  --bound 8 --topk 32 --neighbourhood-cap 50 --owners 8
# partition method
run_one b8_k32_c50_o3_edge  --bound 8 --topk 32 --neighbourhood-cap 50 --partition edge-hash
run_one b8_k32_c50_o8_edge  --bound 8 --topk 32 --neighbourhood-cap 50 --owners 8 --partition edge-hash
run_one b8_k32_c50_o4_reldom --bound 8 --topk 32 --neighbourhood-cap 50 --owners 4 --partition relation-domain
echo "ALL ABLATIONS DONE"
