#!/usr/bin/env bash
# Run-tools-first: spend LLM calls ONLY on tools that actually execute.
#   Phase 1  no-LLM probe (TOFU_NO_LLM=1, short budget): mandatory sanitizers + fallback
#            seeds, $0. Determines which tools execute and already trips evidence-gated
#            introspection tracers (path/ssrf/reflected/temp/log) for free.
#   Phase 2  eval/select_executable.py -> the executable config list.
#   Phase 3  full LLM pass, ONLY on those configs.
# All phases go through run_corpus_sbx.sh (sandbox, node-v22 preflight, unsafe-skip).
#
#   ARM=gpt41-expand-pc WORKERS=12 TOFU_RSS_LIMIT_MB=2048 \
#     ./eval/run_probe_then_llm.sh Benchmarks/extraction/corpus_never_fuzzed_pc.txt
#
# Resumable: re-running re-enters each phase; run_eval skips done configs per arm.
set -u
cd "$(dirname "$0")/.." || exit 1
ARM="${ARM:?set ARM base name, e.g. gpt41-expand-pc}"
REPOS="${1:?usage: run_probe_then_llm.sh <repos-file> [extra run_eval args]}"; shift || true
PY="${TOFU_PY:-$PWD/.venv/bin/python}"
PROBE_TIME="${TOFU_PROBE_TIME:-30}"
EXEC_LIST="eval/exec_${ARM}.txt"
[ -f "$REPOS" ] || { echo "no repos file: $REPOS"; exit 1; }

echo "############ PHASE 1: no-LLM probe (arm ${ARM}-probe, ${PROBE_TIME}s/tool, \$0) ############"
ARM="${ARM}-probe" TOFU_NO_LLM=1 TOFU_TIME="$PROBE_TIME" CORPUS_MODE=none \
    bash ./eval/run_corpus_sbx.sh --only-repos-file "$REPOS" "$@" || { echo "phase 1 failed"; exit 1; }

echo "############ PHASE 2: pick executable configs ############"
"$PY" eval/select_executable.py --arm "${ARM}-probe" --out "$EXEC_LIST" || { echo "phase 2 failed"; exit 1; }
N=$(grep -vc '^#' "$EXEC_LIST" 2>/dev/null || echo 0)
echo "   executable configs: $N -> $EXEC_LIST"
[ "$N" -gt 0 ] || { echo "no executable configs; nothing to send to the LLM. Done."; exit 0; }

echo "############ PHASE 3: LLM pass (arm ${ARM}) on ${N} executable configs ############"
ARM="$ARM" CORPUS_MODE=none \
    bash ./eval/run_corpus_sbx.sh --only-configs-file "$EXEC_LIST" "$@"
