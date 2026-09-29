#!/usr/bin/env bash
# Measure ToFu's real LLM usage (calls + tokens) on the ablation set (266 servers / 1,801 tools),
# with the SAME recording proxy that metered Viper and Cisco (eval/llm_cache_proxy.py).
#
# ToFu's replay cache stores only the LLM's outputs, not the prompts or token usage, so the usage
# cannot be reconstructed from disk. This re-runs ToFu's two LLM stages (sanitizer selection +
# seed generation) live for every tool, through the proxy, with an EMPTY ToFu cache, and a 5 s
# fuzz budget (fuzzing makes no LLM calls; the budget only has to be long enough to start).
# Model/temperature/seed come from .tofu_env.sh (gpt-4.1, T=0, seed 20260910), as in every run.
#
#   RUN IN tmux on the PSU PC, NOT through a tool (~1-1.5 h, ~$35-40 of gpt-4.1):
#     tmux new -s tofuusage
#     cd /scratch/tofu && source ./.tofu_env.sh
#     ./eval/measure_tofu_llm_usage.sh
#   ./eval/measure_tofu_llm_usage.sh --summary   # summarize the ledger only, runs nothing
#
# Resumable (run_eval skips finished configs). Ctrl-C-safe: the proxy is stopped on exit.
set -u
cd "$(dirname "$0")/.." || exit 1

PORT="${USAGE_PROXY_PORT:-8792}"
PROXY_DIR="$PWD/eval/state/tofu_usage_proxy"      # proxy ledger (+ its own record of responses)
TOFU_CACHE="$PWD/eval/state/llm_cache_usage"      # fresh ToFu cache -> every tool misses -> live calls
PREFIX="usage"

summary() { python3 eval/tofu_llm_usage_summary.py --ledger "$PROXY_DIR/_ledger.jsonl" \
                    --index "eval/state/runs.$PREFIX-full.jsonl"; }
[ "${1:-}" = "--summary" ] && { summary; exit 0; }

[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set (source ./.tofu_env.sh first)"; exit 1; }
mkdir -p "$PROXY_DIR" "$TOFU_CACHE"

python3 eval/llm_cache_proxy.py --port "$PORT" --cache-dir "$PROXY_DIR" --mode rw \
    > "$PROXY_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
trap 'kill $PROXY_PID 2>/dev/null; echo "proxy stopped"' EXIT
sleep 2
kill -0 $PROXY_PID 2>/dev/null || { echo "proxy failed to start: $(tail -3 $PROXY_DIR/proxy.log)"; exit 1; }
echo "proxy up on :$PORT (ledger $PROXY_DIR/_ledger.jsonl)"

export TOFU_LLM_BASE_URL="http://127.0.0.1:$PORT/v1"   # ToFu -> proxy -> api.openai.com
export TOFU_LLM_CACHE_DIR="$TOFU_CACHE"
export TOFU_TIME="${TOFU_TIME:-5}"
ABL_ALLOW_CACHE_MISS=1 ABL_PREFIX="$PREFIX" ABL_ARMS=full ./eval/run_ablation.sh "$@"
rc=$?
echo; summary
exit $rc
