#!/usr/bin/env bash
# ToolFuzz H2H-45 on the PSU PC, next to a live repo24 campaign.
# Uses its own targets/configs/state (eval/*_tf) and ToolFuzz's own py3.10 venv;
# every target server runs in bwrap (run_toolfuzz.py). Resumable; Ctrl-C safe.
#   cd /scratch/tofu && tmux new -s toolfuzz ./eval/psu_toolfuzz_run.sh
# Needs OPENAI_API_KEY in /scratch/tofu/.env (chmod 600).
set -uo pipefail
R=/scratch/tofu
cd "$R" || exit 1
source "$R/.tofu_env.sh"
export TOOLFUZZ_PREPARED="$R/eval/state_tf/prepared.jsonl"
export TOOLFUZZ_INDEX="$R/eval/state_tf/toolfuzz_runs.jsonl"
export TOOLFUZZ_CALLS_FILE="$R/eval/state_tf/toolfuzz_llm_calls.json"
export TOOLFUZZ_CACHE_DB="$R/eval/state_tf/toolfuzz_llm_cache.sqlite"
export TOOLFUZZ_OUT="$R/eval/toolfuzz_runs"
export TOOLFUZZ_TOFU_INDEX="$R/findings/baselines/tofu_runs_e2_20260922.jsonl"
export SHARDS="${SHARDS:-3}" NICE="${NICE:-10}"
exec ./eval/run_toolfuzz_h2h.sh "$@"
