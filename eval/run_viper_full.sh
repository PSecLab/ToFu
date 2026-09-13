#!/usr/bin/env bash
# VIPER-MCP full baseline (Phase I CodeQL + Phase II LLM fuzz) over every
# prepared ToFu target. Run this in YOUR terminal, not through a tool call:
# ~15 min/server per the VIPER paper -> 40 servers ~= 10 h. Ctrl-C safe,
# resumable (skips repos already in eval/state/viper_runs.jsonl).
#
#   ./eval/run_viper_full.sh            # all servers, rounds=10 (paper default)
#   ./eval/run_viper_full.sh smoke      # 1 server, rounds=2
#   VIPER_ROUNDS=5 ./eval/run_viper_full.sh
#
# Protocol (state in the paper): gpt-4.1 for all three LLM roles (theirs:
# gpt-5.4), temperature 0 (theirs: 0.7), CodeQL 2.27.0, four PATCH (ToFu)
# edits to the artifact (see findings/baselines/README.md). Serial (workers=1):
# CodeQL DB builds are CPU/RAM heavy and Phase II restarts the target server
# every prompt; parallel runs would contend and distort per-server timing.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
set -a; . ./.env; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set in .env"; exit 1; }
# CodeQL: brew on the laptop, or ~/codeql (bundle) on a Linux VM.
export PATH="$HOME/codeql:$HOME/.local/bin:$PATH"
command -v codeql >/dev/null || { echo "codeql not on PATH (laptop: brew install codeql; VM: eval/vm_bootstrap_viper.sh)"; exit 1; }
# Interpreter: run_viper.py is stdlib-only. Use ToFu's .venv when present
# (laptop), else the system python3 (VM). Viper's own deps live in
# Benchmarks/Viper-MCP/.venv, which run_viper.py picks up via VPY.
PY="${PY:-$( [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3 )}"

export VIPER_MODEL="${VIPER_MODEL:-gpt-4.1}"
export VIPER_ROUNDS="${VIPER_ROUNDS:-10}"
MODE="${1:-full}"
LOG="eval/state/viper_full_$(date +%Y%m%d_%H%M%S).log"
mkdir -p eval/state

case "$MODE" in
  smoke) EXTRA="--limit 1"; export VIPER_ROUNDS=2 ;;
  *)     EXTRA="" ;;
esac

echo "model=$VIPER_MODEL rounds=$VIPER_ROUNDS codeql=$(codeql version --format=terse) log=$LOG"
exec "$PY" eval/run_viper.py --timeout 1800 ${EXTRA} 2>&1 | tee "$LOG"
