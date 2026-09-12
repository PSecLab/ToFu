#!/usr/bin/env bash
# Cisco MCP Scanner baseline with gpt-4.1 as the llm analyzer.
#
# WHY gpt-4.1: it is the SAME model as ToFu's gpt41-full arm, so the Cisco-vs-
# ToFu comparison holds the LLM fixed and varies only the tool. yara needs no
# model; the `api` (cloud) analyzer stays OFF -- no Cisco AI Defense
# subscription -- so this baseline is the open-source analyzers only.
#
#   ./eval/run_cisco_gpt41.sh              # all prepared servers, yara+llm
#   ./eval/run_cisco_gpt41.sh smoke        # 2 servers
#   ./eval/run_cisco_gpt41.sh yara         # yara-only, no LLM (fast)
#   ./eval/run_cisco_gpt41.sh summary      # print ToFu-vs-Cisco table
#
# RESUMABLE: appends to eval/state/cisco_runs.jsonl; re-running skips done repos.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
PY="$PWD/.venv/bin/python"
RUNNER="eval/run_cisco_scanner.py"

set -a; . ./.env; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set in .env"; exit 1; }

export CISCO_LLM_MODEL="${CISCO_LLM_MODEL:-openai/gpt-4.1}"
export CISCO_LLM_BASE_URL="${CISCO_LLM_BASE_URL:-https://api.openai.com/v1}"
export MCP_SCANNER_LLM_API_KEY="$OPENAI_API_KEY"
export CISCO_LLM_TIMEOUT="${CISCO_LLM_TIMEOUT:-120}"

MODE="${1:-full}"
case "$MODE" in
  summary) exec "$PY" "$RUNNER" --summary ;;
  yara)    ANALYZERS="yara"; LIMIT="" ;;
  smoke)   ANALYZERS="yara,llm"; LIMIT="--limit 2" ;;
  full|*)  ANALYZERS="yara,llm"; LIMIT="" ;;
esac

echo "model=$CISCO_LLM_MODEL  endpoint=$CISCO_LLM_BASE_URL  analyzers=$ANALYZERS"
exec "$PY" "$RUNNER" --analyzers "$ANALYZERS" --workers 2 ${LIMIT}
