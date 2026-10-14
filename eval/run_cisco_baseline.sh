#!/usr/bin/env bash
# One-shot driver for the Cisco AI Defense MCP Scanner baseline.
#
#   ./eval/run_cisco_baseline.sh            # setup if needed, smoke, then full
#   ./eval/run_cisco_baseline.sh smoke      # 2 servers only
#   ./eval/run_cisco_baseline.sh summary    # print the ToFu-vs-Cisco table
#
# Resumable: safe to Ctrl-C and re-run, it skips servers already scanned.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
ROOT=$(pwd)
RUNNER="$ROOT/eval/run_cisco_scanner.py"
VENV="$ROOT/Benchmarks/Cisco-MCP-Scanner/.venv"

# The scanner runs from its OWN venv; this driver only needs a plain python3.
PY=${PY:-python3}
MODE=${1:-full}

export CISCO_LLM_MODEL=${CISCO_LLM_MODEL:-ollama_chat/llama3.1:8b}
export CISCO_LLM_BASE_URL=${CISCO_LLM_BASE_URL:-http://localhost:11434}

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

if [ "$MODE" = "summary" ]; then
  exec "$PY" "$RUNNER" --summary
fi

if [ ! -x "$VENV/bin/mcp-scanner" ]; then
  say "building the scanner venv (once)"
  "$PY" "$RUNNER" --setup || exit 1
fi

say "preflight"
"$PY" "$RUNNER" --preflight || {
  echo "preflight failed -- fix the above before scanning" >&2
  exit 1
}

if [ "$MODE" = "smoke" ]; then
  say "smoke test: 2 servers"
  exec "$PY" "$RUNNER" --limit 2 --timeout 300 --workers 1
fi

say "smoke test first (2 servers)"
"$PY" "$RUNNER" --limit 2 --timeout 300 --workers 1 || exit 1

say "full baseline"
"$PY" "$RUNNER" --timeout 900 --workers 2

say "comparison"
"$PY" "$RUNNER" --summary
