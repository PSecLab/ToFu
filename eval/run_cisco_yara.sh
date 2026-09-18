#!/usr/bin/env bash
# Cisco MCP Scanner -- YARA analyzer ONLY.
#
# YARA is a pure static rule match on tool metadata (names/descriptions/schemas):
# NO llm analyzer, NO hosted api analyzer => ZERO LLM calls, no external upload,
# no API key needed. This is the "open-source SAST-on-metadata" baseline.
#
# Scans every prepared (status=ready) server in eval/state/prepared.jsonl -- the
# same pool ToFu/CodeQL use. Resumable: Ctrl-C loses only the in-flight server.
#
#   RUN IN tmux:
#     tmux new -s cisco
#     ./eval/run_cisco_yara.sh --setup      # FIRST TIME ONLY: builds the scanner's venv
#     ./eval/run_cisco_yara.sh              # full YARA scan
#     ./eval/run_cisco_yara.sh --summary    # ToFu vs Cisco table
#     ./eval/run_cisco_yara.sh --limit 3    # smoke test
#
# Needs the scanner checkout once (setup will tell you if missing):
#   git clone https://github.com/cisco-ai-defense/mcp-scanner
set -u
cd "$(dirname "$0")/.." || exit 1
exec python3 eval/run_cisco_scanner.py --analyzers yara --workers "${CISCO_WORKERS:-2}" "$@"
