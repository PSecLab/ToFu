#!/usr/bin/env bash
# VM bootstrap for the MCPSafetyScanner baseline (johnhalloran321). Run from the
# repo root on the Linux VM. Its own venv (agno multi-agent + mcp + openai).
# The VM is the sandbox: it launches the MCP servers to read their tool lists.
#
#   bash eval/vm_bootstrap_mcpsafety.sh          # build venv + preflight + smoke
set -euo pipefail
[ -f eval/run_mcpsafety.py ] || { echo "run from repo root"; exit 1; }
REPO="$(pwd)"; S="$REPO/Benchmarks/MCPSafetyScanner"
[ -f "$S/pyproject.toml" ] || { echo "MCPSafetyScanner not present -- git pull"; exit 1; }
export PATH="$HOME/.local/bin:$PATH"
command -v uv >/dev/null || { curl -LsSf https://astral.sh/uv/install.sh | sh; export PATH="$HOME/.local/bin:$PATH"; }

echo "== MCPSafetyScanner venv (agno + mcp + openai) =="
uv python install 3.11 >/dev/null 2>&1 || true
[ -x "$S/.venv/bin/python" ] || uv venv "$S/.venv" --python 3.11 >/dev/null
SPY="$S/.venv/bin/python"
uv pip install --python "$SPY" -q -e "$S"
# adapter/client parity: the scanner's mcp client must match modern servers.
uv pip install --python "$SPY" -q "mcp>=1.9,<2" || true
"$SPY" -c "import agno, mcp, openai; print('mcpsafety deps OK')"

echo "== .env / key =="; [ -f "$REPO/.env" ] || { echo "scp .env first"; exit 1; }
set -a; . "$REPO/.env"; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo ".env has no OPENAI_API_KEY"; exit 1; }

echo "== preflight =="; python3 eval/run_mcpsafety.py --preflight
echo "== SMOKE: 1 server (gpt-4.1) =="
MCPSAFETY_MODEL=gpt-4.1 python3 eval/run_mcpsafety.py --limit 1 || true
echo
echo "=================================================================="
echo "Full run in tmux (all 40, gpt-4.1):"
echo "  tmux new -s mcpsafety"
echo "  cd $REPO && set -a && . ./.env && set +a && MCPSAFETY_MODEL=gpt-4.1 \\"
echo "    python3 eval/run_mcpsafety.py 2>&1 | tee eval/state/mcpsafety_vm_\$(date +%Y%m%d_%H%M%S).log"
echo "=================================================================="
