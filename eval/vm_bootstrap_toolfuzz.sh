#!/usr/bin/env bash
# VM bootstrap for the ToolFuzz baseline (eth-sri/ToolFuzz). Run from the repo
# root on the Linux VM AFTER vm_bootstrap_viper.sh (reuses node/uv/the prepared
# targets). ToolFuzz needs its OWN Python 3.10 env (separate from Viper/ToFu).
#
#   bash eval/vm_bootstrap_toolfuzz.sh          # build env + smoke one tool
#
# The VM is the sandbox: ToolFuzz executes the MCP tools. Idempotent.
set -euo pipefail
[ -f eval/run_toolfuzz.py ] || { echo "run from repo root"; exit 1; }
REPO="$(pwd)"; TF="$REPO/Benchmarks/ToolFuzz"
export PATH="$HOME/.local/bin:$PATH"
command -v uv >/dev/null || { curl -LsSf https://astral.sh/uv/install.sh | sh; export PATH="$HOME/.local/bin:$PATH"; }

echo "== ToolFuzz py3.10 venv (its setup.py pins langchain>=0.3.19, langgraph>=0.2.74) =="
uv python install 3.10 >/dev/null 2>&1 || true
[ -x "$TF/.venv/bin/python" ] || uv venv "$TF/.venv" --python 3.10 >/dev/null
TFPY="$TF/.venv/bin/python"
# ToolFuzz itself + the MCP->langchain bridge. langchain_mcp_adapters must match
# ToolFuzz's langchain-core (0.3.x); pin a 0.1.x adapter that supports it.
uv pip install --python "$TFPY" -q -e "$TF"
# langchain-mcp-adapters 0.1.x imports mcp.shared.session.ProgressFnT, which
# exists in mcp 1.9+ (NOT mcp 2.x, which restructured the package). Pin mcp 1.x.
uv pip install --python "$TFPY" -q "langchain-mcp-adapters>=0.1,<0.2" "mcp>=1.9,<2" "langgraph>=0.2.74" "langchain-openai>=0.3.6"
echo "== import check =="
cd "$TF" && "$TFPY" - <<'PY'
import sys; sys.path.insert(0, ".")
from src.toolfuzz.runtime.runtime_fuzzer import RuntimeErrorTester
from src.toolfuzz.correctness.correctness_fuzzer import CorrectnessTester
from src.toolfuzz.agent_executors.langchain.react_new import ReactAgentNew
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
print("ToolFuzz + bridge imports OK")
PY
cd "$REPO"
echo "== .env =="; [ -f .env ] || { echo "scp .env first"; exit 1; }; set -a; . ./.env; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo ".env has no OPENAI_API_KEY"; exit 1; }
echo
echo "== SMOKE: one small repo, runtime only, iters=3 =="
OPENAI_API_KEY="$OPENAI_API_KEY" "$TFPY" eval/run_toolfuzz.py --only maoxiaoke --modes runtime --iters 3 --max-tools 1 || true
echo
echo "=================================================================="
echo "If the smoke wrote a rec to eval/state/toolfuzz_runs.jsonl, run full in tmux:"
echo "  tmux new -s toolfuzz"
echo "  cd $REPO && set -a && . ./.env && set +a \\"
echo "    && $TFPY eval/run_toolfuzz.py --iters 10 --modes runtime,correctness \\"
echo "       2>&1 | tee eval/state/toolfuzz_vm_\$(date +%Y%m%d_%H%M%S).log"
echo "=================================================================="
