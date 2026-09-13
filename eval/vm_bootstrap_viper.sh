#!/usr/bin/env bash
# One-shot VM bootstrap for the VIPER-MCP baseline. Run FROM the cloned repo
# root on a Linux VM (x86_64 or aarch64). Idempotent: safe to re-run.
#
#   scp eval/vm_bootstrap_viper.sh .env  user@VM:~/toolfuzzer/   (from laptop)
#   ssh user@VM
#   cd ~/toolfuzzer && bash eval/vm_bootstrap_viper.sh
#
# The VM is the sandbox (untrusted MCP servers run here, not on your laptop),
# so no Docker layer. sudo is used ONLY for apt (git/node/build tools).
set -euo pipefail
[ -f eval/run_viper.py ] || { echo "run this from the repo root (eval/run_viper.py not found)"; exit 1; }
REPO="$(pwd)"
CODEQL_TAG="codeql-bundle-v2.27.0"          # same version as the laptop run

case "$(uname -m)" in
  x86_64)  CQ_ARCH=linux64 ;;
  aarch64|arm64) CQ_ARCH=linux-arm64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
echo "== arch $(uname -m) -> codeql bundle $CQ_ARCH =="

echo "== 1/6 system packages (sudo: apt only) =="
sudo apt-get update -qq
sudo apt-get install -y -qq git curl ca-certificates build-essential python3 >/dev/null
if ! command -v node >/dev/null || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - >/dev/null
  sudo apt-get install -y -qq nodejs >/dev/null
fi
echo "   node $(node -v)  git $(git --version | awk '{print $3}')"

echo "== 2/6 uv + managed Python 3.11 (no sudo) =="
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
export PATH="$HOME/.local/bin:$PATH"
uv python install 3.11 >/dev/null 2>&1 || true
echo "   uv $(uv --version)"

echo "== 3/6 CodeQL bundle $CODEQL_TAG ($CQ_ARCH) -> ~/codeql (no sudo) =="
if ! [ -x "$HOME/codeql/codeql" ]; then
  curl -fsSL -o /tmp/codeql.tar.gz \
    "https://github.com/github/codeql-action/releases/download/${CODEQL_TAG}/codeql-bundle-${CQ_ARCH}.tar.gz"
  tar -xzf /tmp/codeql.tar.gz -C "$HOME" && rm -f /tmp/codeql.tar.gz
fi
export PATH="$HOME/codeql:$PATH"
grep -q 'codeql:\$PATH' ~/.bashrc 2>/dev/null || echo 'export PATH="$HOME/codeql:$HOME/.local/bin:$PATH"' >> ~/.bashrc
echo "   codeql $(codeql version --format=terse)"

echo "== 4/6 Viper venv (Benchmarks/Viper-MCP/.venv; run_viper.py's default VPY) =="
V="$REPO/Benchmarks/Viper-MCP"
[ -x "$V/.venv/bin/python" ] || uv venv "$V/.venv" --python 3.11 >/dev/null
uv pip install --python "$V/.venv/bin/python" -q -r "$V/requirements.txt"
"$V/.venv/bin/python" -c "import langchain_mcp_adapters, yaml, openai; print('   viper deps OK')"

echo "== 5/6 secrets check (.env must be scp'd; never committed) =="
[ -f "$REPO/.env" ] || { echo "   MISSING .env -> scp it from the laptop, then re-run"; exit 1; }
set -a; . "$REPO/.env"; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo "   .env has no OPENAI_API_KEY"; exit 1; }
echo "   OPENAI_API_KEY present (len=${#OPENAI_API_KEY})"

echo "== 6/6 re-prepare the 41 host-corpus targets ON THIS VM (arch-specific; 20-40 min) =="
# prepared.jsonl/skipped.jsonl from git (or a prior host) carry FOREIGN absolute
# paths; leaving them makes prepare skip everything and targets never clone.
rm -f eval/state/prepared.jsonl eval/state/skipped.jsonl
python3 eval/prepare_targets.py --only-set host
echo
echo "=================================================================="
echo "BOOTSTRAP DONE. Start the (hours-long) Viper run inside tmux:"
echo
echo "  tmux new -s viper"
echo "  cd $REPO && set -a && . ./.env && set +a \\"
echo "    && export VIPER_MODEL=gpt-4.1 VIPER_ROUNDS=10 PATH=\"\$HOME/codeql:\$HOME/.local/bin:\$PATH\" \\"
echo "    && python3 eval/run_viper.py --timeout 1800 2>&1 | tee eval/state/viper_vm_\$(date +%Y%m%d_%H%M%S).log"
echo
echo "Detach: Ctrl-b d   Reattach: tmux attach -t viper   Progress: wc -l eval/state/viper_runs.jsonl"
echo "=================================================================="
