#!/usr/bin/env bash
# One-shot VM bootstrap for a ToFu fuzzing campaign (the harness itself, not
# Viper -- see vm_bootstrap_viper.sh for that). Run FROM the cloned repo root on
# a Linux VM (x86_64 or aarch64). Idempotent: safe to re-run.
#
#   scp eval/vm_bootstrap_tofu.sh .env  user@VM:~/toolfuzzer/   (from laptop)
#   ssh user@VM
#   cd ~/toolfuzzer && bash eval/vm_bootstrap_tofu.sh
#
# The VM is the sandbox (untrusted MCP servers run here, not on your laptop),
# so no Docker layer. sudo is used ONLY for apt.
#
# WHY 3.13 (nazmul.todo item 86): PythonRunner imports Python targets
# IN-PROCESS, so every target venv must be the same CPython as ToFu's, and the
# runner refuses to start otherwise. atheris 3.0.0 supports 3.11-3.13; 3.13 is
# the only version satisfying every corpus lockfile (uml >=3.12,<3.15; osm and
# mcp-text-editor >=3.13). prepare_targets.py defaults TOFU_TARGET_PYTHON to the
# interpreter that runs it -- which is why every ToFu command below uses
# .venv/bin/python, never the system python3.
set -euo pipefail
[ -f eval/run_eval.py ] || { echo "run this from the repo root (eval/run_eval.py not found)"; exit 1; }
REPO="$(pwd)"
PYVER=3.13
export TOFU_TARGET_PYTHON="$PYVER"

case "$(uname -m)" in
  x86_64)        FUZZ_ARCH=x86_64 ;;
  aarch64|arm64) FUZZ_ARCH=aarch64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac
echo "== arch $(uname -m) -> libFuzzer archive for $FUZZ_ARCH =="

echo "== 1/7 system packages (sudo: apt only) =="
sudo apt-get update -qq
# clang/llvm + compiler-rt: atheris builds its libFuzzer bindings from source
# on Linux. The compiler-rt package name differs by distro release; try the
# generic one first, then the versioned one for the installed clang.
sudo apt-get install -y -qq git curl ca-certificates build-essential unzip procps lsof clang llvm >/dev/null
sudo apt-get install -y -qq libclang-rt-dev >/dev/null 2>&1 \
  || sudo apt-get install -y -qq "libclang-rt-$(clang --version | grep -oE '[0-9]+' | head -1)-dev" >/dev/null 2>&1 \
  || echo "   WARNING: no libclang-rt package found; atheris may fail to link libFuzzer"
if ! command -v node >/dev/null || [ "$(node -v | cut -d. -f1 | tr -d v)" -lt 22 ]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - >/dev/null
  sudo apt-get install -y -qq nodejs >/dev/null
fi
echo "   node $(node -v)  clang $(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)"

echo "== 2/7 uv + managed Python $PYVER + bun (no sudo) =="
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
export PATH="$HOME/.local/bin:$HOME/.bun/bin:$PATH"
uv python install "$PYVER" >/dev/null 2>&1 || true
# bun: several corpus node repos build with `bun build` (memory-bank-mcp, cal-mcp, ...)
command -v bun >/dev/null || curl -fsSL https://bun.sh/install | bash >/dev/null 2>&1 || echo "   WARNING: bun install failed (bun-built node targets will skip)"
grep -q 'TOFU_TARGET_PYTHON' ~/.bashrc 2>/dev/null || cat >> ~/.bashrc <<EOF
export PATH="\$HOME/.local/bin:\$HOME/.bun/bin:\$PATH"
export TOFU_TARGET_PYTHON=$PYVER
EOF
echo "   uv $(uv --version)  bun $(bun --version 2>/dev/null || echo none)"

echo "== 3/7 libFuzzer archive check =="
LIB="$(clang -print-file-name=libclang_rt.fuzzer_no_main-${FUZZ_ARCH}.a)"
case "$LIB" in /*) [ -f "$LIB" ] || LIB="" ;; *) LIB="" ;; esac
[ -n "$LIB" ] || { echo "   FATAL: libclang_rt.fuzzer_no_main-${FUZZ_ARCH}.a not found via clang. Install the compiler-rt package for your clang (e.g. libclang-rt-18-dev) and re-run."; exit 1; }
echo "   $LIB"

echo "== 4/7 ToFu venv (.venv, Python $PYVER) + requirements (atheris from source) =="
if [ -x .venv/bin/python ] && ! .venv/bin/python -c "import sys; assert sys.version_info[:2] == tuple(map(int, '$PYVER'.split('.')))" 2>/dev/null; then
  echo "   existing .venv is not $PYVER -> rebuilding"; rm -rf .venv
fi
[ -x .venv/bin/python ] || uv venv .venv --python "$PYVER" >/dev/null
CC=clang CXX=clang++ LIBFUZZER_LIB="$LIB" uv pip install --python .venv/bin/python -q -r requirements.txt
.venv/bin/python -c "import sys, atheris, mcp; print('   python', sys.version.split()[0], '| atheris+mcp import OK')"

echo "== 5/7 tests (must be green before any campaign; CLAUDE.md) =="
.venv/bin/python -m pytest tests/ -q -x 2>&1 | tail -2

echo "== 6/7 secrets check (.env must be scp'd; never committed) =="
[ -f "$REPO/.env" ] || { echo "   MISSING .env -> scp it from the laptop, then re-run"; exit 1; }
set -a; . "$REPO/.env"; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo "   .env has no OPENAI_API_KEY"; exit 1; }
echo "   OPENAI_API_KEY present (len=${#OPENAI_API_KEY})"

echo "== 7/7 prepare targets ON THIS VM (arch-specific; Python venvs on $PYVER) =="
# prepared.jsonl/skipped.jsonl from another host carry FOREIGN absolute paths;
# leaving them makes prepare skip everything and targets never clone.
rm -f eval/state/prepared.jsonl eval/state/skipped.jsonl
# .venv/bin/python, NOT python3: TOFU_TARGET_PYTHON defaults to the running interpreter.
.venv/bin/python eval/prepare_targets.py --only-set host
echo
echo "=================================================================="
echo "BOOTSTRAP DONE. Verify the Python arm on ONE tool first (60s, cheap):"
echo
echo "  cd $REPO && set -a && . ./.env && set +a && export TOFU_TARGET_PYTHON=$PYVER \\"
echo "    && ARM=py313-smoke TOFU_TIME=60 WORKERS=1 ./eval/run_arm_gpt41.sh --only-repo mcp-text-editor --limit 1"
echo "  grep -h 'EXEC_SUMMARY\\|PythonRunner' eval/runs/py313-smoke/*.log   # need n_success>0 and 'via in-process'"
echo
echo "Then the campaign, inside tmux (hours; resumable, Ctrl-C safe):"
echo
echo "  tmux new -s tofu"
echo "  cd $REPO && set -a && . ./.env && set +a && export TOFU_TARGET_PYTHON=$PYVER \\"
echo "    && ARM=gpt41-vm TOFU_TIME=900 WORKERS=4 ./eval/run_arm_gpt41.sh 2>&1 | tee eval/state/tofu_vm_\$(date +%Y%m%d_%H%M%S).log"
echo
echo "Detach: Ctrl-b d   Reattach: tmux attach -t tofu   Progress: .venv/bin/python eval/run_eval.py --arm gpt41-vm --status"
echo "Results back to laptop: rsync eval/runs/gpt41-vm/ eval/state/runs.gpt41-vm.jsonl"
echo "=================================================================="
