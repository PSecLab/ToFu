#!/usr/bin/env bash
# Run VIPER-MCP inside its own container (tofu-viper-sandbox). Reuses the SAME
# sandbox-prepared targets as ToFu (eval/sandbox/targets + state), so Viper and
# ToFu score the identical corpus. Viper output -> eval/sandbox/viper_runs.
#
#   ./eval/viper_sandbox.sh build
#   ./eval/viper_sandbox.sh smoke                 # 1 target, Phase I+II
#   ./eval/viper_sandbox.sh run [args...]         # all prepared targets
#   ./eval/viper_sandbox.sh shell
#
# Repo mounted READ-ONLY at its real path (paths in prepared.jsonl stay valid;
# an escape lands in the container, not $HOME). CodeQL + node run inside.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="tofu-viper-sandbox:latest"
SBX="$REPO/eval/sandbox"
# viper_runs holds per-target CodeQL DBs + SARIF + fuzz results (can be GBs).
OVERLAYS=(targets state viper_runs)
for d in "${OVERLAYS[@]}"; do mkdir -p "$SBX/$d" "$REPO/eval/$d"; done

need_docker(){ docker version >/dev/null 2>&1 || { echo "Docker daemon not up (open -a Docker)"; exit 1; }; }
mounts(){
  local m=(-v "$REPO:/work:ro")
  for d in "${OVERLAYS[@]}"; do m+=(-v "$SBX/$d:/work/eval/$d"); done
  m+=(--tmpfs /tmp:rw,exec,size=2g)
  echo "${m[@]}"
}
run_opts(){ echo --rm -i --init --memory 10g --cpus 4 --pids-limit 2048 \
  -w /work -e HOME=/home/tofu -e VIPER_PY=/opt/viper-venv/bin/python -e VIPER_MODEL=gpt-4.1; }

case "${1:-}" in
  build) need_docker; exec docker build -f "$REPO/Dockerfile.viper" -t "$IMAGE" "$REPO" ;;
  shell) need_docker; exec docker run $(run_opts) -t $(mounts) "$IMAGE" /bin/bash ;;
  smoke) need_docker; shift
    set -a; . "$REPO/.env" 2>/dev/null || true; set +a
    exec docker run $(run_opts) -e OPENAI_API_KEY $(mounts) "$IMAGE" \
      python eval/run_viper.py --only excel-reader --limit 1 --timeout 1500 "$@" ;;
  run) need_docker; shift
    set -a; . "$REPO/.env" 2>/dev/null || true; set +a
    exec docker run $(run_opts) -e OPENAI_API_KEY $(mounts) "$IMAGE" \
      python eval/run_viper.py --timeout 1800 "$@" ;;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
