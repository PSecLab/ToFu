#!/usr/bin/env bash
# Run the ToFu eval INSIDE a container so untrusted MCP servers never touch the
# host FS/creds. The repo is mounted at its identical host path so the absolute
# paths baked into prepared.jsonl work verbatim; a path escape then lands in the
# container, not your home directory.
#
#   ./eval/sandbox.sh build                 # build the image (needs Docker running)
#   ./eval/sandbox.sh shell                 # interactive shell in the sandbox
#   ./eval/sandbox.sh prepare [args...]     # prepare_targets.py inside the sandbox
#   ./eval/sandbox.sh run -- <cmd...>       # any command inside the sandbox
#   ./eval/sandbox.sh smoke                 # build one node target + one fuzz config
#
# State is kept under eval/sandbox/ so this NEVER disturbs the host campaign's
# eval/targets, eval/state, eval/runs.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="tofu-sandbox:latest"
SBX="$REPO/eval/sandbox"
ARM="${ARM:-gpt41-sandbox}"
# Every directory the harness writes gets a sandbox-backed overlay. The repo
# itself is mounted READ-ONLY, so any write path missing from this list fails
# with EROFS mid-run -- keep it in sync with run_eval.py / prepare_targets.py.
OVERLAYS=(targets state runs configs seeds metrics corpora "metrics_$ARM" "corpora_$ARM")
# Two mkdirs per overlay: the sandbox-backed SOURCE, and an empty MOUNTPOINT
# inside the (read-only) repo tree -- Docker cannot create a mountpoint inside
# an ro bind mount (runc: "create mountpoint ... read-only file system"). The
# host-side eval/<d> stays empty; container writes land in eval/sandbox/<d>.
for d in "${OVERLAYS[@]}"; do mkdir -p "$SBX/$d" "$REPO/eval/$d"; done

need_docker() {
  docker version >/dev/null 2>&1 || {
    echo "Docker daemon not reachable. Start Docker Desktop (open -a Docker) and retry." >&2
    exit 1; }
}

# Mount map: repo read-only at its real path (source can't be poisoned by a
# target), with writable sandbox-backed overlays where the harness must write.
# Host home, /etc, other projects are simply absent from the container.
mounts() {
  local m=(-v "$REPO:$REPO:ro")
  for d in "${OVERLAYS[@]}"; do m+=(-v "$SBX/$d:$REPO/eval/$d"); done
  # /tmp is where js_runner puts its Unix socket and where targets dump
  # scratch files; give the container its own writable tmpfs, never host /tmp.
  m+=(--tmpfs /tmp:rw,exec,size=2g)
  echo "${m[@]}"
}

# Resource caps + egress on (LLM API, git clone). No host devices.
run_opts() {
  echo --rm -i --init \
    --memory 8g --cpus 4 --pids-limit 1024 \
    -w /work -e HOME=/home/tofu -e TOFU_LLM_TEMPERATURE=0 -e ARM="$ARM" -e TOFU_ARM="$ARM"
}

case "${1:-}" in
  build)
    need_docker
    exec docker build -f "$REPO/Dockerfile.sandbox" -t "$IMAGE" "$REPO"
    ;;
  shell)
    need_docker
    exec docker run $(run_opts) -t $(mounts) "$IMAGE" /bin/bash
    ;;
  prepare)
    need_docker; shift
    # set -a exports .env for the child; keys reach the container via -e below
    set -a; . "$REPO/.env" 2>/dev/null || true; set +a
    exec docker run $(run_opts) -e OPENAI_API_KEY $(mounts) "$IMAGE" \
      python eval/prepare_targets.py "$@"
    ;;
  run)
    need_docker; shift; [ "${1:-}" = "--" ] && shift
    set -a; . "$REPO/.env" 2>/dev/null || true; set +a
    exec docker run $(run_opts) -e OPENAI_API_KEY $(mounts) "$IMAGE" "$@"
    ;;
  smoke)
    need_docker
    set -a; . "$REPO/.env" 2>/dev/null || true; set +a
    echo "== prepare 1 node target in the sandbox =="
    docker run $(run_opts) -e OPENAI_API_KEY $(mounts) "$IMAGE" \
      python eval/prepare_targets.py --only-set a --only-lang node --limit 1 || exit 1
    echo "== isolation checks (host-side paths baked in, evaluated INSIDE) =="
    HOST_HOME="$HOME"
    docker run $(run_opts) $(mounts) "$IMAGE" bash -c '
      fail=0
      neg() { if [ -e "$1" ]; then echo "  LEAK   $1 is visible"; fail=1; else echo "  ok     $1 unreachable"; fi; }
      echo "-- host paths that MUST be absent --"
      neg "'"$HOST_HOME"'/.ssh"; neg "'"$HOST_HOME"'/.zshrc"; neg "'"$HOST_HOME"'/Library"
      neg "'"$HOST_HOME"'/.aws"; neg "'"$HOST_HOME"'/.config"; neg "/Volumes"
      [ "$(ls -A '"$HOST_HOME"' 2>/dev/null | grep -vc "^pseclab$")" = "0" ] \
        && echo "  ok     host HOME shows nothing but the repo parent" \
        || { echo "  LEAK   host HOME lists: $(ls -A '"$HOST_HOME"' | tr "\n" " ")"; fail=1; }
      echo "-- positive controls --"
      [ -f src/fuzzer.py ] && echo "  ok     repo visible (src/fuzzer.py)" || { echo "  FAIL   repo not mounted"; fail=1; }
      ( echo probe > eval/state/.write_probe && rm eval/state/.write_probe ) 2>/dev/null \
        && echo "  ok     overlay eval/state writable" || { echo "  FAIL   overlay not writable (uid mapping?)"; fail=1; }
      ( echo x > src/.ro_probe ) 2>/dev/null \
        && { echo "  FAIL   repo source is WRITABLE (should be ro)"; rm -f src/.ro_probe; fail=1; } \
        || echo "  ok     repo source read-only"
      ( echo x > /tmp/.tmp_probe && rm /tmp/.tmp_probe ) && echo "  ok     private /tmp writable" || { echo "  FAIL   /tmp"; fail=1; }
      echo "  uid=$(id -u) ps=$(which ps) node=$(node --version) targets_prepared=$(ls eval/targets | wc -l)"
      exit $fail' && echo "== ISOLATION: PASS ==" || echo "== ISOLATION: FAIL (see LEAK/FAIL lines) =="
    ;;
  *)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
