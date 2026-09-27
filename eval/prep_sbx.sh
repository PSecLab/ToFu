#!/usr/bin/env bash
# Sandboxed target preparation. clone + `npm install` / `uv pip install` run the
# packages' OWN build/postinstall scripts = third-party code execution. On the
# sensitive PSU PC (CLAUDE.md) that MUST be sandboxed. Filesystem is read-only
# except the target/config/state/cache dirs; ~/.ssh, cloud creds and .env* are
# masked unreadable; network stays ON (prep needs to clone + download).
#
#   source ./.tofu_env.sh   # node 22 + caches on /scratch (PC)
#   ./eval/prep_sbx.sh --only-set full --only-repos-file <list> [prepare_targets args...]
#
# Uses the harness .venv python so target venvs match it (item: python-mismatch guard).
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
PY="${TOFU_PY:-$ROOT/.venv/bin/python}"
command -v bwrap >/dev/null || { echo "bubblewrap missing: sudo apt install bubblewrap"; exit 1; }
[ -x "$PY" ] || { echo "no harness venv python at $PY"; exit 1; }
if command -v node >/dev/null; then case "$(node -v)" in v22.*) : ;; *) echo "node $(node -v) != v22 -- source ./.tofu_env.sh"; exit 1;; esac
else echo "node not on PATH -- source ./.tofu_env.sh"; exit 1; fi

mkdir -p eval/targets eval/configs eval/state
W=(--bind "$ROOT/eval/targets" "$ROOT/eval/targets" \
   --bind "$ROOT/eval/configs" "$ROOT/eval/configs" \
   --bind "$ROOT/eval/state" "$ROOT/eval/state")
for d in "${XDG_CACHE_HOME:-}" "${UV_CACHE_DIR:-}" "${npm_config_cache:-}" "${PLAYWRIGHT_BROWSERS_PATH:-}"; do
    [ -n "$d" ] && mkdir -p "$d" && W+=(--bind "$d" "$d")
done
M=()
for s in .ssh .aws .gnupg .kube .docker .netrc .git-credentials .config/gcloud .config/gh; do
    [ -d "$HOME/$s" ] && M+=(--tmpfs "$HOME/$s")
done
for f in "$ROOT"/.env "$ROOT"/.env.* ; do [ -f "$f" ] && M+=(--ro-bind /dev/null "$f"); done

echo "== sandboxed prepare_targets (network on; targets/configs/state/caches writable; secrets masked) =="
exec bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm \
    "${W[@]}" "${M[@]}" -- "$PY" eval/prepare_targets.py "$@"
