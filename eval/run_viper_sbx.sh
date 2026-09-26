#!/usr/bin/env bash
# Viper-MCP baseline under the bubblewrap sandbox. Viper's Phase II EXECUTES the
# target, so it gets the same containment as ToFu's fuzzers (CLAUDE.md): / read-only,
# private /tmp, secrets masked, .env blanked (the key is passed via env), and only
# eval/viper_runs/, eval/state/viper_runs.jsonl and VIPER_HOME (codeql pack/compile
# cache) writable. Run natively in tmux (CLAUDE.md rule 4).
#
#   ./eval/run_viper_sbx.sh --only "a/b,c/d"           # named repos, 10 rounds
#   ./eval/run_viper_sbx.sh --only a/b --rounds 1      # smoke
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
REAL_HOME=$HOME
[ -f "$ROOT/.tofu_env.sh" ] && source "$ROOT/.tofu_env.sh" >/dev/null 2>&1   # PC: nvm node 22 + caches
[ -s "$REAL_HOME/.nvm/nvm.sh" ] && { source "$REAL_HOME/.nvm/nvm.sh" >/dev/null 2>&1; nvm use 22 >/dev/null 2>&1; }
ENVF=.env; [ -f "$ENVF" ] || ENVF=.env.campaign-hidden
[ -f "$ENVF" ] && { set -a; . "./$ENVF"; set +a; }
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set (.env)"; exit 1; }
command -v bwrap >/dev/null || { echo "bubblewrap missing"; exit 1; }
bwrap --ro-bind / / --tmpfs /tmp -- /bin/true 2>/dev/null || { echo "bwrap cannot start (userns?)"; exit 1; }

CODEQL="${VIPER_CODEQL:-}"
[ -z "$CODEQL" ] && for c in "$ROOT/tools/codeql/codeql" "$REAL_HOME/codeql/codeql"; do [ -x "$c" ] && { CODEQL=$c; break; }; done
[ -x "$CODEQL" ] || { echo "codeql not found (set VIPER_CODEQL)"; exit 1; }
VH="${VIPER_HOME:-$ROOT/.viper_home}"; [ -d "$VH/.codeql" ] || VH=$REAL_HOME   # VM: packs live in ~/.codeql
mkdir -p "$ROOT/eval/viper_runs"; touch "$ROOT/eval/state/viper_runs.jsonl"

M=""
for d in .ssh .aws .gnupg .kube .docker .config/gcloud .config/gh; do [ -d "$REAL_HOME/$d" ] && M="$M --tmpfs $REAL_HOME/$d"; done
for f in "$ROOT"/.env*; do [ -f "$f" ] && M="$M --ro-bind /dev/null $f"; done
HOMEBIND="--bind $VH/.codeql $VH/.codeql"; [ "$VH" != "$REAL_HOME" ] && HOMEBIND="--bind $VH $VH --setenv HOME $VH"

run_sbx() {   # run one sandboxed run_viper with the given args
  bwrap --die-with-parent --ro-bind / / --dev /dev --tmpfs /dev/shm --proc /proc --tmpfs /tmp $M \
    --bind "$ROOT/eval/viper_runs" "$ROOT/eval/viper_runs" \
    --bind "$ROOT/eval/state/viper_runs.jsonl" "$ROOT/eval/state/viper_runs.jsonl" $HOMEBIND \
    -- "$ROOT/.venv/bin/python" eval/run_viper.py --codeql "$CODEQL" "$@"
}

# Parallelism. run_viper.py is serial and Viper calls codeql without --threads (1
# thread), so by default this uses ~1 core. VIPER_PARALLEL=N runs N sandboxed shards
# over the --only list concurrently; CODEQL_THREADS (honored by the codeql CLI) splits
# VIPER_THREADS (default 12) across them. Each shard logs to eval/viper_runs/.shard<k>.log.
PAR="${VIPER_PARALLEL:-1}"; TOT="${VIPER_THREADS:-12}"
ONLY=""; REST=()
while [ $# -gt 0 ]; do
  case "$1" in --only) ONLY="$2"; shift 2 ;; --only=*) ONLY="${1#--only=}"; shift ;; *) REST+=("$1"); shift ;; esac
done
echo "viper(sbx): codeql=$($CODEQL version 2>/dev/null | head -1) home=$VH parallel=$PAR threads=$TOT"
if [ "$PAR" -le 1 ] || [ -z "$ONLY" ]; then
  export CODEQL_THREADS="${CODEQL_THREADS:-$TOT}"
  [ -n "$ONLY" ] && exec_args=(--only "$ONLY") || exec_args=()
  run_sbx "${exec_args[@]}" "${REST[@]}"; exit $?
fi
export CODEQL_THREADS=$(( TOT / PAR > 0 ? TOT / PAR : 1 ))
IFS=, read -r -a REPOS <<< "$ONLY"
pids=()
for ((k=0; k<PAR; k++)); do
  part=""; for ((i=k; i<${#REPOS[@]}; i+=PAR)); do part="${part:+$part,}${REPOS[$i]}"; done
  [ -z "$part" ] && continue
  echo "  shard $k: $part  (CODEQL_THREADS=$CODEQL_THREADS)"
  run_sbx --only "$part" "${REST[@]}" > "$ROOT/eval/viper_runs/.shard$k.log" 2>&1 &
  pids+=($!)
done
rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
echo "viper(sbx): all shards done rc=$rc  (logs: eval/viper_runs/.shard*.log)"
exit $rc
