#!/usr/bin/env bash
# Viper-MCP baseline under the bubblewrap sandbox. Viper's Phase II EXECUTES the
# target, so it gets the same containment as ToFu's fuzzers (CLAUDE.md): / read-only,
# private /tmp, secrets masked, .env blanked (the key is passed via env), and only
# eval/viper_runs/, eval/state/viper_runs.jsonl and VIPER_HOME (codeql pack/compile
# cache) writable. Run natively in tmux (CLAUDE.md rule 4).
#
#   ./eval/run_viper_sbx.sh --only "a/b,c/d"           # named repos, 10 rounds
#   ./eval/run_viper_sbx.sh --only a/b --rounds 1      # smoke
#   VIPER_TAG=c251 VIPER_PARALLEL=4 VIPER_THREADS=4 \
#     ./eval/run_viper_sbx.sh --repos-file Benchmarks/extraction/ablation_251_repos.txt
#       campaign mode: own index eval/state/viper_runs.<tag>.jsonl + outputs
#       eval/viper_runs/<tag>/; RESUMABLE (re-run the same command: repos with an ok row
#       are skipped); Ctrl-C safe (partial repo is re-run cleanly); `touch
#       eval/viper_runs/<tag>/STOP` = finish the current repos, then stop.
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
TAG="${VIPER_TAG:-}"; export VIPER_TAG="$TAG"
IDX="$ROOT/eval/state/viper_runs${TAG:+.$TAG}.jsonl"
mkdir -p "$ROOT/eval/viper_runs${TAG:+/$TAG}"; touch "$IDX"

M=""
for d in .ssh .aws .gnupg .kube .docker .config/gcloud .config/gh; do [ -d "$REAL_HOME/$d" ] && M="$M --tmpfs $REAL_HOME/$d"; done
for f in "$ROOT"/.env*; do [ -f "$f" ] && M="$M --ro-bind /dev/null $f"; done
# Private, writable, per-sandbox HOME inside the tmpfs /tmp: target servers write state
# under $HOME (e.g. todo-list-mcp's SQLite DB -> "unable to open database file" when HOME
# was the read-only real home). CodeQL still finds its packs/compile cache via a symlink.
HOMEBIND="--bind $VH/.codeql $VH/.codeql"; [ "$VH" != "$REAL_HOME" ] && HOMEBIND="--bind $VH $VH"
HOMEBIND="$HOMEBIND --dir /tmp/vhome --symlink $VH/.codeql /tmp/vhome/.codeql --setenv HOME /tmp/vhome"

# Viper instruments PYTHON targets by writing mcp_fuzzer_hook_auto.pth into the
# target venv. The real targets must stay pristine (ToFu fuzzes them too), and this
# bwrap (0.9) has no overlay, so each repo gets a throwaway COPY bound over its own
# path: Viper sees the normal path and writes into the copy; the copy is deleted after.
work_binds() {   # $1 = comma list of repos, $2 = work dir  -> prints bwrap bind args
  local r slug
  mkdir -p "$2"
  IFS=, read -r -a _rs <<< "$1"
  for r in "${_rs[@]}"; do
    slug="${r//\//__}"
    [ -d "$ROOT/eval/targets/$slug" ] || continue
    cp -a --reflink=auto "$ROOT/eval/targets/$slug" "$2/$slug" 2>/dev/null || continue
    printf -- "--bind %s %s " "$2/$slug" "$ROOT/eval/targets/$slug"
  done
}

run_sbx() {   # $1 = extra bwrap args (string), rest = run_viper args
  local extra="$1"; shift
  bwrap --die-with-parent --ro-bind / / --dev /dev --tmpfs /dev/shm --proc /proc --tmpfs /tmp $M \
    --bind "$ROOT/eval/viper_runs" "$ROOT/eval/viper_runs" \
    --bind "$IDX" "$IDX" $HOMEBIND $extra \
    -- "$ROOT/.venv/bin/python" eval/run_viper.py --codeql "$CODEQL" "$@"
}

# LLM record/replay cache (eval/llm_cache_proxy.py). Viper calls gpt-4.1 live with no
# cache of its own; routing OPENAI_BASE_URL through the proxy makes repeat runs free and
# exact (identical requests replay byte-for-byte) and logs real token usage per call.
# VIPER_LLM_CACHE: rw (default) | ro (replay only, misses refused -> zero spend) | off.
CACHE_MODE="${VIPER_LLM_CACHE:-rw}"
if [ "$CACHE_MODE" != off ]; then
  CDIR="$ROOT/eval/state/viper_llm_cache"; mkdir -p "$CDIR"
  UPSTREAM="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
  PPORT=$("$ROOT/.venv/bin/python" -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1])")
  "$ROOT/.venv/bin/python" "$ROOT/eval/llm_cache_proxy.py" --port "$PPORT" --cache-dir "$CDIR" \
      --upstream "$UPSTREAM" --mode "$CACHE_MODE" > "$CDIR/_proxy.log" 2>&1 &
  PROXY_PID=$!
  trap 'kill $PROXY_PID 2>/dev/null' EXIT
  for _ in $(seq 50); do "$ROOT/.venv/bin/python" -c "import socket;socket.create_connection(('127.0.0.1',$PPORT),1)" 2>/dev/null && break; sleep 0.2; done
  export OPENAI_BASE_URL="http://127.0.0.1:$PPORT/v1"
  export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"
  LSTART=$(wc -l < "$CDIR/_ledger.jsonl" 2>/dev/null || echo 0)
  echo "llm cache: mode=$CACHE_MODE proxy=127.0.0.1:$PPORT -> $UPSTREAM  ($(find "$CDIR" -name '*.json' | wc -l) cached responses)"
fi
cache_report() {
  [ "$CACHE_MODE" = off ] && return
  "$ROOT/.venv/bin/python" - "$CDIR/_ledger.jsonl" "$LSTART" <<'PYR'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]).readlines()[int(sys.argv[2]):] if l.strip()]
hit = sum(r.get("hit") for r in rows); miss = len(rows) - hit
pt = sum(r.get("prompt_tokens") or 0 for r in rows); ct = sum(r.get("completion_tokens") or 0 for r in rows)
print(f"llm cache this run: {len(rows)} calls, {hit} replayed, {miss} upstream; upstream tokens in={pt} out={ct}")
PYR
}

# Parallelism. run_viper.py is serial and Viper calls codeql without --threads (1
# thread), so by default this uses ~1 core. VIPER_PARALLEL=N runs N sandboxed shards
# over the --only list concurrently; CODEQL_THREADS (honored by the codeql CLI) splits
# VIPER_THREADS (default 12) across them. Each shard logs to eval/viper_runs/.shard<k>.log.
PAR="${VIPER_PARALLEL:-1}"; TOT="${VIPER_THREADS:-12}"
ONLY=""; RFILE=""; REST=()
while [ $# -gt 0 ]; do
  case "$1" in --only) ONLY="$2"; shift 2 ;; --only=*) ONLY="${1#--only=}"; shift ;;
    --repos-file) RFILE="$2"; shift 2 ;; --repos-file=*) RFILE="${1#--repos-file=}"; shift ;;
    *) REST+=("$1"); shift ;; esac
done
echo "viper(sbx): codeql=$($CODEQL version 2>/dev/null | head -1) home=$VH parallel=$PAR threads=$TOT tag=${TAG:-<none>} index=${IDX#$ROOT/}"
WORKROOT="$ROOT/.viper_work${TAG:+.$TAG}"

# ---- campaign mode: --repos-file (exact names, resumable, one sandbox + one target copy per repo)
if [ -n "$RFILE" ]; then
  [ -n "$TAG" ] || { echo "--repos-file needs VIPER_TAG (keeps campaign outputs separate)"; exit 1; }
  [ -f "$RFILE" ] || { echo "no such repos file: $RFILE"; exit 1; }
  OUTD="$ROOT/eval/viper_runs/$TAG"; STOPF="$OUTD/STOP"; rm -f "$STOPF"
  TODO="$OUTD/.todo"
  "$ROOT/.venv/bin/python" - "$RFILE" "$IDX" "$ROOT/eval/state/prepared.jsonl" > "$TODO" <<'PYT'
import json, sys
want = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
done = set()
for l in open(sys.argv[2]):
    try:
        r = json.loads(l)
        if r.get("ok") and not r.get("test_agent"): done.add(r["repo"])
    except Exception: pass
ready = set()
for l in open(sys.argv[3]):
    try:
        t = json.loads(l)
        if t.get("status") == "ready": ready.add(t["repo"])
    except Exception: pass
miss = [r for r in want if r not in ready]
if miss: print(f"WARNING {len(miss)} not prepared here (skipped): {miss[:8]}", file=sys.stderr)
for r in want:
    if r in ready and r not in done: print(r)
print(f"campaign: listed {len(want)}  ok-done {len(done & set(want))}  todo "
      f"{sum(1 for r in want if r in ready and r not in done)}", file=sys.stderr)
PYT
  mapfile -t REPOS < "$TODO"
  [ "${#REPOS[@]}" -eq 0 ] && { echo "nothing to do (all listed repos have an ok row in ${IDX#$ROOT/})"; cache_report; exit 0; }
  export CODEQL_THREADS=$(( TOT / PAR > 0 ? TOT / PAR : 1 ))
  shard() {   # $1 = shard index; runs its repos one at a time, each in its own sandbox
    local k=$1 i r
    for ((i=k; i<${#REPOS[@]}; i+=PAR)); do
      [ -f "$STOPF" ] && { echo "STOP file seen -- shard $k stopping"; break; }
      r="${REPOS[$i]}"
      EX=$(work_binds "$r" "$WORKROOT/s$k")
      run_sbx "$EX" --only "$r" --exact "${REST[@]}"
      rm -rf "$WORKROOT/s$k"
    done
  }
  pids=()
  on_int() {
    trap - INT TERM
    echo; echo "viper(sbx): interrupted -- stopping shards (finished repos are kept; re-run the same command to resume)"
    for p in "${pids[@]}"; do pkill -TERM -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
    wait 2>/dev/null; rm -rf "$WORKROOT"; cache_report; exit 130
  }
  trap on_int INT TERM
  echo "  ${#REPOS[@]} repos over $PAR shard(s), CODEQL_THREADS=$CODEQL_THREADS; logs eval/viper_runs/$TAG/.shard<k>.log"
  for ((k=0; k<PAR && k<${#REPOS[@]}; k++)); do
    shard "$k" > "$OUTD/.shard$k.log" 2>&1 &
    pids+=($!)
  done
  rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
  trap - INT TERM
  rm -rf "$WORKROOT"
  "$ROOT/.venv/bin/python" - "$IDX" "$RFILE" <<'PYS'
import json, sys, collections
want = {l.strip() for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")}
last = {}
for l in open(sys.argv[1]):
    try: r = json.loads(l); last[r["repo"]] = r
    except Exception: pass
rows = [r for k, r in last.items() if k in want]
ok = [r for r in rows if r.get("ok")]
print(f"viper campaign: {len(rows)}/{len(want)} repos have a row, {len(ok)} ok, "
      f"{sum(1 for r in rows if not r.get('ok'))} failed")
print(f"  static>0 {sum(1 for r in ok if (r.get('n_static') or 0) > 0)}  "
      f"sink>0 {sum(1 for r in ok if (r.get('n_sink_events') or 0) > 0)}  "
      f"confirmed>0 {sum(1 for r in ok if (r.get('n_confirmed_distinct') or 0) > 0)}  "
      f"hook not injected {sum(1 for r in ok if not r.get('hook_injected'))}")
PYS
  echo "viper(sbx): campaign pass done rc=$rc -- re-run the same command to retry failed/unfinished repos"
  cache_report; exit $rc
fi
if [ "$PAR" -le 1 ] || [ -z "$ONLY" ]; then
  export CODEQL_THREADS="${CODEQL_THREADS:-$TOT}"
  if [ -n "$ONLY" ]; then
    EX=$(work_binds "$ONLY" "$WORKROOT/s0")
    run_sbx "$EX" --only "$ONLY" "${REST[@]}"; rc=$?
  else
    echo "  (no --only: targets stay read-only; python targets cannot be instrumented)"
    run_sbx "" "${REST[@]}"; rc=$?
  fi
  rm -rf "$WORKROOT"; cache_report; exit $rc
fi
export CODEQL_THREADS=$(( TOT / PAR > 0 ? TOT / PAR : 1 ))
IFS=, read -r -a REPOS <<< "$ONLY"
pids=()
for ((k=0; k<PAR; k++)); do
  part=""; for ((i=k; i<${#REPOS[@]}; i+=PAR)); do part="${part:+$part,}${REPOS[$i]}"; done
  [ -z "$part" ] && continue
  echo "  shard $k: $part  (CODEQL_THREADS=$CODEQL_THREADS)"
  EX=$(work_binds "$part" "$WORKROOT/s$k")
  run_sbx "$EX" --only "$part" "${REST[@]}" > "$ROOT/eval/viper_runs/.shard$k.log" 2>&1 &
  pids+=($!)
done
rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
rm -rf "$WORKROOT"
echo "viper(sbx): all shards done rc=$rc  (logs: eval/viper_runs/.shard*.log)"
cache_report
exit $rc
