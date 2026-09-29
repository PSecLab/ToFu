#!/usr/bin/env bash
# Cisco MCP Scanner baseline (yara + llm + behavioral) under the bubblewrap sandbox.
# The scanner LAUNCHES each target over stdio to list its tools, so the target runs:
# it gets the same containment as ToFu / Viper (CLAUDE.md): / read-only, private /tmp
# and HOME, secrets masked, .env blanked (the key is passed via env), and each repo a
# throwaway COPY of its target bound over the real path. Only this campaign's index and
# output dir are writable. Run natively in tmux (CLAUDE.md rule 4).
#
#   CISCO_TAG=c273 CISCO_PARALLEL=4 ./eval/run_cisco_sbx.sh \
#       --repos-file Benchmarks/extraction/h2h_273_repos.txt
#   RESUMABLE (re-run the same command: repos with an ok row are skipped); Ctrl-C safe;
#   `touch eval/cisco_runs/<tag>/STOP` = finish the current repos, then stop.
#
# Env: CISCO_LLM_MODEL (default openai/gpt-4.1-mini), CISCO_ANALYZERS (default
# yara,llm,behavioral), CISCO_TIMEOUT (per-server s, default 1800), CISCO_LLM_CACHE
# rw|ro|off (default rw; record/replay proxy eval/llm_cache_proxy.py).
set -u
cd "$(dirname "$0")/.." || exit 1
ROOT=$PWD
REAL_HOME=$HOME
[ -s "$REAL_HOME/.nvm/nvm.sh" ] && { source "$REAL_HOME/.nvm/nvm.sh" >/dev/null 2>&1; nvm use 22 >/dev/null 2>&1; }
ENVF=.env; [ -f "$ENVF" ] || ENVF=.env.campaign-hidden
[ -f "$ENVF" ] && { set -a; . "./$ENVF"; set +a; }
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set (.env)"; exit 1; }
command -v bwrap >/dev/null || { echo "bubblewrap missing"; exit 1; }
bwrap --ro-bind / / --tmpfs /tmp -- /bin/true 2>/dev/null || { echo "bwrap cannot start (userns?)"; exit 1; }
[ -x "$ROOT/Benchmarks/Cisco-MCP-Scanner/.venv/bin/mcp-scanner" ] || { echo "scanner venv missing (run_cisco_scanner.py --setup)"; exit 1; }

TAG="${CISCO_TAG:-}"; [ -n "$TAG" ] || { echo "set CISCO_TAG (keeps this campaign's outputs separate)"; exit 1; }
export CISCO_TAG="$TAG"
export CISCO_LLM_MODEL="${CISCO_LLM_MODEL:-openai/gpt-4.1-mini}"
export CISCO_LLM_TIMEOUT="${CISCO_LLM_TIMEOUT:-120}"
ANALYZERS="${CISCO_ANALYZERS:-yara,llm,behavioral}"
TIMEOUT="${CISCO_TIMEOUT:-1800}"
PAR="${CISCO_PARALLEL:-1}"
IDX="$ROOT/eval/state/cisco_runs.$TAG.jsonl"; OUTD="$ROOT/eval/cisco_runs/$TAG"
mkdir -p "$OUTD"; touch "$IDX"

M=""
for d in .ssh .aws .gnupg .kube .docker .config/gcloud .config/gh; do [ -d "$REAL_HOME/$d" ] && M="$M --tmpfs $REAL_HOME/$d"; done
for f in "$ROOT"/.env*; do [ -f "$f" ] && M="$M --ro-bind /dev/null $f"; done

work_bind() {   # $1 = repo, $2 = work dir -> prints bwrap bind args for a throwaway target copy
  local slug="${1//\//__}"
  mkdir -p "$2"
  [ -d "$ROOT/eval/targets/$slug" ] || return 0
  cp -a --reflink=auto "$ROOT/eval/targets/$slug" "$2/$slug" 2>/dev/null || return 0
  printf -- "--bind %s %s " "$2/$slug" "$ROOT/eval/targets/$slug"
}
run_sbx() {   # $1 = extra bwrap args, rest = run_cisco_scanner args
  local extra="$1"; shift
  bwrap --die-with-parent --ro-bind / / --dev /dev --tmpfs /dev/shm --proc /proc --tmpfs /tmp $M \
    --dir /tmp/chome --setenv HOME /tmp/chome \
    --bind "$OUTD" "$OUTD" --bind "$IDX" "$IDX" $extra \
    -- "$ROOT/.venv/bin/python" eval/run_cisco_scanner.py "$@"
}

# LLM record/replay cache (same proxy as Viper): repeat runs are free and the ledger
# records the real token spend per call. LiteLLM honours MCP_SCANNER_LLM_BASE_URL.
CACHE_MODE="${CISCO_LLM_CACHE:-rw}"
CDIR="$ROOT/eval/state/cisco_llm_cache"
if [ "$CACHE_MODE" != off ]; then
  mkdir -p "$CDIR"; touch "$CDIR/_ledger.jsonl"
  PPORT=$("$ROOT/.venv/bin/python" -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1])")
  "$ROOT/.venv/bin/python" "$ROOT/eval/llm_cache_proxy.py" --port "$PPORT" --cache-dir "$CDIR" \
      --upstream "https://api.openai.com/v1" --mode "$CACHE_MODE" > "$CDIR/_proxy.log" 2>&1 &
  PROXY_PID=$!
  trap 'kill $PROXY_PID 2>/dev/null' EXIT
  for _ in $(seq 50); do "$ROOT/.venv/bin/python" -c "import socket;socket.create_connection(('127.0.0.1',$PPORT),1)" 2>/dev/null && break; sleep 0.2; done
  export CISCO_LLM_BASE_URL="http://127.0.0.1:$PPORT/v1"
  export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"
  LSTART=$(wc -l < "$CDIR/_ledger.jsonl")
  echo "llm cache: mode=$CACHE_MODE proxy=127.0.0.1:$PPORT  ($(find "$CDIR" -name '*.json' | wc -l) cached responses)"
else
  export CISCO_LLM_BASE_URL="https://api.openai.com/v1"
fi
export MCP_SCANNER_LLM_API_KEY="$OPENAI_API_KEY"
cache_report() {
  [ "$CACHE_MODE" = off ] && return
  "$ROOT/.venv/bin/python" - "$CDIR/_ledger.jsonl" "$LSTART" <<'PYR'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]).readlines()[int(sys.argv[2]):] if l.strip()]
hit = sum(1 for r in rows if r.get("hit")); miss = len(rows) - hit
pt = sum(r.get("prompt_tokens") or 0 for r in rows); ct = sum(r.get("completion_tokens") or 0 for r in rows)
print(f"llm cache this run: {len(rows)} calls, {hit} replayed, {miss} upstream; upstream tokens in={pt} out={ct}")
PYR
}

RFILE=""; REST=()
while [ $# -gt 0 ]; do
  case "$1" in --repos-file) RFILE="$2"; shift 2 ;; --repos-file=*) RFILE="${1#--repos-file=}"; shift ;;
    *) REST+=("$1"); shift ;; esac
done
[ -n "$RFILE" ] && [ -f "$RFILE" ] || { echo "need --repos-file <list>"; exit 1; }
echo "cisco(sbx): tag=$TAG analyzers=$ANALYZERS model=$CISCO_LLM_MODEL parallel=$PAR timeout=${TIMEOUT}s index=${IDX#$ROOT/}"

STOPF="$OUTD/STOP"; rm -f "$STOPF"; TODO="$OUTD/.todo"
"$ROOT/.venv/bin/python" - "$RFILE" "$IDX" "$ROOT/eval/state/prepared.jsonl" > "$TODO" <<'PYT'
import json, sys
want = [l.strip() for l in open(sys.argv[1]) if l.strip() and not l.startswith("#")]
done, ready = set(), set()
for l in open(sys.argv[2]):
    try:
        r = json.loads(l)
        if r.get("ok"): done.add(r["repo"])
    except Exception: pass
for l in open(sys.argv[3]):
    try:
        t = json.loads(l)
        if t.get("status") == "ready": ready.add(t["repo"])
    except Exception: pass
miss = [r for r in want if r not in ready]
if miss: print(f"WARNING {len(miss)} not prepared here (skipped): {miss[:8]}", file=sys.stderr)
todo = [r for r in want if r in ready and r not in done]
for r in todo: print(r)
print(f"campaign: listed {len(want)}  ok-done {len(done & set(want))}  todo {len(todo)}", file=sys.stderr)
PYT
mapfile -t REPOS < "$TODO"
[ "${#REPOS[@]}" -eq 0 ] && { echo "nothing to do"; cache_report; exit 0; }
WORKROOT="$ROOT/.cisco_work.$TAG"
shard() {
  local k=$1 i r
  for ((i=k; i<${#REPOS[@]}; i+=PAR)); do
    [ -f "$STOPF" ] && { echo "STOP file seen -- shard $k stopping"; break; }
    r="${REPOS[$i]}"
    EX=$(work_bind "$r" "$WORKROOT/s$k")
    run_sbx "$EX" --only-repo "$r" --exact --analyzers "$ANALYZERS" --behavioral \
      --workers 1 --timeout "$TIMEOUT" --no-summary "${REST[@]}"
    rm -rf "$WORKROOT/s$k"
  done
}
pids=()
on_int() {
  trap - INT TERM HUP
  echo; echo "cisco(sbx): interrupted -- finished repos are kept; re-run the same command to resume"
  for p in "${pids[@]}"; do pkill -TERM -P "$p" 2>/dev/null; kill "$p" 2>/dev/null; done
  wait 2>/dev/null; rm -rf "$WORKROOT"; cache_report; exit 130
}
trap on_int INT TERM HUP
echo "  ${#REPOS[@]} repos over $PAR shard(s); logs eval/cisco_runs/$TAG/.shard<k>.log"
for ((k=0; k<PAR && k<${#REPOS[@]}; k++)); do
  shard "$k" > "$OUTD/.shard$k.log" 2>&1 &
  pids+=($!)
done
rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
trap - INT TERM HUP
rm -rf "$WORKROOT"
"$ROOT/.venv/bin/python" - "$IDX" "$RFILE" <<'PYS'
import json, sys, collections
want = {l.strip() for l in open(sys.argv[2]) if l.strip() and not l.startswith("#")}
last = {}
for l in open(sys.argv[1]):
    try: r = json.loads(l); last[r["repo"]] = r
    except Exception: pass
rows = [r for k, r in last.items() if k in want]; ok = [r for r in rows if r.get("ok")]
by = collections.Counter()
for r in ok:
    for a, n in (r.get("findings_by_analyzer") or {}).items():
        if n: by[a] += 1
print(f"cisco campaign: {len(rows)}/{len(want)} repos have a row, {len(ok)} ok, {len(rows) - len(ok)} failed; "
      f"flagged {sum(1 for r in ok if r.get('n_tools_flagged'))}; repos flagged per analyzer {dict(by)}")
PYS
echo "cisco(sbx): pass done rc=$rc -- re-run the same command to retry failed/unfinished repos"
cache_report; exit $rc
