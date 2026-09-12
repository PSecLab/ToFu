#!/usr/bin/env bash
# ToFu overnight campaign -- Set A + Set B on gemma4:12b, temperature 0.
#
# RESUMABLE and Ctrl-C SAFE at every phase. If you stop it, or it dies, or the
# Mac sleeps, just run it again: prepare_targets skips repos already in
# prepared.jsonl/skipped.jsonl, and run_eval skips configs already in
# runs.jsonl. Nothing is re-run and nothing is lost.
#
#   ./eval/run_overnight.sh            # full night: preflight -> prepare -> smoke -> campaign
#   ./eval/run_overnight.sh prepare    # just materialise the targets
#   ./eval/run_overnight.sh smoke      # just the 1-config validation run
#   ./eval/run_overnight.sh campaign   # just the sweep (assumes prepare is done)
#   ./eval/run_overnight.sh status     # progress + LLM-stage health, safe anytime
#
# Per-tool budget: TOFU_TIME (default 180s). Workers: TOFU_WORKERS (default 2).

set -u
cd "$(dirname "$0")/.." || exit 1
ROOT="$PWD"
PY="${TOFU_PY:-$ROOT/.venv/bin/python}"   # TOFU_PY overrides (sandbox: /opt/tofu-venv/bin/python)
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG="$ROOT/eval/state/overnight_${STAMP}.log"
mkdir -p "$ROOT/eval/state"

TOFU_TIME="${TOFU_TIME:-180}"
TOFU_WORKERS="${TOFU_WORKERS:-2}"

# .env is inert on its own (nothing calls load_dotenv, python-dotenv is not
# installed). Source it into the environment so the campaign actually uses it.
if [ -f "$ROOT/.env" ]; then set -a; . "$ROOT/.env"; set +a; fi
export TOFU_LLM_BASE_URL="${TOFU_LLM_BASE_URL:-http://localhost:11434/v1}"
export TOFU_LLM_MODEL="${TOFU_LLM_MODEL:-gemma4:12b}"
export TOFU_LLM_TEMPERATURE="${TOFU_LLM_TEMPERATURE:-0}"
export TOFU_LLM_SEED="${TOFU_LLM_SEED:-20260910}"
export TOFU_LLM_TIMEOUT="${TOFU_LLM_TIMEOUT:-300}"
export OLLAMA_CLOUD_API_KEY="${OLLAMA_CLOUD_API_KEY:-ollama}"
export OLLAMA_NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-1}"
export TOFU_JS_COV_SLOTS="${TOFU_JS_COV_SLOTS:-10000}"
export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"

say() { printf '\n\033[1m=== %s ===\033[0m %s\n' "$1" "$(date '+%H:%M:%S')"; }
die() { printf '\n\033[31mHALT: %s\033[0m\n' "$1"; exit 1; }

trap 'printf "\n\nInterrupted. Nothing lost -- everything is resumable.\n  resume:  ./eval/run_overnight.sh\n  status:  ./eval/run_overnight.sh status\n  log:     %s\n" "$LOG"; exit 130' INT TERM

# ---------------------------------------------------------------- preflight
preflight() {
  say "PREFLIGHT"
  [ -x "$PY" ] || die ".venv/bin/python missing. The system python3 is 3.10 and atheris needs 3.11 (dis.Positions)."
  "$PY" -c 'import sys; assert sys.version_info[:2]==(3,11), sys.version' \
    || die "venv is not Python 3.11"
  "$PY" -c 'import pyflakes' 2>/dev/null \
    || die "pyflakes missing -- run_eval's undefined-name preflight skips SILENTLY without it, and two campaigns have already been lost to NameErrors.  $PY -m pip install pyflakes"
  "$PY" -c 'import atheris, mcp, langchain_openai, pymongo' 2>/dev/null \
    || die "ToFu dependencies not importable in the venv"

  say "TEST SUITE"
  "$PY" -m pytest tests/ -q || die "tests failed -- do not run a campaign on a red tree"

  say "OLLAMA"
  curl -sf -m 5 "${TOFU_LLM_BASE_URL%/v1}/api/tags" >/dev/null \
    || die "Ollama not reachable at $TOFU_LLM_BASE_URL. Run 'ollama serve' in another Terminal tab."
  curl -sf -m 5 "${TOFU_LLM_BASE_URL%/v1}/api/tags" | grep -q "\"$TOFU_LLM_MODEL\"" \
    || die "model '$TOFU_LLM_MODEL' not present. Run: ollama pull $TOFU_LLM_MODEL"

  printf '  python      %s\n' "$("$PY" -V 2>&1)"
  printf '  model       %s @ %s\n' "$TOFU_LLM_MODEL" "$TOFU_LLM_BASE_URL"
  printf '  temperature %s   seed %s   OLLAMA_NUM_PARALLEL %s\n' \
         "$TOFU_LLM_TEMPERATURE" "$TOFU_LLM_SEED" "$OLLAMA_NUM_PARALLEL"
  printf '  budget      %ss per tool, %s workers\n' "$TOFU_TIME" "$TOFU_WORKERS"
  printf '  commit      %s%s\n' "$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)" \
         "$( [ -n "$(git -C "$ROOT" status --porcelain 2>/dev/null)" ] && echo ' (DIRTY -- uncommitted audit + seed-validation fix)')"
}

# ------------------------------------------------------------------ prepare
prepare() {
  say "PREPARE TARGETS (Set A 50 + Set B 8) -- resumable, ~2-3h"
  echo "Clone at pinned commit -> install deps -> detect entrypoint -> tools/list -> one config per tool."
  echo "A real failure rate is EXPECTED and is the paper's exclusion list. Do not hand-fix failures."
  "$PY" eval/prepare_targets.py
  printf '\nprepared: %s repos   skipped: %s repos   configs: %s\n' \
    "$(wc -l < eval/state/prepared.jsonl 2>/dev/null | tr -d ' ')" \
    "$(wc -l < eval/state/skipped.jsonl  2>/dev/null | tr -d ' ')" \
    "$(ls eval/configs/*.json 2>/dev/null | wc -l | tr -d ' ')"
}

# -------------------------------------------------------------------- smoke
# One short run whose only job is to answer the two questions that decide
# whether the night's numbers mean anything.
smoke() {
  say "SMOKE / VALIDATION RUN (1 config, 120s)"
  "$PY" eval/run_eval.py --time 120 --limit 1 --workers 1
  local newest
  newest="$(ls -t eval/runs/*.log 2>/dev/null | head -1)"
  [ -n "$newest" ] || { echo "no log produced"; return; }

  say "VERDICT  ($(basename "$newest"))"

  echo "-- did the tool ACTUALLY EXECUTE? (read this before anything else) --"
  grep -a -oE "EXEC_SUMMARY.*" "$newest" | tail -1
  grep -a -oE "EXEC_ERROR n=[0-9]+ detail=.{0,90}" "$newest" | head -2
  grep -a -q "NOT_EXECUTABLE" "$newest" && \
    echo "   *** NOT_EXECUTABLE: every execution errored. A '0 findings' here says" && \
    echo "   *** NOTHING about the target. Exclude it from any denominator."
  echo
  echo "-- LLM stage --"
  grep -oE 'LLM_SELECTION_(OK|FAILED)[^"]{0,90}'  "$newest" | head -3
  grep -oE 'LLM_SEEDGEN_(OK|REJECTED|FALLBACK)[^"]{0,90}' "$newest" | head -5
  echo "   LLM_SEEDGEN_REJECTED means gemma4 returned tool-call envelopes instead of"
  echo "   tool arguments; those are now dropped instead of being fuzzed as entropy."

  echo
  echo "-- seed corpus actually written (must have the TOOL's keys, not name/parameters) --"
  local cdir
  cdir="$(ls -td eval/corpora/*/ 2>/dev/null | head -1)"
  [ -n "$cdir" ] && head -c 220 "$cdir"seed_0.json 2>/dev/null && echo

  echo
  echo "-- JS coverage acceptance test (HANDOFF section 4) --"
  grep -oE 'cov: [0-9]+ ft: [0-9]+ corp: [0-9]+' "$newest" | awk '!s[$0]++'
  cat <<'EOT'
   (a) cov: must INCREASE down that list      (was pinned at one value)
   (b) corp: must grow past 2-4               (was stuck at 1-4)
   (c) exec/s must rise                       (was 0-33)
   All three identical = coverage guidance still dead. Scope coverage claims to
   Python targets, or check worker-thread coverage in coverage_wrapper.js first.
   A single line here is INCONCLUSIVE, not a failure: it means the run had one
   corpus entry and nothing to explore.
EOT
  echo
  echo "This verdict is also saved in $LOG. The campaign continues either way --"
  echo "a bad verdict does not corrupt the index, it tells you what to quarantine."
}

# ----------------------------------------------------------------- campaign
campaign() {
  local n; n="$(ls eval/configs/*.json 2>/dev/null | wc -l | tr -d ' ')"
  say "CAMPAIGN -- $n configs, ${TOFU_TIME}s each, $TOFU_WORKERS workers"
  echo "Rough wall clock: n * (budget + ~120s LLM/startup overhead) / workers"
  echo "                = $n * ($TOFU_TIME + 120) / $TOFU_WORKERS ~= $(( n * (TOFU_TIME + 120) / TOFU_WORKERS / 3600 ))h"
  echo "Whatever does not finish by morning is simply not in runs.jsonl yet."
  echo "Re-run this script to continue from exactly where it stopped."
  "$PY" eval/run_eval.py --time "$TOFU_TIME" --workers "$TOFU_WORKERS"
}

status() {
  say "STATUS"
  "$PY" eval/run_eval.py --status
}

main() {
  case "${1:-all}" in
    preflight) preflight ;;
    prepare)   preflight; prepare ;;
    smoke)     preflight; smoke ;;
    campaign)  preflight; campaign; status ;;
    status)    status ;;
    all)       preflight; prepare; smoke; campaign; status ;;
    *) echo "usage: $0 [all|preflight|prepare|smoke|campaign|status]"; exit 2 ;;
  esac
  say "DONE"
  echo "Full log: $LOG"
}

main "$@" 2>&1 | tee -a "$LOG"
