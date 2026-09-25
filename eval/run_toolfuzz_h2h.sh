#!/usr/bin/env bash
# ToolFuzz baseline over the head-to-head set (45 repos), budget-capped and resumable.
#
#   ./eval/run_toolfuzz_h2h.sh              # launch / resume (run inside tmux, natively)
#   python3 eval/toolfuzz_llm_guard.py status   # live LLM spend
#   tail -f eval/logs/toolfuzz_h2h_shard*.log
#
# Resumable: re-run the same command; finished (repo, tool) rows are skipped and
# every LLM response is cached, so a redone tool costs ~0 calls.
# Ctrl-C safe: all shards stop; the in-flight tools are redone on resume.
# Hard stop: when TOOLFUZZ_MAX_CALLS real API calls have been made, every shard
# exits (code 3). Raise the cap and re-run to continue.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

: "${SHARDS:=4}"
: "${NICE:=0}"          # e.g. NICE=10 on a host shared with a ToFu campaign
export TOOLFUZZ_SANDBOX="${TOOLFUZZ_SANDBOX:-bwrap}"
: "${REPOS_FILE:=Benchmarks/extraction/head2head_cisco.txt}"
: "${SKIP_FILE:=Benchmarks/extraction/set_e2_unsafe_repos.txt}"
export TOOLFUZZ_MODEL="${TOOLFUZZ_MODEL:-gpt-4.1}"
export TOOLFUZZ_MAX_CALLS="${TOOLFUZZ_MAX_CALLS:-10000}"
export TOOLFUZZ_MAX_CALLS_PER_TOOL="${TOOLFUZZ_MAX_CALLS_PER_TOOL:-40}"
export TOOLFUZZ_ITERS="${TOOLFUZZ_ITERS:-10}"
export TOOLFUZZ_RT_MAX_EXAMPLES="${TOOLFUZZ_RT_MAX_EXAMPLES:-3}"
export TOOLFUZZ_RT_MAX_PROMPTS="${TOOLFUZZ_RT_MAX_PROMPTS:-1}"
export TOOLFUZZ_CT_SETS="${TOOLFUZZ_CT_SETS:-1}"
export TOOLFUZZ_CT_MAX_PROMPTS="${TOOLFUZZ_CT_MAX_PROMPTS:-3}"
export TOOLFUZZ_TOOL_TIMEOUT="${TOOLFUZZ_TOOL_TIMEOUT:-600}"
export TOOLFUZZ_SEED="${TOOLFUZZ_SEED:-20260923}"
EXTRA_ARGS=("$@")

TFPY="$ROOT/Benchmarks/ToolFuzz/.venv/bin/python"
[ -x "$TFPY" ] || { echo "missing ToolFuzz venv: run eval/vm_bootstrap_toolfuzz.sh"; exit 1; }
for f in "$REPOS_FILE" "${TOOLFUZZ_PREPARED:-eval/state/prepared.jsonl}" \
         "${TOOLFUZZ_TOFU_INDEX:-eval/state/runs.gpt41-corpus.jsonl}"; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
done

# secrets: load. .env is NOT moved (a campaign sharing this checkout may re-read
# it); the bwrap sandbox masks it with /dev/null inside every target instead.
ENVF="${TOOLFUZZ_ENV_FILE:-.env}"
if [ -f "$ENVF" ]; then set -a; . "$ENVF"; set +a; fi
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set ($ENVF)"; exit 1; }
HIDDEN=""

PIDS=()
cleanup() {
  trap - INT TERM EXIT
  for p in "${PIDS[@]}"; do kill -INT "$p" 2>/dev/null; done
  sleep 2
  for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
  [ -n "$HIDDEN" ] && [ -f "$HIDDEN" ] && mv "$HIDDEN" .env
  echo; python3 eval/toolfuzz_llm_guard.py status
}
trap cleanup INT TERM EXIT

# Protect any co-located campaign: every ToolFuzz process (and each target server
# it spawns, by inheritance) is the kernel OOM killer's FIRST choice, runs at NICE
# CPU priority and idle-class disk I/O.
echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true
IONICE=(); command -v ionice >/dev/null && IONICE=(ionice -c3)

mkdir -p eval/logs
echo "ToolFuzz H2H: sandbox=$TOOLFUZZ_SANDBOX nice=$NICE shards=$SHARDS model=$TOOLFUZZ_MODEL cap=$TOOLFUZZ_MAX_CALLS calls (per tool $TOOLFUZZ_MAX_CALLS_PER_TOOL)"
for ((k=0; k<SHARDS; k++)); do
  nice -n "$NICE" "${IONICE[@]}" "$TFPY" eval/run_toolfuzz.py --shard "$k/$SHARDS" --repos-file "$REPOS_FILE" \
      --skip-repos-file "$SKIP_FILE" --executable-only "${EXTRA_ARGS[@]}" \
      >> "eval/logs/toolfuzz_h2h_shard$k.log" 2>&1 &
  PIDS+=($!)
  echo "  shard $k -> pid $! (eval/logs/toolfuzz_h2h_shard$k.log)"
done

rc=0
for p in "${PIDS[@]}"; do wait "$p" || rc=$?; done
[ "$rc" = 3 ] && echo "LLM budget cap reached ($TOOLFUZZ_MAX_CALLS). Raise TOOLFUZZ_MAX_CALLS and re-run to resume."
"$TFPY" eval/score_toolfuzz.py --repos-file "$REPOS_FILE" \
    --write "findings/baselines/toolfuzz_h2h_scored_$(date +%Y%m%d).md" > /dev/null \
  && echo "scored -> findings/baselines/toolfuzz_h2h_scored_$(date +%Y%m%d).md"
exit $rc
