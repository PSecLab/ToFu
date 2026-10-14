#!/usr/bin/env bash
# Spawn the "Set E, recalculated" corpus fuzz: every repo that actually cloned +
# installed + exposed tools (status=ready in prepared.jsonl), tier-1 (bug-bearing
# sink) repos first. Resumable and Ctrl-C-safe -- done configs are skipped, so
# re-running continues where it stopped.
#
#   RUN IT IN tmux, NOT through a tool:
#     tmux new -s e2
#     ./eval/run_set_e2.sh
#     # detach: Ctrl-b d      reattach: tmux attach -t e2
#
#   ./eval/run_set_e2.sh --status         # progress only, runs nothing
#   ./eval/run_set_e2.sh --limit 3        # smoke: 3 configs then stop
#
# .env is sourced (for OPENAI_API_KEY + TOFU_JS_COV_SLOTS=1024) then hidden for
# the run by run_arm_gpt41.sh and restored on ANY exit. Do not remove that.
set -u
cd "$(dirname "$0")/.." || exit 1

# Corpus knobs (override by exporting before the call). These are the settings
# that make a whole-corpus sweep finish: a tight kill grace so a dead config
# does not sit at the budget, a start deadline so a hung handshake fails fast,
# an RSS cap, and fail-fast on tools that never succeed.
export ARM="${ARM:-gpt41-corpus}"
export TOFU_TIME="${TOFU_TIME:-60}"          # fuzz seconds per tool
export WORKERS="${WORKERS:-5}"               # = nproc on the VM
export TOFU_KILL_GRACE="${TOFU_KILL_GRACE:-60}"
export TOFU_STARTUP_TIMEOUT="${TOFU_STARTUP_TIMEOUT:-25}"
export TOFU_RSS_LIMIT_MB="${TOFU_RSS_LIMIT_MB:-4096}"
export TOFU_FAILFAST_EXECS="${TOFU_FAILFAST_EXECS:-500}"
# TOFU_JS_COV_SLOTS comes from .env (1024). Belt-and-suspenders in case .env was
# edited: never let it be the 10000 that made every node config ERR at 120s.
export TOFU_JS_COV_SLOTS="${TOFU_JS_COV_SLOTS:-1024}"

# Refresh the manifest + tier-1 list from the CURRENT ready pool, so a re-prep
# (more repos becoming ready) is picked up automatically.
python3 Benchmarks/extraction/build_set_e2.py || {
    echo "build_set_e2.py failed -- fix the manifest before spawning"; exit 1; }

PRIO="Benchmarks/extraction/set_e2_tier1_repos.txt"
UNSAFE="Benchmarks/extraction/set_e2_unsafe_repos.txt"
echo "== Set E (recalculated) corpus fuzz =="
echo "   arm=$ARM time=${TOFU_TIME}s workers=$WORKERS slots=$TOFU_JS_COV_SLOTS"
echo "   priority (tier-1 first): $PRIO"
echo "   skip (unsafe host-control targets): $UNSAFE"
echo

# Skip host-control targets (process spawn/kill, tmux, FS) that crash the harness
# without a sandbox -- they are recorded as findings, not fuzzed. Set
# TOFU_FUZZ_UNSAFE=1 to include them (only under a sandbox).
SKIP_ARG=""
[ -z "${TOFU_FUZZ_UNSAFE:-}" ] && [ -f "$UNSAFE" ] && SKIP_ARG="--skip-repos-file $UNSAFE"
exec ./eval/run_arm_gpt41.sh --priority-repos-file "$PRIO" $SKIP_ARG "$@"
