#!/usr/bin/env bash
# 24h deep-fuzz campaign (RQ4): a long per-config budget on the reachable,
# still-climbing tools chosen by eval/select_deep24.py, with the findings-over-
# time timeline switched on. Run it natively in a terminal (inside tmux), never
# through an agent tool call (CLAUDE.md rule 4).
#
#   python3 eval/select_deep24.py        # 1) pick targets -> eval/deep24_configs.txt
#   ./eval/run_deep24.sh --limit 1       # 2) smoke: one config end-to-end, then stop
#   ./eval/run_deep24.sh                 # 3) full campaign
#   ./eval/run_deep24.sh --status        #    progress only, runs nothing
#
# RESUME: re-run the same command. run_eval skips every config already recorded
# in eval/state/runs.deep24.jsonl (ok or err).
# CTRL-C: run_eval kills every in-flight fuzzer's process group and exits at once;
# those configs are not in the index, so they re-run from the start on resume.
# .env is sourced then hidden for the run and restored on ANY exit by
# run_arm_gpt41.sh -- do not remove that.
#
# Knobs (export before the call to override):
#   TOFU_TIME=5400   seconds per config   WORKERS=5 (= nproc on the VM)
# The selector's cap assumes the same TOFU_TIME/WORKERS; if you change them,
# re-run select_deep24.py with --time/--workers to match.
set -u
cd "$(dirname "$0")/.." || exit 1

export ARM="${ARM:-deep24}"                       # separate index/logs/metrics
export TOFU_TIME="${TOFU_TIME:-5400}"             # 1.5 h per config
export WORKERS="${WORKERS:-5}"
export TOFU_FINDINGS_TIMELINE=1                   # findings_timeline_*.csv (only this run)
export TOFU_KILL_GRACE="${TOFU_KILL_GRACE:-300}"  # hard kill at budget + 5 min
export TOFU_STARTUP_TIMEOUT="${TOFU_STARTUP_TIMEOUT:-25}"
export TOFU_RSS_LIMIT_MB="${TOFU_RSS_LIMIT_MB:-6144}"   # 38 GB / 5 workers, with headroom
export TOFU_FAILFAST_EXECS="${TOFU_FAILFAST_EXECS:-500}"
# never the 10000 that made every node config ERR (HANDOFF / 2026-09-17 quarantine)
export TOFU_JS_COV_SLOTS="${TOFU_JS_COV_SLOTS:-1024}"

CFGS="eval/deep24_configs.txt"
UNSAFE="Benchmarks/extraction/set_e2_unsafe_repos.txt"
[ -s "$CFGS" ] || { echo "no $CFGS -- run: python3 eval/select_deep24.py"; exit 1; }

N=0; CACHED=0
while IFS= read -r c; do
    case "$c" in \#*|"") continue ;; esac
    N=$((N + 1))
    [ -f "eval/state/llm_cache/$c.json" ] && CACHED=$((CACHED + 1))
done < "$CFGS"

echo "== 24h deep fuzz =="
echo "   arm=$ARM  time=${TOFU_TIME}s/config  workers=$WORKERS  configs=$N"
echo "   LLM replay cache hits expected: $CACHED/$N  (misses make fresh LLM calls)"
echo "   est. wall: ~$(( N * (TOFU_TIME + 120) / WORKERS / 3600 )) h"
echo "   index   -> eval/state/runs.$ARM.jsonl"
echo "   metrics -> eval/metrics_$ARM/<config>/{coverage,findings}_timeline_*.csv"
echo

SKIP_ARG=""
[ -f "$UNSAFE" ] && SKIP_ARG="--skip-repos-file $UNSAFE"
exec ./eval/run_arm_gpt41.sh --only-configs-file "$CFGS" $SKIP_ARG "$@"
