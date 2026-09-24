#!/usr/bin/env bash
# Per-repo deep fuzzing: 24 worker-hours per repo, saturation-based early stop
# (every reachable tool 1 h with no new edge and no new finding signature).
# Protocol + accounting: eval/run_repo24.py docstring. Run natively inside tmux,
# never through an agent tool call (CLAUDE.md rule 4).
#
#   ./eval/run_repo24.sh --select 10     # 1) pick the top-10 repos -> eval/repo24_repos.txt
#   ARM=repo24-smoke TOFU_PLATEAU=120 TOFU_TIME=180 TOFU_BUDGET_H=0.25 ./eval/run_repo24.sh --limit 1
#                                        # 2) smoke: ~15 min, several slices, separate arm
#   ./eval/run_repo24.sh                 # 3) campaign
#   ./eval/run_repo24.sh --status        #    progress only
#
# RESUME: re-run the same command (ledger: eval/state/repo24_state.<arm>.json).
# CTRL-C: kills every in-flight fuzzer; the interrupted slice re-runs on resume.
# .env is sourced, hidden for the run and restored on ANY exit by run_arm_gpt41.sh.
set -u
cd "$(dirname "$0")/.." || exit 1

export ARM="${ARM:-repo24}"
export WORKERS="${WORKERS:-5}"                       # repos in parallel
PLATEAU="${TOFU_PLATEAU:-3600}"
BUDGET_H="${TOFU_BUDGET_H:-24}"
export TOFU_TIME="${TOFU_TIME:-$((PLATEAU + 600))}"   # slice length
export TOFU_KEEP_CORPUS=1                            # resume each tool across slices
export TOFU_REQUIRE_LLM_SEEDS="${TOFU_REQUIRE_LLM_SEEDS:-1}"  # LLM seeds only: cached iff tagged
                                                     # llm, else live; live failure aborts the tool
export TOFU_FINDINGS_TIMELINE=1
export TOFU_KILL_GRACE="${TOFU_KILL_GRACE:-300}"
export TOFU_STARTUP_TIMEOUT="${TOFU_STARTUP_TIMEOUT:-25}"
export TOFU_RSS_LIMIT_MB="${TOFU_RSS_LIMIT_MB:-6144}"
export TOFU_FAILFAST_EXECS="${TOFU_FAILFAST_EXECS:-500}"
export TOFU_JS_COV_SLOTS="${TOFU_JS_COV_SLOTS:-1024}"
export TOFU_ENTRY=eval/run_repo24.py

echo "== repo24: ${BUDGET_H} worker-h/repo, slice ${TOFU_TIME}s, plateau ${PLATEAU}s, ${WORKERS} repos in parallel =="
exec ./eval/run_arm_gpt41.sh --budget-h "$BUDGET_H" --plateau-s "$PLATEAU" "$@"
