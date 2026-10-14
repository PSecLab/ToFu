#!/usr/bin/env bash
# Stock-CodeQL security-extended baseline over set_e2 (the same executable pool
# ToFu fuzzes), so ToFu's runtime findings can be compared against what static
# SAST flags on the identical repos. STATIC ONLY (--build-mode=none): CodeQL
# reads source, never runs a tool. Resumable (done repos skipped).
#
#   RUN IT IN tmux (own window, alongside the ToFu run):
#     tmux new -s cql
#     ./eval/run_codeql_e2.sh
#     # detach Ctrl-b d ; reattach tmux attach -t cql
#
#   ./eval/run_codeql_e2.sh --summary     # print the findings table
#   ./eval/run_codeql_e2.sh --limit 3     # smoke
#
# CPU: THREADS=2 by default so it shares the 5-core box with the ToFu fuzz
# (5 workers). Raise CODEQL_THREADS only if the ToFu run is paused.
set -u
cd "$(dirname "$0")/.." || exit 1
export CODEQL="${CODEQL:-$HOME/codeql/codeql}"
export CODEQL_THREADS="${CODEQL_THREADS:-2}"
export CODEQL_RAM="${CODEQL_RAM:-4096}"
[ -x "$CODEQL" ] || { echo "codeql not found at $CODEQL -- set CODEQL=/path/to/codeql"; exit 1; }

# Ensure the manifest matches the current ready pool (same set ToFu runs).
python3 Benchmarks/extraction/build_set_e2.py >/dev/null || {
    echo "build_set_e2.py failed"; exit 1; }

echo "== CodeQL security-extended over set_e2 =="
echo "   codeql=$CODEQL threads=$CODEQL_THREADS ram=$CODEQL_RAM"
echo "   index -> eval/state/codeql_runs_e2.jsonl   sarif -> eval/codeql_baseline_e2/"
echo
exec python3 eval/run_codeql_set.py e2 "$@"
