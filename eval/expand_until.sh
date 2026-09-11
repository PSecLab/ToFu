#!/usr/bin/env bash
# Prepare Set E in chunks until TARGET repos are prepared AND executable.
#
# Measured yield on Set A+B: 58 attempted -> 14 prepared -> ~6 executable.
# ~10% end to end, so reaching 30 usable repos means attempting a few hundred.
# Chunked so you can stop the moment the target is met instead of clone-and-
# installing all 300.
#
#   ./eval/expand_until.sh            # target 30, chunks of 40
#   TARGET=40 CHUNK=25 ./eval/expand_until.sh
#
# RESUMABLE and Ctrl-C safe: prepare_targets skips anything already in
# prepared.jsonl/skipped.jsonl, so re-running continues where it stopped.
set -u
cd "$(dirname "$0")/.." || exit 1
PY="$PWD/.venv/bin/python"
TARGET="${TARGET:-30}"
CHUNK="${CHUNK:-40}"
LOG="eval/state/expand_$(date +%Y%m%d_%H%M%S).log"

trap 'echo; echo "Interrupted. Resumable: ./eval/expand_until.sh"; exit 130' INT TERM

while :; do
  n_prepared=$("$PY" - <<'EOF'
import json
print(sum(1 for l in open('eval/state/prepared.jsonl') if l.strip()))
EOF
)
  echo "=== prepared so far: $n_prepared (target $TARGET) ==="
  if [ "$n_prepared" -ge "$TARGET" ]; then
    echo "TARGET MET. Prepared repos: $n_prepared"
    echo "Next: measure how many of them actually EXECUTE --"
    echo "  the campaign's EXEC_SUMMARY / 'tool executability' line is the authority."
    break
  fi
  echo "--- preparing next $CHUNK from Set E ---"
  "$PY" eval/prepare_targets.py --only-set e --limit "$CHUNK" || {
    echo "prepare_targets exited non-zero; stopping"; break; }
done 2>&1 | tee -a "$LOG"
echo "log: $LOG"
