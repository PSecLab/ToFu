#!/usr/bin/env bash
# Two repeat Full ToFu runs over the ablation set (266 servers / 1,801 tools), for run-to-run
# variation. Same code, budget, sandbox, LLM replay cache and settings as the ablation's `full`
# arm; each repeat writes its own index (runs.abl-r2-full.jsonl, runs.abl-r3-full.jsonl), so
# runs.abl-full.jsonl is never touched. Runs the repeats ONE AFTER THE OTHER (never concurrently:
# shared CPU would skew throughput and coverage between runs).
#
#   RUN IN tmux, NOT through a tool (overnight, ~2.7 h per repeat):
#     tmux new -s repeats
#     source ./.tofu_env.sh
#     ./eval/run_full_repeats.sh
#   ./eval/run_full_repeats.sh --status     # progress only, runs nothing
#
# Resumable and Ctrl-C-safe: a finished repeat is skipped, a partial one resumes where it stopped.
# newtype-01/obsidian-mcp deletes its own target directory while being fuzzed (inside the sandbox),
# so it is re-prepared (sandboxed) before each repeat that still has work to do.
set -u
cd "$(dirname "$0")/.." || exit 1

REPEATS="${REPEATS:-r2 r3}"
CFG="${ABL_CONFIGS:-Benchmarks/extraction/ablation_266_configs.txt}"
NWANT=$(grep -vc '^\s*\(#\|$\)' "$CFG")
LOG="eval/state/full_repeats.log"

done_rows() {  # rows of this repeat's index that belong to the config list
    python3 - "$1" "$CFG" <<'EOF'
import json, os, sys
idx, cfg = sys.argv[1], sys.argv[2]
want = {os.path.splitext(l.strip())[0] for l in open(cfg) if l.strip() and not l.startswith("#")}
got = set()
if os.path.exists(idx):
    for l in open(idx):
        if l.strip():
            got.add(os.path.splitext(json.loads(l).get("config", ""))[0])
print(len(want & got))
EOF
}

status() {
    for r in $REPEATS; do
        echo "  abl-$r-full: $(done_rows eval/state/runs.abl-$r-full.jsonl)/$NWANT"
    done
}

if [ "${1:-}" = "--status" ]; then echo "== full repeats =="; status; exit 0; fi

trap 'echo; echo "interrupted -- re-run ./eval/run_full_repeats.sh to resume"; exit 130' INT TERM

{
echo "== Full ToFu repeats $(date '+%F %T') commit $(git rev-parse --short HEAD) =="
echo "   repeats: $REPEATS   configs: $NWANT ($CFG)"
status
for r in $REPEATS; do
    idx="eval/state/runs.abl-$r-full.jsonl"
    n=$(done_rows "$idx")
    if [ "$n" -ge "$NWANT" ]; then echo; echo "---- abl-$r-full already complete ($n/$NWANT), skipping"; continue; fi
    echo; echo "---- abl-$r-full: $n/$NWANT done, starting $(date '+%F %T')"
    echo "     re-preparing newtype-01/obsidian-mcp (sandboxed)"
    prep=$(./eval/prep_sbx.sh --only-set full --only-repo newtype-01/obsidian-mcp --redo 2>&1)
    echo "$prep" | grep -E "READY|SKIP" | tail -1
    echo "$prep" | grep -q "READY" || { echo "ABORT: obsidian-mcp re-prep failed (see above)"; exit 1; }
    ABL_PREFIX="abl-$r" ABL_ARMS=full ./eval/run_ablation.sh
    rc=$?
    [ $rc -eq 130 ] && exit 130
    n=$(done_rows "$idx")
    echo "---- abl-$r-full finished rc=$rc at $(date '+%F %T'): $n/$NWANT rows"
    [ "$n" -lt "$NWANT" ] && { echo "ABORT: abl-$r-full incomplete -- re-run to resume"; exit 1; }
done
echo; echo "== all repeats done $(date '+%F %T') =="
status
for r in $REPEATS; do .venv/bin/python eval/ablation_check.py --prefix "abl-$r" full; done
} 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"
