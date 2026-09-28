#!/usr/bin/env bash
# Prepare ToolFuzz targets on the PSU PC (clone at ToFu's pinned commit, install,
# build, tools/list probe) -- ALL inside bwrap: filesystem read-only except
# ToolFuzz's own eval/{targets,configs,state}_tf, /scratch/tofu/.cache and a
# scratch HOME; own PID/IPC namespace. Never touches repo24's eval/targets,
# eval/configs, eval/state. Low priority, OOM-first. Resumable (prepare_targets).
#   cd /scratch/tofu && tmux new -s tfprep ./eval/psu_toolfuzz_prep.sh [REPOS_FILE]
set -uo pipefail
R=/scratch/tofu
cd "$R" || exit 1
source "$R/.tofu_env.sh"
REPOS_FILE="${1:-Benchmarks/extraction/ablation_251_repos.txt}"
[ -s "$REPOS_FILE" ] || { echo "missing $REPOS_FILE"; exit 1; }
command -v bwrap >/dev/null || { echo "bwrap required -- refusing to run untrusted builds unsandboxed"; exit 1; }
export PATH="$R/.cache/bun-linux-x64:$HOME/.local/bin:$PATH"     # bun + uv (executed, never written)
TGT=$R/eval/targets_tf; CFG=$R/eval/configs_tf; ST=$R/eval/state_tf; TFH=$R/.tf_home
export TOFU_TARGETS_DIR=$TGT TOFU_CONFIGS_DIR=$CFG TOFU_STATE_DIR=$ST
mkdir -p "$TGT" "$CFG" "$ST" "$TFH" "$R/.cache" eval/logs
echo 1000 > /proc/self/oom_score_adj 2>/dev/null || true
REPOS=$(tr '\n' ',' < "$REPOS_FILE" | tr -d ' ')
: "${PREP_SHARDS:=2}"
echo "preparing $(grep -c . "$REPOS_FILE") repos from $REPOS_FILE with $PREP_SHARDS shards (resumable)"
for ((k=0; k<PREP_SHARDS; k++)); do
  nice -n 19 ionice -c3 bwrap --die-with-parent --unshare-pid --unshare-ipc --new-session \
    --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$TGT" "$TGT" --bind "$CFG" "$CFG" --bind "$ST" "$ST" \
    --bind "$R/.cache" "$R/.cache" --bind "$TFH" "$TFH" --setenv HOME "$TFH" \
    -- "$R/.venv/bin/python" eval/prepare_targets.py --only-set full --only-repo "$REPOS" \
       --shard "$k/$PREP_SHARDS" >> "eval/logs/tf_prep_$k.log" 2>&1 &
done
wait
echo "ready: $(grep -c '"status": "ready"' "$ST/prepared.jsonl")  skipped: $(grep -c . "$ST/skipped.jsonl" 2>/dev/null || echo 0)"
