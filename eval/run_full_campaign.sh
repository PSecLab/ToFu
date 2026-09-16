#!/usr/bin/env bash
# Whole-corpus ToFu campaign: ALL 1,404 tool-exposing MCPCorpus repos
# (Benchmarks/extraction/set_full.json), both runners, one uniform arm.
# Run ON THE VM inside tmux. Every phase is resumable / Ctrl-C-safe:
#   prepare skips repos already in eval/state/prepared.jsonl|skipped.jsonl,
#   fuzz  skips tools already in eval/state/runs.$ARM.jsonl.
#
#   ./eval/run_full_campaign.sh prepare 1 4     # tier-1 repos (high-value sinks), 4 parallel shards
#   ./eval/run_full_campaign.sh fuzz            # fuzz every prepared config, 60s/tool (restart to pick up new configs)
#   ./eval/run_full_campaign.sh prepare 2 4     # then tier-2 (log/API-only) repos
#   ./eval/run_full_campaign.sh status
#
# Disk: the VM has ~400G free; a full prepare is ~250G. No delete cycle needed.
# Compute: ~24k tools. At 60s/tool with 4 workers that is ~100h of fuzzing on
# 5 CPUs -- most creds/backend-gated tools fail fast (~3s) so real wall time is
# lower, but plan for days, not hours. More cores => raise WORKERS linearly.
set -u
cd "$(dirname "$0")/.." || exit 1
PY="${TOFU_PY:-$PWD/.venv/bin/python}"
export TOFU_TARGET_PYTHON="${TOFU_TARGET_PYTHON:-3.13}"   # must equal the venv python (item 86)
ARM="${ARM:-gpt41-corpus}"
TIME="${TOFU_TIME:-60}"
WORKERS="${WORKERS:-$(nproc 2>/dev/null || echo 4)}"   # fuzz is CPU-bound: one worker per core
export TOFU_RSS_LIMIT_MB="${TOFU_RSS_LIMIT_MB:-4096}"   # item 93: code-exec tools OOM at 2048
# Fail-fast threshold for 0-success tools. ~60% of the corpus is creds/backend-
# gated; at the default 2000 execs a dead tool still burns most of its 60s
# (needs ~2000 execs at ~60 exec/s). 500 kills it in ~8s and roughly halves the
# campaign (~100h -> ~45-50h on 4 workers). LLM seeds run first, so a tool that
# only the LLM seeds can drive still gets its chance; re-run the executable=no
# rows at 2000 afterwards if time allows (nazmul.todo 2026-09-15).
export TOFU_FAILFAST_EXECS="${TOFU_FAILFAST_EXECS:-500}"

phase_prepare() {
  local tier="${1:-1}" n="${2:-4}"
  # regenerate the manifest for the requested tier ONLY; prepare skips
  # anything already recorded, so re-running with tier 2 later just adds.
  "$PY" Benchmarks/extraction/build_set_full.py --tier "$tier" || exit 1
  echo "== prepare tier $tier in $n parallel shards (logs: eval/state/prepare_full_t${tier}_k*.log) =="
  local pids=()
  for k in $(seq 0 $((n-1))); do
    "$PY" eval/prepare_targets.py --only-set full --shard "$k/$n" \
        > "eval/state/prepare_full_t${tier}_k${k}.log" 2>&1 &
    pids+=($!)
  done
  trap 'kill "${pids[@]}" 2>/dev/null' INT TERM
  wait "${pids[@]}"
  trap - INT TERM
  echo "== prepare tier $tier done =="
  "$PY" - <<'PYEOF'
import json, collections, os
def rows(p): return [json.loads(l) for l in open(p) if l.strip()] if os.path.exists(p) else []
pr, sk = rows("eval/state/prepared.jsonl"), rows("eval/state/skipped.jsonl")
ready = {r["repo"] for r in pr}
print(f"   READY {len(ready)} repos, {sum(r.get('n_configs',0) for r in pr)} configs;  skipped {len({r['repo'] for r in sk})}")
print("   by lang:", dict(collections.Counter(r['lang'] for r in pr)))
c = collections.Counter(str(r.get('reason',''))[:40] for r in sk); print("   top skip reasons:", c.most_common(5))
PYEOF
  # restore the full manifest so set_full.json on disk is the whole corpus again
  "$PY" Benchmarks/extraction/build_set_full.py >/dev/null
}

phase_fuzz() {
  echo "== fuzz: arm=$ARM time=${TIME}s workers=$WORKERS rss=${TOFU_RSS_LIMIT_MB}MB failfast=${TOFU_FAILFAST_EXECS} execs =="
  echo "   (run_arm_gpt41.sh sources .env, hides it for the run, restores on exit -- item 91)"
  # run_eval builds its config list at start: after a later prepare phase adds
  # configs, just re-run this; done tools are skipped from the index.
  ARM="$ARM" TOFU_TIME="$TIME" WORKERS="$WORKERS" ./eval/run_arm_gpt41.sh "$@"
}

phase_status() {
  "$PY" eval/run_eval.py --arm "$ARM" --status 2>&1 | tail -25
  echo; echo "== prepare =="
  for f in eval/state/prepared.jsonl eval/state/skipped.jsonl; do [ -f "$f" ] && echo "   $(wc -l < "$f") $f"; done
  echo "   configs on disk: $(ls eval/configs/*.json 2>/dev/null | wc -l)"
  echo "   disk: $(df -h . | tail -1 | awk '{print $4" free of "$2}')"
}

case "${1:-}" in
  prepare) shift; phase_prepare "${1:-1}" "${2:-4}" ;;
  fuzz)    shift; phase_fuzz "$@" ;;
  status)  phase_status ;;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
