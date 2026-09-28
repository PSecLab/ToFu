#!/usr/bin/env bash
# ToolFuzz H2H-45 on the PSU PC, next to a live repo24 campaign.
# Uses its own targets/configs/state (eval/*_tf) and ToolFuzz's own py3.10 venv;
# every target server runs in bwrap (run_toolfuzz.py). Resumable; Ctrl-C safe.
#   cd /scratch/tofu && tmux new -s toolfuzz ./eval/psu_toolfuzz_run.sh
# Needs OPENAI_API_KEY=... in /scratch/tofu/eval/state_tf/openai.env (chmod 600).
set -uo pipefail
R=/scratch/tofu
cd "$R" || exit 1
source "$R/.tofu_env.sh"
export TOOLFUZZ_PREPARED="$R/eval/state_tf/prepared.jsonl"
export TOOLFUZZ_INDEX="$R/eval/state_tf/toolfuzz_runs.jsonl"
export TOOLFUZZ_CALLS_FILE="$R/eval/state_tf/toolfuzz_llm_calls.json"
export TOOLFUZZ_CACHE_DB="$R/eval/state_tf/toolfuzz_llm_cache.sqlite"
export TOOLFUZZ_OUT="$R/eval/toolfuzz_runs"
# key lives in a ToolFuzz-only file (repo24 never reads it; masked inside bwrap)
export TOOLFUZZ_ENV_FILE="$R/eval/state_tf/openai.env"
# ToFu's own index decides --executable-only and the ToFu side of the comparison.
# Default: the sandboxed 60s headline runs (corpus-sbx + recover-pc) that define the
# 251-repo set (nazmul.todo item 25); falls back to the 09-22 snapshot.
if [ -f "$R/eval/state_tf/tofu_sbx_index.jsonl" ]; then
  export TOOLFUZZ_TOFU_INDEX="${TOOLFUZZ_TOFU_INDEX:-$R/eval/state_tf/tofu_sbx_index.jsonl}"
else
  export TOOLFUZZ_TOFU_INDEX="${TOOLFUZZ_TOFU_INDEX:-$R/findings/baselines/tofu_runs_e2_20260922.jsonl}"
fi
export SHARDS="${SHARDS:-3}" NICE="${NICE:-19}"

# Never fuzz a repo that a repo24 campaign on this host is fuzzing right now
# (shared external APIs / rate limits could change its results). Those repos
# are skipped now and picked up by a later resume once repo24 is done.
SKIP="$R/eval/state_tf/skip_now.txt"
UNSAFE=Benchmarks/extraction/set_e2_unsafe_repos.txt
[ -s "$UNSAFE" ] || { echo "missing $UNSAFE -- refusing to run without the unsafe-repo skip list"; exit 1; }
cat "$UNSAFE" > "$SKIP"
# ...and never a repo that ANY running ToFu campaign (run_repo24.py / run_eval.py,
# e.g. the ablation) is fuzzing: its repo list, or the repos behind its config list.
ps -eo args | awk '/[r]un_repo24.py|[r]un_eval.py/' | python3 -c '
import sys, json, os
out = []
for line in sys.stdin:
    a = line.split()
    for i, x in enumerate(a[:-1]):
        f = a[i + 1]
        if not os.path.isfile(f): continue
        if x in ("--repos-file", "--priority-repos-file"):
            out += open(f).read().replace(",", "\n").split(); print("avoiding repos of running campaign:", f, file=sys.stderr)
        elif x == "--only-configs-file":
            for c in open(f).read().split():
                try: out.append(json.load(open(os.path.join("eval/configs", c)))["_repo"])
                except Exception: pass
            print("avoiding repos behind running campaign configs:", f, file=sys.stderr)
print("\n".join(out))' >> "$SKIP"
export SKIP_FILE="$SKIP"
exec ./eval/run_toolfuzz_h2h.sh "$@"
