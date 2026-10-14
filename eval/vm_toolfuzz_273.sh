#!/usr/bin/env bash
# ToolFuzz over the H2H-273 dynamic set (266 repos; nazmul.todo / build_h2h_273.py) on the VM.
# Tool filter = tofu_exec_index_273.jsonl (1,585 executed tools). Every target in bwrap
# (own PID/IPC ns, / read-only), gpt-4.1-mini, reduced-call budget. Resumable, Ctrl-C safe.
#   cd ~/toolfuzzer && tmux new -s toolfuzz ./eval/vm_toolfuzz_273.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export REPOS_FILE=Benchmarks/extraction/h2h_273_dynamic_repos.txt
export TOOLFUZZ_TOFU_INDEX=Benchmarks/extraction/tofu_exec_index_273.jsonl
export TOOLFUZZ_MAX_CALLS="${TOOLFUZZ_MAX_CALLS:-35000}"
export SHARDS="${SHARDS:-4}" NICE="${NICE:-10}"
UNSAFE=Benchmarks/extraction/set_e2_unsafe_repos.txt
[ -s "$UNSAFE" ] || { echo "missing $UNSAFE -- refusing to run without the unsafe-repo skip list"; exit 1; }
SKIP=eval/state/toolfuzz_skip_now.txt; cat "$UNSAFE" > "$SKIP"
# never a repo that a ToFu/Viper campaign on this host is fuzzing right now
ps -eo args | awk '/[r]un_repo24.py|[r]un_eval.py|[r]un_viper/' | python3 -c '
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
