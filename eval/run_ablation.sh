#!/usr/bin/env bash
# ToFu ablation campaign: the SAME 1,801 configs (the 266-repo H2H dynamic set = 273 minus the 7
# host-control servers no dynamic tool runs; 251 executed in the 60s sandboxed sweeps + 15 that
# succeeded only in the 09-22 run) under six arms, each removing one ToFu stage. PSU PC,
# 12 workers, 60s/tool, bubblewrap sandbox (via run_corpus_sbx.sh). Resumable and
# Ctrl-C-safe: each arm has its own index, done configs are skipped on re-run.
#
#   RUN IN tmux, NOT through a tool:
#     tmux new -s abl
#     source ./.tofu_env.sh
#     ./eval/run_ablation.sh
#   ./eval/run_ablation.sh --status             # progress only, runs nothing
#   ABL_ARMS=full ./eval/run_ablation.sh --limit 3   # smoke: 3 configs of one arm
#
# Arms (order matters -- `full` runs first and is the only one allowed to write the
# LLM replay cache; every later arm replays it read-only, so the stage that is NOT
# ablated sees exactly the full arm's LLM output):
#   full        full ToFu + shadow oracle log (oracle ablations derive from this arm)
#   nollmseeds  deterministic fallback seeds, LLM sanitizer selection kept
#   mandatory   LLM seeds kept, selection = the 10 BASE_MANDATORY_SANITIZERS only
#   nollm       both LLM stages off (fallback seeds + mandatory sanitizers), $0
#   noseeds     empty initial corpus (no LLM, no fallback seeds), selection kept
#   allsan      LLM seeds kept, selection = ALL AVAILABLE_SANITIZERS
# The 2x2 grid is {full, nollmseeds, mandatory, nollm}. Analysis: eval/ablation_report.py
set -u
cd "$(dirname "$0")/.." || exit 1

CFG="${ABL_CONFIGS:-Benchmarks/extraction/ablation_266_configs.txt}"
ALL_ARMS="full nollmseeds mandatory nollm noseeds allsan"
ARMS="${ABL_ARMS:-$ALL_ARMS}"
PREFIX="${ABL_PREFIX:-abl}"
export TOFU_TIME="${TOFU_TIME:-60}"
export WORKERS="${WORKERS:-12}"
export TOFU_SANDBOX=bwrap
export TOFU_RSS_LIMIT_MB="${TOFU_RSS_LIMIT_MB:-2048}"
export TOFU_LLM_CACHE_DIR="${TOFU_LLM_CACHE_DIR:-$PWD/eval/state/llm_cache_ablation}"
[ -f "$CFG" ] || { echo "missing $CFG"; exit 1; }
NWANT=$(grep -vc '^\s*\(#\|$\)' "$CFG")

status() {
    python3 - "$CFG" "$PREFIX" $ALL_ARMS <<'EOF'
import json, os, sys
cfg, prefix, arms = sys.argv[1], sys.argv[2], sys.argv[3:]
want = {os.path.splitext(l.strip())[0] for l in open(cfg) if l.strip() and not l.startswith("#")}
for a in arms:
    p = f"eval/state/runs.{prefix}-{a}.jsonl"
    rows = {}
    if os.path.exists(p):
        for l in open(p):
            if l.strip():
                r = json.loads(l); rows[os.path.splitext(r.get("config", ""))[0]] = r
    rows = {k: v for k, v in rows.items() if k in want}
    ex = sum(1 for r in rows.values() if (r.get("n_exec_success") or 0) >= 1)
    hits = sum(1 for r in rows.values() if r.get("ok") and r.get("finding_hits"))
    print(f"  {prefix}-{a:<11} {len(rows):>5}/{len(want)} done  executed={ex:<5} configs-with-alerts={hits}")
EOF
}

if [ "${1:-}" = "--status" ]; then echo "== ablation progress =="; status; exit 0; fi

# ---- preflight (nothing runs if any of these fail) ----
for a in $ARMS; do case " $ALL_ARMS " in *" $a "*) : ;; *) echo "unknown arm '$a' (valid: $ALL_ARMS)"; exit 1;; esac; done
NHAVE=$(python3 -c "
import os,sys
w={os.path.splitext(l.strip())[0] for l in open('$CFG') if l.strip() and not l.startswith('#')}
h={os.path.splitext(f)[0] for f in os.listdir('eval/configs')}
print(len(w&h))")
NCACHE=$(python3 -c "
import os
w={os.path.splitext(l.strip())[0] for l in open('$CFG') if l.strip() and not l.startswith('#')}
d='$TOFU_LLM_CACHE_DIR'
h={os.path.splitext(f)[0] for f in os.listdir(d)} if os.path.isdir(d) else set()
print(len(w&h))")
echo "== ToFu ablation =="
echo "   arms: $ARMS"
echo "   configs: $NHAVE/$NWANT prepared   cache: $NCACHE/$NWANT in $TOFU_LLM_CACHE_DIR"
echo "   time=${TOFU_TIME}s workers=$WORKERS sandbox=$TOFU_SANDBOX"
echo "   est. wall per arm @ ~75s/config: ~$(( NWANT * 75 / WORKERS / 60 )) min"
if [ "$NHAVE" -lt "$NWANT" ] && [ -z "${ABL_ALLOW_MISSING:-}" ]; then
    echo "ABORT: $((NWANT - NHAVE)) configs not prepared. Prepare first:"
    echo "   ./eval/prep_sbx.sh --only-set full --only-repos-file Benchmarks/extraction/ablation_251_repos.txt"
    echo "   (ABL_ALLOW_MISSING=1 to run anyway -- every arm then covers a smaller set)"
    exit 1
fi
if [ "$NCACHE" -lt "$NWANT" ] && [ -z "${ABL_ALLOW_CACHE_MISS:-}" ]; then
    echo "ABORT: $((NWANT - NCACHE)) configs have no replay-cache entry -> the full arm would"
    echo "   make fresh LLM calls for them. ABL_ALLOW_CACHE_MISS=1 to accept that (small cost)."
    exit 1
fi
if [ -z "${ABL_SKIP_TESTS:-}" ]; then
    .venv/bin/python -m pytest tests/ -q -x -p no:warnings --basetemp=eval/state/pytest_tmp/abl >eval/state/abl_pytest.log 2>&1 \
        || { tail -20 eval/state/abl_pytest.log; echo "ABORT: tests fail"; rm -f eval/state/abl_pytest.log; exit 1; }
    tail -1 eval/state/abl_pytest.log; rm -f eval/state/abl_pytest.log
fi

trap 'echo; echo "interrupted -- re-run to resume"; exit 130' INT TERM

for a in $ARMS; do
    # clear every switch, then set this arm's. Only `full` may write the cache.
    unset TOFU_NO_LLM TOFU_NO_LLM_SEEDS TOFU_NO_SEEDS TOFU_NO_LLM_SANITIZERS TOFU_ORACLE_SHADOW TOFU_LLM_CACHE_READONLY
    case "$a" in
      full)       export TOFU_ORACLE_SHADOW=1 ;;
      nollmseeds) export TOFU_NO_LLM_SEEDS=1 ;;
      mandatory)  export TOFU_NO_LLM_SANITIZERS=mandatory ;;
      nollm)      export TOFU_NO_LLM=1 ;;
      noseeds)    export TOFU_NO_SEEDS=1 ;;
      allsan)     export TOFU_NO_LLM_SANITIZERS=all ;;
    esac
    [ "$a" != full ] && export TOFU_LLM_CACHE_READONLY=1
    echo
    echo "==== arm $PREFIX-$a  [$(env | grep -E '^TOFU_(NO_|ORACLE_|LLM_CACHE_READONLY)' | sort | tr '\n' ' ')] ===="
    ARM="$PREFIX-$a" CORPUS_MODE=none bash ./eval/run_corpus_sbx.sh --only-configs-file "$CFG" "$@"
    rc=$?
    [ $rc -eq 130 ] && exit 130
    [ $rc -ne 0 ] && echo "arm $PREFIX-$a exited rc=$rc -- see eval/runs/$PREFIX-$a/ ; continuing"
done
echo; echo "== done =="; status
echo "report: python3 eval/ablation_report.py"
