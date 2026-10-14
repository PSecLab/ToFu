#!/usr/bin/env bash
# Sandboxed full-corpus re-sweep: every ready config at a 60s budget, under the
# bubblewrap sandbox, with the reachable configs scheduled first. A NEW arm
# (gpt41-corpus-sbx) so the 2026-09-22 gpt41-corpus index is never touched.
#
# Purpose: put the whole corpus on the CURRENT oracles (reflected-xss + exfil,
# added after the original run) and the sandbox, and settle the 59 "corpus-only"
# candidates from repo24 (hypothesis: shared /tmp across concurrent unsandboxed
# configs faked cross-config temp-file leaks; the sandbox's private /tmp removes
# them). See findings/repo24_20260926/REPORT.md.
#
#   RUN IN tmux, NOT through a tool:
#     tmux new -s csbx
#     ./eval/run_corpus_sbx.sh
#   ./eval/run_corpus_sbx.sh --status     # progress only
#   ./eval/run_corpus_sbx.sh --limit 3    # smoke
#
# PRECONDITION: all corpus targets must be prepared (eval/targets + eval/configs).
# The PSU PC only had repo24-b's targets; prepare the rest first, e.g.
#   python3 eval/prepare_targets.py --only-set full
# .env handling + model/temp/seed come from run_arm_gpt41.sh (do not remove).
set -u
cd "$(dirname "$0")/.." || exit 1

export ARM="${ARM:-gpt41-corpus-sbx}"
export TOFU_TIME="${TOFU_TIME:-60}"
export WORKERS="${WORKERS:-12}"
export TOFU_SANDBOX="${TOFU_SANDBOX:-bwrap}"
export TOFU_KILL_GRACE="${TOFU_KILL_GRACE:-60}"
export TOFU_STARTUP_TIMEOUT="${TOFU_STARTUP_TIMEOUT:-25}"
export TOFU_RSS_LIMIT_MB="${TOFU_RSS_LIMIT_MB:-2048}"
export TOFU_FAILFAST_EXECS="${TOFU_FAILFAST_EXECS:-500}"
export TOFU_JS_COV_SLOTS="${TOFU_JS_COV_SLOTS:-1024}"

if [ "$TOFU_SANDBOX" = bwrap ]; then
    command -v bwrap >/dev/null || { echo "bubblewrap missing: sudo apt install bubblewrap"; exit 1; }
    if ! _bw=$(bwrap --die-with-parent --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp -- /bin/true 2>&1); then
        echo "bwrap cannot start here: $_bw"
        echo "Ubuntu 24.04: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"; exit 1
    fi
fi

# JS targets are built for node 22; a non-sourced shell defaults to system node
# (v18 on the PSU PC) and every node config fails at startup while run_eval still
# records ok=True. Refuse to launch on the wrong node (2026-09-26 bad probe).
NODE_WANT="${TOFU_NODE_MAJOR:-22}"
if command -v node >/dev/null; then
    NV=$(node -v 2>/dev/null); case "$NV" in v${NODE_WANT}.*) : ;; *)
        echo "node $NV but need v${NODE_WANT}.x -- run: source ./.tofu_env.sh (or nvm use ${NODE_WANT})"; exit 1 ;; esac
else
    echo "node not on PATH -- source ./.tofu_env.sh first"; exit 1
fi

PRIO="Benchmarks/extraction/corpus_reachable_configs.txt"
UNSAFE="Benchmarks/extraction/set_e2_unsafe_repos.txt"
[ -f "$PRIO" ] || { echo "missing $PRIO"; exit 1; }
NCFG=$(ls eval/configs/*.json 2>/dev/null | wc -l)
echo "== sandboxed corpus re-sweep =="
echo "   arm=$ARM time=${TOFU_TIME}s workers=$WORKERS sandbox=$TOFU_SANDBOX slots=$TOFU_JS_COV_SLOTS"
echo "   configs in eval/configs: $NCFG   reachable-first: $(grep -vc '^#' $PRIO)"
echo "   est. wall @ ${WORKERS}w, ~80s/config: ~$(( NCFG * 80 / WORKERS / 3600 )) h"
echo
[ "$NCFG" -lt 1000 ] && echo "WARNING: only $NCFG configs -- corpus targets likely NOT all prepared (see PRECONDITION)."

# Host-control targets (process spawn/kill, tmux, FS) stay skipped even under the
# sandbox: it contains filesystem damage but not process/CPU-load hazards.
SKIP_ARG=""
[ -z "${TOFU_FUZZ_UNSAFE:-}" ] && [ -f "$UNSAFE" ] && SKIP_ARG="--skip-repos-file $UNSAFE"

# CORPUS_MODE: priority (default) = full corpus, reachable configs first;
#              reachable = ONLY the reachable configs; none = neither (caller
#              passes its own --only-repos-file etc. via "$@", e.g. PC recovery probe).
case "${CORPUS_MODE:-priority}" in
  priority)  ORDER_ARG="--priority-configs-file $PRIO" ;;
  reachable) ORDER_ARG="--only-configs-file $PRIO" ;;
  none)      ORDER_ARG="" ;;
  *) echo "bad CORPUS_MODE=${CORPUS_MODE}"; exit 1 ;;
esac
echo "   CORPUS_MODE=${CORPUS_MODE:-priority}"
exec ./eval/run_arm_gpt41.sh $ORDER_ARG $SKIP_ARG "$@"
