#!/usr/bin/env bash
# Continue the ToFu campaign INSIDE the Docker sandbox.
#
#   ./eval/run_sandbox_campaign.sh prepare      # clone + npm/pip install ALL sets a+b in the sandbox
#   ./eval/run_sandbox_campaign.sh prepare --only-set a --only-lang node --limit 3   # smoke prepare
#   ./eval/run_sandbox_campaign.sh run           # gpt-4.1 arm, all sandbox configs
#   ./eval/run_sandbox_campaign.sh run --only-repo excel-reader   # one repo
#   ./eval/run_sandbox_campaign.sh status
#
# ARM NAME: gpt41-sandbox. Kept DISTINCT from the host arm (gpt41-full) so no
# number can be confused across the two environments. The host arm's 4xx/530
# configs stay on disk as host-run evidence; published numbers come from here.
# State lives in eval/sandbox/{state,runs,targets,configs,...} (bind-mounted
# over eval/* inside the container), never touching the host campaign dirs.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
SBX="./eval/sandbox.sh"
ARM="${ARM:-gpt41-sandbox}"
TIME="${TOFU_TIME:-180}"
WORKERS="${WORKERS:-4}"
MODE="${1:-}"; shift || true

case "$MODE" in
  prepare)
    exec "$SBX" prepare "$@"
    ;;
  run)
    # run_arm_gpt41.sh handles model/temp/seed env; TOFU_PY points it at the
    # container venv; ARM/TIME/WORKERS pass through.
    exec "$SBX" run -- env TOFU_PY=/opt/tofu-venv/bin/python ARM="$ARM" TOFU_TIME="$TIME" WORKERS="$WORKERS" \
      ./eval/run_arm_gpt41.sh "$@"
    ;;
  status)
    echo "sandbox arm: $ARM"
    [ -f eval/sandbox/state/prepared.jsonl ] && echo "prepared: $(wc -l < eval/sandbox/state/prepared.jsonl) repos" || echo "prepared: none yet"
    [ -f "eval/sandbox/state/runs.$ARM.jsonl" ] && echo "runs done: $(wc -l < "eval/sandbox/state/runs.$ARM.jsonl")" || echo "runs done: 0"
    echo "configs: $(ls eval/sandbox/configs/*.json 2>/dev/null | wc -l | tr -d ' ')"
    ;;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
