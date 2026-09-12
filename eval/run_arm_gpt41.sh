#!/usr/bin/env bash
# Hosted-model arm: gpt-4.1, kept strictly separate from the gemma4 index.
#
# WHY gpt-4.1 AND NOT gpt-5 / o3 / o4-mini
# Those are reasoning models: they ignore `temperature` and reject `max_tokens`
# ("Unsupported parameter: 'max_tokens' is not supported with this model").
# The gemma4 arm runs at temperature=0 with reasoning DISABLED precisely so the
# model is the only variable; pairing it with a model that reasons
# unconditionally would confound the comparison. gpt-4.1 accepts temperature=0,
# seed and max_tokens, so the protocol is identical and only the model changes.
# Keep gpt-5 for a deliberate thinking arm later (nazmul.todo item 24).
#
# ETHICS -- sec10_ethical.tex NEEDS A NOTE BEFORE THIS SHIPS.
# This arm sends third-party tool names, descriptions and schemas to OpenAI.
# The local arms do not. HANDOFF section 13 item 6 flagged exactly this as a
# precondition for adding a hosted model.
#
#   ./eval/run_arm_gpt41.sh                      # 5 repos, small test
#   ARM=gpt41-full ./eval/run_arm_gpt41.sh --only-repo DesktopCommander
set -u
cd "$(dirname "$0")/.." || exit 1
PY="${TOFU_PY:-$PWD/.venv/bin/python}"   # TOFU_PY overrides (sandbox: /opt/tofu-venv/bin/python)

set -a; . ./.env; set +a
[ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set in .env"; exit 1; }

export TOFU_LLM_BASE_URL=https://api.openai.com/v1
export TOFU_LLM_MODEL="${TOFU_LLM_MODEL_OVERRIDE:-gpt-4.1}"
export TOFU_LLM_TEMPERATURE=0
export TOFU_LLM_SEED=20260910
export TOFU_LLM_TIMEOUT=120
export TOFU_LLM_REASONING=""       # gpt-4.1 REJECTS reasoning_effort:
                                   #   400 Unrecognized request argument supplied
                                   # It has no reasoning knob, so there is nothing
                                   # to disable. Recorded as "" in provenance.
export TOFU_LLM_MAX_TOKENS=4096
unset OLLAMA_CLOUD_API_KEY         # or it would win over OPENAI_API_KEY

ARM="${ARM:-gpt41}"
TIME="${TOFU_TIME:-180}"
WORKERS="${WORKERS:-2}"

echo "arm=$ARM  model=$TOFU_LLM_MODEL  endpoint=$TOFU_LLM_BASE_URL"
echo "index -> eval/state/runs.$ARM.jsonl   logs -> eval/runs/$ARM/"
echo

exec "$PY" eval/run_eval.py --arm "$ARM" --time "$TIME" --workers "$WORKERS" "$@"
