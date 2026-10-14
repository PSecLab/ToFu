#!/usr/bin/env bash
# Item 86 validation: does the Python arm actually IMPORT and EXECUTE a real
# target now? Runs INSIDE the sandbox (Linux, ToFu venv = TOFU_TARGET_PYTHON).
#
#   ./eval/smoke_python_arm.sh prepare   # re-prepare the 3 probe repos on ToFu's CPython (--redo)
#   ./eval/smoke_python_arm.sh single    # one LLM-free execution per repo via --test-input
#   ./eval/smoke_python_arm.sh fuzz      # 60s gpt-4.1 fuzz on two local-FS tools
#   ./eval/smoke_python_arm.sh report    # grep the evidence lines
#   ./eval/smoke_python_arm.sh all
#
# PASS criterion (nazmul.todo item 86): a "[PythonRunner] <tool>: module=... via ..."
# line AND an EXEC_SUMMARY with n_success > 0 on a real corpus target. Anything
# less and the Python arm is still unmeasured -- do not report its 0 findings.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/eval/sandbox/runs/smoke86"; mkdir -p "$OUT"
REPOS="osm-mcp-server,uml-mcp,mcp-text-editor"
# LLM env for the fuzz phase (same as eval/run_arm_gpt41.sh; the sandbox only
# forwards OPENAI_API_KEY, so the rest is passed inline to the container).
# An ARRAY, expanded as "${LLM_ENV[@]}": a single string expanded unquoted is
# word-split by bash but NOT by zsh, and then `env` receives ONE argument
# "TOFU_LLM_BASE_URL=https://api.openai.com/v1 TOFU_LLM_MODEL=..." -- the whole
# string becomes the base URL and every LLM call 404s (seen 2026-09-15).
LLM_ENV=(TOFU_LLM_BASE_URL=https://api.openai.com/v1 TOFU_LLM_MODEL=gpt-4.1 TOFU_LLM_TEMPERATURE=0
         TOFU_LLM_SEED=20260910 TOFU_LLM_TIMEOUT=120 TOFU_LLM_MAX_TOKENS=4096 TOFU_LLM_REASONING=)

sbx() { "$REPO/eval/sandbox.sh" run -- "$@"; }

# config basename -> JSON test input (schema-correct, benign). A case, not an
# associative array: macOS /bin/bash is 3.2 and has none.
SINGLE_CFGS="antoinebou12__uml-mcp__list_diagram_types jagan-shanmugam__osm-mcp-server__geocode_address tumf__mcp-text-editor__get_text_file_contents"
single_input() {
  case "$1" in
    antoinebou12__uml-mcp__list_diagram_types)          echo '{}' ;;
    jagan-shanmugam__osm-mcp-server__geocode_address)   echo '{"address": "Old Main, University Park, PA"}' ;;
    tumf__mcp-text-editor__get_text_file_contents)      echo '{"files": [{"file_path": "/work/README.md", "ranges": [{"start": 1, "end": 3}]}]}' ;;
    *) echo '{}' ;;
  esac
}
FUZZ="tumf__mcp-text-editor__get_text_file_contents antoinebou12__uml-mcp__list_diagram_types"

phase_prepare() {
  echo "== prepare (--redo) $REPOS on the sandbox interpreter =="
  "$REPO/eval/sandbox.sh" prepare --only-set host --only-lang python --only-repo "$REPOS" --redo \
    2>&1 | tee "$OUT/prepare.log"
  echo "-- venv interpreters now:"
  for s in jagan-shanmugam__osm-mcp-server antoinebou12__uml-mcp tumf__mcp-text-editor; do
    printf "   %-40s %s\n" "$s" "$(grep -m1 version_info "$REPO/eval/sandbox/targets/$s/.venv/pyvenv.cfg" 2>/dev/null || echo 'NO VENV')"
  done
}

phase_single() {
  echo "== single LLM-free execution per repo (--test-input) =="
  for cfg in $SINGLE_CFGS; do
    f="eval/configs/$cfg.json"
    [ -f "$REPO/eval/sandbox/configs/$cfg.json" ] || { echo "   MISSING $f (prepare first)"; continue; }
    echo "-- $cfg"
    # LLM env passed here too: src/__main__ resolves the API key from
    # TOFU_LLM_BASE_URL and exits before anything runs if it is unset.
    # --metrics-dir/--corpus-dir MUST point into sandbox overlays: the repo is
    # mounted read-only and the default relative metrics/ dir is under it.
    sbx env "${LLM_ENV[@]}" python -m src --config "$f" --test-input "$(single_input "$cfg")" \
        --corpus-dir "eval/corpora/smoke86_$cfg" --metrics-dir "eval/metrics/smoke86" \
        > "$OUT/$cfg.single.log" 2>&1
    grep -E "\[PythonRunner\]|Failed to start runner|Result:|success|Error|Traceback" "$OUT/$cfg.single.log" | head -12 | sed 's/^/   /'
  done
}

phase_fuzz() {
  echo "== 60s fuzz (gpt-4.1) on local-FS tools =="
  for cfg in $FUZZ; do
    f="eval/configs/$cfg.json"
    [ -f "$REPO/eval/sandbox/configs/$cfg.json" ] || { echo "   MISSING $f"; continue; }
    echo "-- $cfg"
    sbx env "${LLM_ENV[@]}" python -m src --config "$f" --time 60 \
        --corpus-dir "eval/corpora/smoke86_$cfg" --metrics-dir "eval/metrics/smoke86" \
        > "$OUT/$cfg.fuzz.log" 2>&1
    grep -E "EXEC_SUMMARY|NOT_EXECUTABLE|EXEC_ERROR|\[PythonRunner\]|Failed to start runner|POTENTIAL VULNERABILITY" \
        "$OUT/$cfg.fuzz.log" | tail -8 | sed 's/^/   /'
  done
}

phase_report() {
  echo "== evidence =="
  for l in "$OUT"/*.log; do
    echo "-- $(basename "$l")"
    grep -E "\[PythonRunner\] .*: module=|EXEC_SUMMARY|NOT_EXECUTABLE|Failed to start runner|shadowing ToFu" "$l" | head -6 | sed 's/^/   /'
  done
  echo
  echo "PASS needs: 'via bare function|in-process JSON-RPC server' AND EXEC_SUMMARY n_success>0."
}

case "${1:-all}" in
  prepare) phase_prepare ;;
  single)  phase_single ;;
  fuzz)    phase_fuzz ;;
  report)  phase_report ;;
  all)     phase_prepare && phase_single && phase_fuzz && phase_report ;;
  *) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
