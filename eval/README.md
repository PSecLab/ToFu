# ToFu evaluation runbook

Two steps. Both are RESUMABLE and safe to Ctrl-C. Run from the repo root
(`~/pseclab/toolfuzzer`), natively in Terminal -- NOT through Claude's device
shell, which kills background jobs when each call returns.

## 0. LLM backend  (we are using LOCAL Ollama + llama3.1:8b)

ToFu's LLMHandler now reads its backend from the environment, so the same code
runs against local Ollama or the cloud. For the local setup:

    ollama serve                 # if not already running
    ollama pull llama3.1:8b

    export TOFU_LLM_BASE_URL=http://localhost:11434/v1
    export TOFU_LLM_MODEL=llama3.1:8b
    export OLLAMA_CLOUD_API_KEY=ollama      # local Ollama ignores the value
    # optional: export TOFU_LLM_TIMEOUT=180  (8B on CPU can be slow)

run_eval.py preflights the backend with a one-token request and exits in
seconds if it is unreachable, instead of failing 40 runs into a campaign.

### Still rotate the leaked key
RESOLVED 2026-09-10. A live credential used to be the hardcoded default for
OLLAMA_CLOUD_API_KEY in 12 files: `targets/fuzz_*.py` (11 of them, including
`fuzz_http_check.py`) and `src/__main__.py`, the entrypoint this harness calls.
All 12 now read the environment variable, with `"ollama"` as the local
placeholder and a hard error otherwise.

The key has been revoked at the provider. A history-rewritten mirror with the
key purged from every blob in every ref is at `_history_scrub/tofu-scrubbed.git`;
it has NOT been pushed, because that rewrites every commit hash on
`PSecLab/toolfuzzer` including Pierre's. See the audit section at the end of
`ToFu_src/nazmul.todo` for the push procedure.

### Report the model -- it is an experimental variable, not a detail
Sanitizer selection and seed generation both run through this model. VIPER-MCP's
RQ4 varied ONLY the backend and saw triggered-server counts swing from 0 to 88
(Claude Haiku 4.5 refused to generate probing prompts at all). An 8B local model
will not select sanitizers as well as a frontier model. Two consequences:
  * State the exact model and endpoint in the setup subsection.
  * A weak selector shows up as LOW RECALL, not as an error -- so if findings
    look sparse, re-run a subset with a stronger model before concluding ToFu
    missed the bugs. That comparison is itself a good ablation (Pierre's TODO
    asks for sanitizer-selection precision anyway).

## 1. Materialise the targets

    python3 eval/prepare_targets.py                # all 58 (Set A 50 + Set B 8)
    python3 eval/prepare_targets.py --limit 3      # smoke test first
    python3 eval/prepare_targets.py --only-set b   # just Set B

Per repo: clone at the PINNED commit -> install deps (prefers the repo's own
lockfile) -> detect the stdio entrypoint -> handshake `tools/list` -> write one
ToFu config per tool.

Outputs:
    eval/targets/<owner>__<repo>/     the checkouts
    eval/configs/<repo>__<tool>.json  one config per tool
    eval/state/prepared.jsonl         what succeeded
    eval/state/skipped.jsonl          what failed AND WHY  <-- the paper's
                                      exclusion list (Pierre's TODO)

### Expect a real failure rate, and report it
Two causes seen while testing, both legitimate exclusions:
  * DEPENDENCY DRIFT. The corpus snapshot is mid-2025; the MCP SDKs have shipped
    breaking changes since. nnquant/qmt-mcp-server dies on the FastMCP rename.
    Pinning the repo commit does NOT pin its dependencies. The lockfile
    preference helps but cannot fix repos that shipped without a lockfile.
  * BROKEN BUILD OUTPUT. StuMason/coolify-mcp and Softeria/ms-365-mcp-server
    build cleanly, then their own dist/index.js throws ERR_MODULE_NOT_FOUND.
Do not hand-fix these into working order -- that silently biases the sample.
Record them, report the count and reasons, move on.

## 1b. Install ToFu's OWN dependencies

The fuzzer needs these in whichever python3 you invoke it with:

    python3 -m pip install -r requirements.txt pymongo

NOTE: `pymongo` is imported by src/ but is MISSING from requirements.txt --
add it there. Without the install you get, per run:
    ModuleNotFoundError: No module named 'mcp'

ATHERIS ON APPLE SILICON is the likely sticking point: it compiles against
libFuzzer and often has no prebuilt arm64 wheel. If `pip install atheris` fails:

    brew install llvm
    export CC=$(brew --prefix llvm)/bin/clang
    export CXX=$(brew --prefix llvm)/bin/clang++
    python3 -m pip install --no-binary :all: atheris

run_eval.py preflights `import src.fuzzer` and refuses to start if this is not
sorted, so you cannot burn a campaign on a broken environment.

## 2. Run the campaign

    python3 eval/run_eval.py --time 60 --limit 3    # SMOKE TEST FIRST
    python3 eval/run_eval.py --time 900 --workers 4 # real run
    python3 eval/run_eval.py --status               # progress, anytime

Outputs:
    eval/runs/<repo>__<tool>.log   full stdout/stderr per run
    eval/state/runs.jsonl          index: repo, tool, seconds, finding_hits

### Why override_rules is empty
Every config sets `"override_rules": {}` deliberately. fuzzer.py:796 shows that
when override_rules is NON-empty the fuzzer SKIPS `llm.select_sanitizers()` and
just uses what it was handed. Every existing `targets/fuzz_*.py` harness passes
explicit override_rules, so all 14 current findings were produced with
HAND-PICKED sanitizers -- bypassing the automated selection that is ToFu's
central claim, and exactly the overfitting Pierre's TODO worries about.
Leaving it empty forces the real path. Keep it that way.

## Budget

    wall-clock ~= n_configs * time_per_tool / workers

Count configs after step 1 (`ls eval/configs | wc -l`). At ~6 tools/repo and 40
repos surviving preparation that is ~240 configs; at 900s and 4 workers that is
~15 h. Start with --time 300 to get a full pass, then deepen.

## Status

Sets are FINAL and committed: Benchmarks/extraction/set_a.{json,csv},
set_b.{json,csv}, seed 20260909, Set A fingerprint aa6f0cffff64.
NO EVALUATION HAS BEEN RUN YET. Nothing here has produced a finding.
