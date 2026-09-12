# Baselines over ToFu's target set

All baselines are pointed at the SAME prepared targets (`eval/state/prepared.jsonl`),
same commits, same LLM (gpt-4.1), cloud/API analyzers OFF. Compare as disjoint
sets of CONFIRMED findings, never by subtracting counts.

| baseline | status | wrapper | index | notes |
|---|---|---|---|---|
| Cisco MCP Scanner (yara+llm) | DONE 40/41 | `eval/run_cisco_gpt41.sh` | `eval/state/cisco_runs.jsonl` | metadata-only verdicts; api analyzer off |
| MCPSafetyScanner | runnable | `eval/run_mcpsafety.py` | `eval/state/mcpsafety_runs.jsonl` | console output only; flag count is heuristic |
| VIPER-MCP (Phase I+II) | **verified end-to-end**, campaign ready | `eval/run_viper_full.sh` | `eval/state/viper_runs.jsonl` | CodeQL 2.27.0; 3 taint classes; ~5-7 min/server at rounds=10; no fixture mechanism for file-taking tools |
| MCPSecBench | NOT a scanner | — | — | GUI attack harness (pyautogui); cite only |
| Set D (VIPER CVE servers) | dataset, 0 prepared | `prepare_targets.py --only-set d` + `score_set_d.py` | — | commits may be patched; verify first |

Results files: `cisco_baseline_gpt41_20260911.md` (+ raw jsonl).

## Run commands (all from repo root, after `set -a; . ./.env; set +a`)
```
# MCPSafetyScanner, all ready servers (resumable). Output is prose; read the logs.
.venv/bin/python eval/run_mcpsafety.py
# VIPER-MCP Phase II only (no CodeQL yet), all servers. ~15 min/server, resumable.
.venv/bin/python eval/run_viper.py --skip-codeql
# VIPER-MCP full (after `brew install codeql`):
.venv/bin/python eval/run_viper.py
# LLM connectivity check only:
.venv/bin/python eval/run_viper.py --test-agent --limit 1
```
Era-pin note: MCPSafetyScanner's venv is built with `--exclude-newer 2025-04-11`
(its last upstream push) because unpinned `agno` 3.x removed modules it imports.
Viper runs with temperature 0 and gpt-4.1 (its defaults: 0.7, gpt-5.4) -- a
stated deviation so the LLM matches every other arm.

## VIPER-MCP — status and required disclosures (2026-09-11)
- **CodeQL installed (2.27.0) and verified.** Smoke on excel-reader: 5 SARIF
  results (`js/file-access-from-request`, read-side traversal at `readExcelFile`)
  -> 5 targeted static-context entries -> agent probed `list_sheets` with
  `../../etc/passwd`. `--skip-codeql` remains invalid (placeholder target).
  Query-pack deps installed via `codeql pack install` in `ql/jsql`, `ql/pyql`.
- **Node instrumentation was missing from the artifact.** `node_hook.js` ships
  but nothing injected it; `oracle.json` stayed empty on every Node target. We
  added `inject_node_hook_env` (NODE_OPTIONS `--require`) mirroring their
  Python injector. Marked `PATCH (ToFu)` in `src/utils/instrumentation.py` and
  `src/agent/surrogate_agent.py`.
- **Two more patches**, both marked: `base_url: ""` in the shipped config is a
  literal URL to the OpenAI SDK (the wrapper now omits it); `optimizer.py`
  used `prompts` without importing it (`from ..fuzz import prompts`).
- **Protocol deviations to state:** gpt-4.1 (theirs gpt-5.4), temperature 0
  (theirs 0.7). Same LLM as every other arm.
- Index fields to trust: `hook_injected` (False = blind run, discard; derived
  from the log because the engine clears oracle.json between rounds),
  `max_oracle_hits_in_round` (sink observations), `n_anomalies` (tool errors,
  NOT vulns), `n_hit_markers`.
- **Fourth patch (verified):** both LLM prompt templates use named fields but
  were formatted positionally (`strategy.py`, `optimizer.py`) -> every round
  silently fell back to rule-based scoring. Fixed with keyword formatting.
- **Structural limit vs ToFu:** Viper has no fixture mechanism for file-taking
  arguments. On excel-reader every `read_excel`/`export_*` call fails at the
  read (`File not found`) before any write sink, so V1 is unreachable for it
  regardless of CodeQL. ToFu's file-backed parameters are what make V1 findable.
- **Viper's observable Node sink set** (from `node_hook.js`, verbatim): `fs.writeFile*`,
  `fs.appendFile*`, `fs.rm*`, `fs.rmdir*`, `fs.unlink*`, `child_process.exec/execFile/
  execSync/execFileSync/spawn/spawnSync`, `http(s).get/request`, `vm.runIn*Context`.
  NOT hooked: `fs.readFile*` (read-side traversal invisible), global `fetch`.
  V1's `writeFileSync` IS in scope -- reachable only with a fixture file.
