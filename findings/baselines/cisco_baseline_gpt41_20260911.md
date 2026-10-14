# Cisco AI Defense MCP Scanner — baseline (gpt-4.1), 2026-09-11

Scanner v4.8.4 @ 16e684d8bd8f. Analyzers: **yara + llm (gpt-4.1)**. Cloud `api`
analyzer OFF (no Cisco AI Defense subscription). Ran over ToFu's own prepared
targets (`eval/state/prepared.jsonl`). One bug patched in the scanner's cli.py
(`os` shadowing) to make it run.

## Cisco result
```
servers scanned : 40 ok / 41 attempted     tools scanned : 535
tools flagged   : 23                        findings      : 28 (yara 20, llm 8)
median wall     : 3.5 s/server  (metadata only — never executes a tool)
```
8 repos carried >=1 flag. Every flag is severity HIGH, but all are **metadata
verdicts** — yara/LLM reading tool names/descriptions, not runtime behaviour:

| repo | tool | analyzer | threat (from description) |
|------|------|----------|---------------------------|
| locallama-mcp | route_task | yara | PROMPT INJECTION, TOOL POISONING |
| locallama-mcp | reload_config | yara | CREDENTIAL HARVESTING |
| pluggedin-mcp-proxy | send_notification | yara | TOOL POISONING |
| google-workspace-mcp | manage_email | yara | TOOL POISONING, DATA EXFILTRATION |
| google-workspace-mcp | manage_drive/scratchpad | yara | CREDENTIAL HARVESTING |
| apisix-mcp | create_secret/update_secret | yara | CREDENTIAL HARVESTING |
| circleci | 6 tools | yara+llm | PROMPT INJECTION, CREDENTIAL HARVESTING |
| square-mcp-server | get_type_info/get_service_info | llm | PROMPT INJECTION |
| DesktopCommanderMCP | start_process, interact_with_process | llm | PROMPT INJECTION |
| mcp_excalidraw | export_scene, read_diagram_guide | yara+llm | CREDENTIAL HARVESTING, PROMPT INJECTION |

These are pattern matches on documented interface text (an email tool named
"manage_email" trips DATA EXFILTRATION). Useful as a metadata screen; not
evidence of a runtime vulnerability.

## Cross-check: what did ToFu (gpt41-full) find on the SAME 8 repos?
Read from `eval/state/runs.gpt41-full.jsonl` (the gpt-4.1 ToFu arm — NOT the
`runs.jsonl` the summary script currently reads; see caveat).

| repo | ToFu executed? | raw hits | ToFu confirmed finding | comparison |
|------|----------------|----------|------------------------|------------|
| **locallama-mcp** | YES (15,682 succ) | 1799 | **V2 log-injection (CONFIRMED), V3 update_server** | **BOTH** — different bug classes |
| google-workspace | YES (8,298 succ) | 5561 | none — positive control, path containment OK | Cisco only (metadata) |
| pluggedin-proxy | partial (661 succ, needs key) | 1 | none (FP) | Cisco only (metadata) |
| apisix-mcp | 1/32 exec (ECONN) | 3 | none (env-excluded) | Cisco only (metadata) |
| circleci | ~never (24 succ, needs token) | 0 | none (env-excluded) | not comparable |
| square-mcp-server | NOT YET RUN | — | — | not comparable |
| DesktopCommanderMCP | NOT YET RUN | — | — | not comparable |
| mcp_excalidraw | NOT YET RUN | — | — | not comparable |

## Conclusions
1. The summary's "Cisco only / ToFu only / both" is WRONG as printed: it reads
   the old `runs.jsonl` arm (77 runs, 0 recorded hits) instead of the gpt-4.1
   arm. Corrected here by hand.
2. **locallama-mcp belongs in BOTH**, and it is the headline disjoint-set case:
   Cisco flags the *description* (prompt-injection/tool-poisoning wording);
   ToFu finds *runtime* bugs Cisco cannot see (V2 unsanitised log write, V3
   unauth self-update). Same repo, non-overlapping bug classes — neither tool
   subsumes the other.
3. "ToFu only" is empty in the script because ToFu's CONFIRMED findings live in
   manual triage (findings/), not as a machine field in the index; raw
   finding_hits are FP-heavy and not a fair proxy. A curated ToFu-findings list
   is needed for the table.
4. 3 of 8 Cisco-only repos (square, DesktopCommander, excalidraw) ToFu HAS NOT
   RUN yet (gpt41-full stopped at 207/530). The comparison is incomplete until
   ToFu covers the same 40 servers.

## Caveats for Table 2
- Open-source analyzers only (yara+llm); cloud api off. State as limitation.
- Cisco reads metadata, ToFu executes. Disjoint sets, NOT a difference.
- Scanner patched (os bug) to run; state in methodology.

---
## UPDATE (same day): summary index fixed -> reads gpt41-full arm

After pointing TOFU_RUNS at runs.gpt41-full.jsonl (298 runs), the script's
disjoint sets became:
```
Cisco only : circleci, square-mcp-server, DesktopCommanderMCP, mcp_excalidraw
ToFu only  : excel-reader-mcp, cursor10x-mcp, bsv-mcp
both       : locallama-mcp, pluggedin-mcp-proxy, google-workspace-mcp, apisix-mcp
```
These sets use raw finding_hits, which are FP-heavy. Triage overlay (the honest
version for the paper):
- ToFu-only that is REAL: **excel-reader-mcp (V1 arbitrary file write)**.
  cursor10x-mcp and bsv-mcp are FP cascades (url sanitizer on non-url args).
- both, REAL on ToFu side: **locallama-mcp (V2 log injection + V3 update_server)**
  — the headline case: Cisco flags the description, ToFu finds runtime bugs.
  google-workspace (ToFu FP, positive control), apisix (env-excluded),
  pluggedin (weak/FP) are "both" only because raw hits fired.
- Cisco-only: circleci (ToFu needs a token), and square / DesktopCommander /
  excalidraw which **ToFu has not run yet** (gpt41-full incomplete).

ACTION ITEMS
- The table must be built from CONFIRMED findings (findings/confirmed + this
  triage), not raw finding_hits. Raw hits belong in an appendix at most.
- Finish the ToFu gpt41-full run so it covers all 40 Cisco servers before the
  final comparison.
