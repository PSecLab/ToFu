# Re-run results — reachability misses recovered (2026-09-22)

> **NOTE 2026-09-26:** the "high-confidence (succ≥0.5)" tier used below is withdrawn — tool-level exec-success rate is reachability, not evidence about a given alert (the oracle already requires per-input success), so it is no longer used to tier or filter candidates. Candidate totals below are unaffected; see findings/RESULTS_SUMMARY.md.


**Task 3 outcome.** The 27 cleanly-executable repos where ToFu found 0 but
CodeQL/Cisco found something (rerun_targets.txt) were re-run at **5× budget**
(TOFU_TIME=300), **cache-accelerated** (0 LLM calls — cached selection+seeds),
with the **two new evidence-gated oracles** (`check_reflected_output` CWE-79/116,
`check_introspection_exfil` CWE-201) live. Only cost was time.

## Recovered: 11 of 27
| repo | now finds | driver |
|---|---|---|
| chemiguel23/memorymesh | 14 | **reflected-xss** |
| pimzino/agentic-tools-mcp | 5 | path-traversal (deeper budget) |
| ddukbg/github-enterprise-mcp | 2 | reflected-xss (+invalid-json) |
| purodelphi/mcpfirebird | 2 | reflected-xss |
| dmontgomery40/meta-mcp-server | 1 | path-traversal |
| i-tozer/excalidraw-mcp | 1 | temp-file leak |
| jae-jae/fetcher-mcp | 1 | resource-exhaustion (budget; robustness, not security-class) |
| jpisnice/shadcn-ui-mcp-unofficial | 1 | reflected-xss |
| makafeli/n8n-workflow-builder | 1 | reflected-xss |
| pinkpixel-dev/MCPollinations | 1 | reflected-xss |
| ruan11223344/McpDocServer | 1 | reflected-xss |

**Two levers, both validated:**
- **New reflected-output (XSS) oracle → 7 of 11 recoveries** (`reflected_output`
  fired 21× across the corpus; 18 high-confidence). The blind-spot fix works.
- **5× budget → 4 more** (path-traversal reached with deeper fuzzing, temp-file,
  a ReDoS/timeout on fetcher-mcp). Cache made re-selection free.
- `exfil` oracle: 0 fires on this set (present for future runs).

## Updated ToFu totals (full set_e2, with re-run)
| metric | before | after |
|---|---|---|
| real-vuln candidates | 600 | **627** |
| high-confidence (succ≥0.5) | 281 | **299** |
| repos with a candidate | 148 | **157** |
| reflected-xss class | 0 | **21 (18 hi)** |
| miss-set (others flagged, ToFu didn't) | 87 | **76** |

## Read for the paper
This is the empirical backing for the miss-analysis claim that ~63% of ToFu's
misses were fixable reachability/coverage gaps: a single re-run pass (one new
oracle + 5× budget, zero extra LLM cost thanks to the cache) recovered **11/27
= 41%** of a hard subset. Further recovery is available via schema-aware seeds
(the `-32602 Invalid arguments` gate) and provisioned backends — future work.
The recovered findings remain UNCONFIRMED candidates (hand-verification owed).
