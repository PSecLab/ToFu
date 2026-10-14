# CWE-915 -- (taxonomy extension) (1 findings: 1 Tier-A, 0 Tier-B)

vanilla-claude-sonnet-5 static audit, 2026-09-21. Grounded per Phase 2 (verify_findings.py). Static reading only, no execution.

| repo | tool | tier | cwe | file:line | param -> sink | why |
|---|---|---|---|---|---|---|
| aaronsb/google-workspace-mcp | `manage_scratchpad` | A | CWE-915 | `src/server/scratchpad/json-path.ts:54` | path -> setByPath (called from ScratchpadManager.jsonSet/jsonInsert in src/server/scratchpad/manager.ts on the JSON.parse()'d scratchpad buffer) writes params.value to a property resolved by walking the caller-supplied path segments with no denylist for '__proto__', 'constructor' or 'prototype'. | operation:'json_set' (or json_insert/json_delete) with path:'$.__proto__.<key>' on a format:'json' scratchpad reaches setByPath in src/server/scratchpad/json-path.ts. Because the intermediate object has no OWN '__proto__' data property (a fresh {} buffer), the bracket-access `current[String(segme... |
