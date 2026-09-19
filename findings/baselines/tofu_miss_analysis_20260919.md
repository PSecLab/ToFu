# Why ToFu missed vulnerabilities other tools found — set_e2 (2026-09-19)

Scope: the full set_e2 corpus run (`runs.gpt41-corpus.jsonl`, 479 repos ToFu
covered) vs CodeQL (`codeql_runs_e2.jsonl`) and Cisco (`cisco_runs.jsonl`). All
numbers trace to those indices + per-config logs under `eval/runs/gpt41-corpus/`.
Repo names lowercased for matching. "ToFu flagged" here = any row with ok=true ∧
finding_hits>0 (207 repos; NOTE this includes the always-on mandatory sanitizer
layer, CLAUDE.md §2 — the security-class-only count is 148, see the comparison doc).

## Set sizes
| set | size |
|---|---|
| ToFu covered (any row) | 479 |
| ToFu flagged (finding_hits>0) | 207 |
| CodeQL flagged (n_findings>0) | 154 / 482 |
| Cisco flagged | 50 / 482 |
| flagged union (CodeQL ∪ Cisco) | 177 |
| **MISS-A** — others flagged, ToFu ran, found nothing | **87** |
| **MISS-B** — others flagged, ToFu never ran | **2** |

MISS-A = 66 CodeQL-only + 13 Cisco-only + 8 both.
MISS-B = `wonderwhy-er/desktopcommandermcp`, `wonderwhy-er/claudedesktopcommander`
— both on `set_e2_unsafe_repos.txt` (host-control, intentionally not fuzzed). Not
a capability failure.

## Why the 87 MISS-A repos found nothing (dominant reason per repo)
- **(a) in-process discovery fail (item 94): 7 repos** — `taxuspt/garmin_mcp`
  (150 tools, all "could not find callable"), `teradata/mcp-server` (47),
  `teradata/teradata-mcp-server` (47), `doobidoo/mcp-memory-service` (28),
  `ttiimmaacc/cinema4d-mcp` (25), `xzq-xu/jvm-mcp-server` (19),
  `reminia/zendesk-mcp-server` (7). The Python in-process runner can't locate the
  server object → 0 executions.
- **(b) not-executable: 32 repos** — startup crash/hang 7 (`playcanvas/editor-mcp-server`
  + `playcanvas/mcp-editor` JS SOCKET_READY hang, 124 tools each; `aptro/superset-mcp`
  Python import crash, 60 tools; …), transport/timeout 10, credential/backend-gated
  15 (`royshil/obs-mcp` "Not connected to OBS", `tsmztech/mcp-server-salesforce`, …).
- **(c) executed-but-no-oracle-hit: 10 repos** — the genuine misses (see below).
- **(d) reached tool, every input turned away: 38 repos** — schema-gated 14
  (`mrkooblu/semrush-mcp` all 77 tools `-32602 Invalid arguments`; …), format-gated 9
  (`jfrog/mcp-jfrog` 28/31 tools "Invalid URL"; `cline/linear-mcp` 21/22), backend/
  state-gated 15 ("connect_db first", "STRAVA_ACCESS_TOKEN missing").

Mechanistic split (87 repos): **never reached tool code 24** (discovery 7 +
startup 7 + transport 10); **reached tool, gated at input/env boundary 53**
(credential 15 + schema 14 + format 9 + other 15); **drove tool to a sink,
oracle silent 10**.

**Only 100 of 1,622 MISS-A configs (6.2%) ever completed a successful tool call**
(corpus-wide: 1,580/6,153 = 25.7%). The overwhelming reason ToFu reports nothing
is that it rarely drives the tool to its sink — not that the oracle is weak.

## Genuine misses (category c): CodeQL class + why ToFu's oracle stayed silent
True blind spots — no ToFu oracle for the class:
- `garoth/wolframalpha-llm-mcp` — `js/incomplete-hostname-regexp`, `missing-regexp-anchor` (regex *correctness*; nothing to fire at runtime).
- `hyperdrive-eng/mcp-nodejs-debugger` — `js/remote-property-injection` (no prototype-pollution oracle).
- `jae-jae/fetcher-mcp` — `js/xss-through-exception` (no HTML/output-encoding oracle).
- `jpisnice/shadcn-ui-mcp-unofficial` — `js/bad-tag-filter`, `cors-permissive`, `file-system-race` (config/TOCTOU; no runtime oracle).
- `simonb97/win-cli-mcp-server` — Cisco-YARA only: flags the command-exec *capability*; running commands is the tool's purpose, so no sanitizer violation.

Oracle-present, sink-not-reached (reachability misses):
- `obra/private-journal-mcp` — `js/clear-text-logging`; ToFu's sensitive-data-logging oracle fired 124× elsewhere but the journal inputs weren't driven as secrets here.
- `dmontgomery40/meta-mcp-server`, `peakmojo/applescript-mcp` — `js/insecure-temporary-file`; temp-file path not exercised.
- `makafeli/n8n-workflow-builder` — `clear-text-logging` (oracle exists) + `file-access-to-http` (exfil dataflow, no oracle).

## The key fraction (n=87 repos)
- **55 (63%) — reachability/coverage gap ToFu could fix**: it has a matching
  oracle for ≥1 flagged class and missed only because it never reached the sink
  (discovery/startup/transport failure, or schema/credential/format gate).
- **19 (22%) — true methodological blind spot**: CodeQL flagged *only* classes
  ToFu has no oracle for (TOCTOU file-system-race, XSS, CORS, prototype/property
  injection, regexp/sanitization correctness, missing-rate-limiting, exfil dataflow).
- **13 (15%) — Cisco-YARA static-capability signatures** a runtime fuzzer can't "hit".

Per CodeQL finding (n=381 on MISS-A repos): 196 (51%) oracle-covered (reachability)
vs 181 (48%) no-oracle (blind spot). Blind-spot classes are finding-dense
(file-access-to-http 57, file-system-race 45), so per-finding it's ~50/50 even
though per-repo it's ~63/37.

## Bottom line for the paper
~**60–65% of ToFu's misses are infrastructure/coverage gaps it could plausibly
fix** — dominated by item-94 in-process-discovery (323 configs incl. garmin's 150),
JS startup hangs, and the fact only 6% of miss configs reach a successful tool
call (schema/credential/format gating). The **irreducible methodological blind
spot is ~35–40% of repos (~48% of findings)**: classes with no runtime oracle
(races, XSS, CORS, prototype pollution, regexp/sanitization correctness, dataflow
exfil) + Cisco's static capability flags.

## Caveats
- "Could fix" is optimistic: converting a reachability miss into a finding still
  needs schema-valid inputs + provisioned backends/credentials (themselves hard).
- finding_hits>0 (207) includes the mandatory-sanitizer layer (CLAUDE.md §2, not
  subtracted here) — MISS-A could *understate* true LLM-selection-design misses.
- Fixes that would recover the most: (1) item-94 PythonStdioRunner fallback
  (biggest single lever), (2) schema-aware seed generation to clear `-32602`
  input gates, (3) format-valid seeds (URLs, xlsx, valid SQL) for format-gated sinks.
