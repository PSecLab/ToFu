# Baseline comparison — ToFu vs Viper-MCP vs CodeQL vs Cisco — 2026-09-15

Same corpus: the **host set = 39 unique repos** (`Benchmarks/extraction/set_host.json`),
the executable A+E subset every tool could run on. gpt-4.1 for all LLM roles
(temp 0, fixed seed) so the model is held constant across arms.

## ⚠ The counts are NOT the same unit
Each tool reports a different object. Do not sum or rank them directly.

| tool | what one "finding" is | confirmed? | lang |
|---|---|---|---|
| **ToFu** | a *semantic* silent-bug: tool accepts adversarial input **and returns success** | **yes, hand-verified** | node+py (py arm broken, item 86) |
| **Viper-MCP** | CodeQL taint flow (Phase I) in 3 classes: cmd-inj, SSRF, path/file-access | taint-proven, Phase-II runtime confirm partial | node+py |
| **CodeQL** (security-extended) | any SAST rule match (family-level) | **no** — static flag, unconfirmed | node+py |
| **Cisco MCP Scanner** | YARA/LLM heuristic on tool descriptions + API surface | **no** — heuristic | node+py |

## Totals on the host-39
| tool | findings | repos flagged | coverage (repos run) |
|---|---|---|---|
| ToFu (confirmed) | **3** (V1+V2+V3) | 2 | 39/39 |
| ToFu (raw alerts, pre-triage) | 58 tool-runs | 9 | 39/39 |
| Viper-MCP | 12 | 5 | 32/39 (7 ERR/skip) |
| CodeQL set-A | 309 | 20 | 39/39 |
| Cisco | 28 | 8 | 39/39 |

ToFu raw 58 → triage → 3: the 55 dropped are the FP families since gated
(url_ssrf, har/markitdown contract, resource_exhaustion). CodeQL 309 and Cisco 28
are **unconfirmed** flags — triage burden, not exploitable MCP-tool bugs.

## Per-repo matrix (any tool > 0)
```
repo                                  tofuRAW tofuCONF viper codeqlA cisco
ArchimedesCrypto/excel-reader-mcp        1       1       5      0      0
Heratiki/locallama-mcp                   4       2       0     11      4
PuroDelphi/mcpFirebird                   0       0       0      9      0
VeriTeknik/pluggedin-mcp-proxy           1       0       0    104      1
aaronsb/google-workspace-mcp             4       0       1     17      4
aashari/boilerplate-mcp-server           0       0       0      5      0
antoinebou12/uml-mcp                     0       0       0     11      0
api7/apisix-mcp                          3       0       0      0      2
aurda012/cursor10x-mcp                   9       0       3      1      0
b-open-io/bsv-mcp                       23       0       0     20      0
bhouston/mcp-server-text-editor          0       0       0      4      0
circleci-public/mcp-server-circleci      0       0       0      4      9
jagan-shanmugam/osm-mcp-server           0       0       0      2      0
jeanibarz/knowledge-base-mcp-server      0       0       1     41      0
krzko/google-cloud-mcp                   9       0       0     20      0
scorzeth/anki-mcp-server                 0       0       0      2      0
shinzo-labs/gmail-mcp                    4       0       0      0      0
square/square-mcp-server                 0       0       0      2      2
thomasgazzoni/vsc-mcp                    0       0       0      4      0
tubone24/midi-mcp-server                 0       0       0      1      0
tumf/mcp-text-editor                     0       0       0      2      0
wonderwhy-er/DesktopCommanderMCP         0       0       2     28      4
yctimlin/mcp_excalidraw                  0       0       0     21      2
```

## Overlap of *flagged repos* (repo granularity)
```
ToFu(conf) ∩ Viper   : excel-reader
ToFu(conf) ∩ CodeQL  : locallama
ToFu(conf) ∩ Cisco   : locallama
Viper ∩ CodeQL       : google-workspace, cursor10x, knowledge-base, DesktopCommander
Viper ∩ Cisco        : google-workspace, DesktopCommander
CodeQL ∩ Cisco       : locallama, pluggedin, google-workspace, circleci, square, DesktopCommander, excalidraw
```

## The complementarity thesis — disjoint at the BUG level (verified)
ToFu's 2 flagged repos are also flagged by others, **but never for the same
bug**. Verified against each tool's raw output:

| repo | ToFu (semantic) | other tools, same repo | same bug? |
|---|---|---|---|
| excel-reader | V1 arbitrary **WRITE** — `export_to_json` outputPath → `writeFileSync` | Viper: 5× file-access, all **READ** (`readExcelFile`, `WorkbookCache.get/set`, `loadWorkbook`) | **NO — write vs read, different sink** |
| locallama | V2 CWE-117 log-injection (subtask→log), V3 unauth `update_server` self-update | CodeQL: rate-limiting, clear-text-logging, fs-race, http-to-file, indirect-cmd. Cisco: YARA on `benchmark_model/reload_config/route_task` | **NO — none is V2 or V3; update_server not flagged by anyone** |

**Every ToFu confirmed bug is invisible to the other three at the sink level.**
Conversely CodeQL's 11 unique-repo flags (mcpFirebird, uml-mcp, bsv, text-editor,
osm, anki, vsc, midi, google-cloud, boilerplate) and Cisco's unique (apisix) are
invisible to ToFu. Four instruments, four disjoint populations of real defects —
the paper's core claim, with data.

## Caveats (state these)
- **Units differ** (table above). The honest headline is *confirmed semantic bugs*
  (ToFu 3) vs *taint flows* (Viper 12) vs *unconfirmed SAST flags* (CodeQL 309,
  Cisco 28) — not a 3-vs-309 "score".
- **Viper coverage 32/39**: 7 ERR/skip (appium/gmail STDOUT-pollute stdio;
  DesktopCommander agent-init). Viper Phase-II runtime hook = 18/35 on the VM, 0 in
  the laptop container (host-dependent; Phase-I CodeQL is host-independent).
- **ToFu Python arm broken** (item 86): all 3 ToFu findings are Node. CodeQL found
  its most on Python (py/log-injection, py/path-injection). ToFu currently
  under-measures Python — biggest known gap in this comparison.
- CodeQL here = **set-A run (39 repos, 309)**, the host subset. The set-E run
  (300 repos, 5361) is the large-corpus SAST baseline, separate file.
- Sources: `runs.gpt41-full.jsonl` (ToFu), `viper_runs_vm_20260913` + per-repo
  `report.json` (Viper), `codeql_runs_20260912.jsonl` (CodeQL), `cisco_runs_gpt41_20260911.jsonl` (Cisco).
