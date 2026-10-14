# CodeQL security-extended baseline — 2026-09-12

Stock CodeQL (CLI 2.27.0) `security-extended` suite over the prepared targets.
STATIC ONLY: `codeql database create --build-mode=none` reads source, never
executes a tool -> ran on the host, no Docker. DISTINCT from Viper Phase I
(Viper's 3 custom taint queries); this is off-the-shelf SAST.

## Result
```
repos analyzed : 39 ok / 39 attempted
repos flagged  : 20
total findings : 309
```
(An earlier paste showed 41/320 — the resumable index had double entries
for mindmap-mcp-server and uml-mcp; deduped to 39 unique repos / 309 findings.)

### Findings by rule (top)
| rule | n |
|---|---|
| js/file-access-to-http | 134 |
| js/file-system-race | 54 |
| js/insecure-temporary-file | 33 |
| js/log-injection | 18 |
| js/http-to-file-access | 11 |
| js/incomplete-sanitization | 7 |
| py/incomplete-url-substring-sanitization | 5 |
| js/insecure-randomness | 4 |
| py/log-injection | 4 |
| js/missing-rate-limiting | 3 |
| js/clear-text-logging | 3 |
| js/indirect-command-line-injection | 3 |
| js/prototype-polluting-assignment | 3 |
| js/incomplete-multi-character-sanitization | 3 |
| js/double-escaping | 3 |

### Repos with >=1 finding
| repo | findings |
|---|---|
| VeriTeknik/pluggedin-mcp-proxy | 104 |
| jeanibarz/knowledge-base-mcp-server | 41 |
| wonderwhy-er/DesktopCommanderMCP | 28 |
| yctimlin/mcp_excalidraw | 21 |
| b-open-io/bsv-mcp | 20 |
| krzko/google-cloud-mcp | 20 |
| aaronsb/google-workspace-mcp | 17 |
| Heratiki/locallama-mcp | 11 |
| antoinebou12/uml-mcp | 11 |
| PuroDelphi/mcpFirebird | 9 |
| aashari/boilerplate-mcp-server | 5 |
| thomasgazzoni/vsc-mcp | 4 |
| bhouston/mcp-server-text-editor | 4 |
| circleci-public/mcp-server-circleci | 4 |
| square/square-mcp-server | 2 |
| scorzeth/anki-mcp-server | 2 |
| jagan-shanmugam/osm-mcp-server | 2 |
| tumf/mcp-text-editor | 2 |
| tubone24/midi-mcp-server | 1 |
| aurda012/cursor10x-mcp | 1 |

## Cross-check vs ToFu confirmed findings
| repo | CodeQL | ToFu confirmed | verdict |
|---|---|---|---|
| ArchimedesCrypto/excel-reader-mcp | 0 (none) | V1 arbitrary file write | ToFu-only (CodeQL missed it) |
| Heratiki/locallama-mcp | 11 (js/missing-rate-limiting, js/clear-text-logging, js/file-system-race, js/http-to-file-access, js/indirect-command-line-injection) | V2 log injection + V3 update_server | both flag repo, DIFFERENT issues |

## Reading
- CodeQL fires on TAINT/QUALITY classes: file-access-to-http (134),
  file-system-race (54), insecure-temporary-file (33), log-injection (18).
- **excel-reader: CodeQL 0 findings**, yet ToFu confirmed arbitrary file
  write (V1). Stock SAST has no sink for an unconstrained tool-output path.
- **locallama: CodeQL 11**, but they are clear-text-logging / file-system-race /
  indirect-command-line-injection — NOT ToFu's V2 (unsanitised log write) or
  V3 (unauth self-update). Same repo, disjoint issues.
- Same complementarity thesis as Cisco: CodeQL/Cisco vs ToFu fail on disjoint
  bug classes; counts are NOT a leaderboard.

## Caveats for the paper
- security-extended includes quality rules (file-system-race, missing-rate-
  limiting); if only security is wanted, re-run with the `security` suite.
- DB built with build-mode=none over repo source (node_modules included by
  CodeQL as library code); findings are in first-party files.
- Corpus = the 41 prepared (host) targets; same set as Cisco for comparability.
