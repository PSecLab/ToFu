# VIPER-MCP baseline (remote VM) — 2026-09-13

Sun et al. VIPER-MCP over the 39-repo host corpus. **Ran on a Linux VM** (40GB/
5CPU), gpt-4.1 for all agent roles, rounds=10, CodeQL 2.27.0. VIPER-MCP = CodeQL
taint (Phase I) + an LLM agent that fuzzes until an attacker value provably
reaches a sink at runtime (Phase II). Its taint model covers exactly 3 classes:
command injection, SSRF, path traversal.

## Run
```
unique repos : 38   ok 35   ERR 3
Phase II hook_injected : 18/35 (runtime confirmation live on the VM; was 0 in the laptop container)
```

## Confirmed vulnerabilities (Phase I CodeQL taint, report.json)
**12 vulns across 5 repos.** by type: ? 12

| repo | vulns | types |
|---|---|---|
| ArchimedesCrypto/excel-reader-mcp | 5 | {'?': 5} |
| aurda012/cursor10x-mcp | 3 | {'?': 3} |
| wonderwhy-er/DesktopCommanderMCP | 2 | {'?': 2} |
| aaronsb/google-workspace-mcp | 1 | {'?': 1} |
| jeanibarz/knowledge-base-mcp-server | 1 | {'?': 1} |

## "Runtime hits" are NOT findings
7 repos showed oracle hits (boilerplate 38, uml 28, bing-cn 3, ...), but those
are the runtime hook observing BENIGN tool I/O (fs.writeFileSync, https.request)
— 6 of the 7 have 0 Phase-I vulns. Only knowledge-base has both a taint vuln AND
runtime hits. Do NOT report oracle-hit counts as vulnerabilities.

## Cross-check vs ToFu confirmed findings — the disjoint-set case
| repo | Viper (taint) | ToFu (semantic) | overlap |
|---|---|---|---|
| excel-reader | 5x file-access-from-request (**READ**: readExcelFile) | V1 arbitrary **WRITE** (outputPath→writeFileSync) | **none — different sinks, same repo** |
| locallama | 0 | V2 log-injection + V3 unauth self-update | none |
| DesktopCommander | 2x command-injection (Phase I static) | — (ERR in ToFu env too) | — |

Viper's 12 findings are ALL taint-style (its 3 modeled classes). ToFu's confirmed
findings are semantic/logic (arbitrary write via type-correct path, unsanitized
log write, unauth self-update) — OUTSIDE any taint sink. **Zero overlap.** This is
the paper's complementarity thesis with data: a taint scanner and a
semantics-derived one fail on disjoint bugs.

## Exclusions (3 ERR — target transport, not Viper/harness bugs)
- appium: prints 'Waiting for client connections...' to STDOUT -> breaks Viper's
  JSON-RPC stdio parse (pydantic json_invalid).
- gmail-mcp: binds HTTP port 3000 -> not clean stdio.
- DesktopCommander: agent-init TaskGroup error at tool load (Phase I still ran ->
  its 2 static vulns above).

## Caveats
- REPRODUCIBILITY: Phase II runtime hook attaches on the native-Linux VM venv
  (18/35) but NOT in the laptop Docker/venv (0). Same code, host-dependent — state
  this. Phase I (CodeQL) is host-independent.
- Phase II did NOT runtime-confirm most Phase I findings (hits and static vulns
  barely overlap). Report Viper's result as its Phase-I taint output, noting
  Phase-II confirmation was partial.
- Corpus = same 39-repo host set as Cisco/CodeQL/ToFu for comparability.
