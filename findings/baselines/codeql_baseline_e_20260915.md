# CodeQL security-extended baseline — Set E — 2026-09-15

Stock CodeQL (CLI 2.27.0) `security-extended` suite over **Set E (300 repos,
large random sample)**. STATIC ONLY: `codeql database create --build-mode=none`
reads source, never executes a tool -> ran on the host, no Docker. Source =
prepared target when present, else blobless shallow clone at the pinned commit
(deleted after analysis). DISTINCT from Viper Phase I (Viper's 3 custom taint
queries); this is off-the-shelf SAST = "what stock static analysis finds".

Index: `eval/state/codeql_runs_e.jsonl` (append-only, resumable).

## Result
```
repos analyzed : 299 ok / 300 attempted
repos flagged  : 171
total findings : 5361   (python 3008 | node 2353)
lang split(ok) : node 170 | python 129
failures       : 1
```
The 1 failure = `n8n-io/n8n` — `database analyze` exceeded the 900s
`CODEQL_DB_TIMEOUT` (n8n is a massive Node monorepo). Recorded `ok:false` in the
index, run continued. Zero clone failures: the 2026-09-15 blobless-shallow clone
fix (`--depth 1 --filter=blob:none`, try/except skip-on-timeout) cleared the
pollinations/pollinations 120s hang that crashed the prior run.

### Findings by rule (top 15)
| rule | n |
|---|---|
| py/log-injection | 1262 |
| js/insecure-temporary-file | 610 |
| py/path-injection | 495 |
| py/stack-trace-exposure | 444 |
| py/clear-text-logging-sensitive-data | 352 |
| js/log-injection | 270 |
| js/file-access-to-http | 268 |
| js/file-system-race | 247 |
| py/incomplete-url-substring-sanitization | 129 |
| js/http-to-file-access | 120 |
| js/incomplete-sanitization | 58 |
| py/overly-permissive-file | 55 |
| js/remote-property-injection | 48 |
| js/polynomial-redos | 47 |
| js/clear-text-logging | 45 |

### Repos with >=1 finding (top 20)
| repo | findings |
|---|---|
| IBM/mcp-context-forge | 748 |
| derisk-ai/derisk | 610 |
| NPC-Worldwide/npcpy | 330 |
| cagostino/npcpy | 330 |
| 1mcp-app/agent | 265 |
| cline/cline | 235 |
| jonathan-politzki/your-memory | 225 |
| microsoft/playwright | 113 |
| trycua/cua | 112 |
| VeriTeknik/pluggedin-mcp-proxy | 104 |
| freshtechbro/Vibe-Coder-MCP | 92 |
| freshtechbro/vibe-coder-mcp | 92 |
| upstash/context7 | 85 |
| upstash/context7-mcp | 85 |
| inclusionAI/AWorld | 79 |
| aarora79/mcp-gateway | 70 |
| ThreatFlux/YaraFlux | 69 |
| volcengine/ai-app-lab | 67 |
| taylorwilsdon/google_workspace_mcp | 59 |
| cjo4m06/mcp-shrimp-task-manager | 58 |

Note: several rows are the same code twice — `NPC-Worldwide/npcpy` &
`cagostino/npcpy` (fork, identical 330), `upstash/context7` &
`context7-mcp`, `freshtechbro/Vibe-Coder-MCP` & `vibe-coder-mcp` (case). Corpus
fork/dup artifacts, not double-counting within one repo. TO DOUBLE-CHECK before
any per-repo paper claim: dedup forks.

## Read for the paper (disjoint-set / precision argument)
- **The two dominant rules are the two families ToFu confirmed:**
  `py/log-injection` (1262) = V2 CWE-117; `py/path-injection` (495) = V1 CWE-73.
- CodeQL flags the **family** across the whole tree (any tainted path/log), but
  cannot decide the **semantic** property ToFu tests: *does the tool accept the
  adversarial input and still return success?* 5361 flags is a triage burden, not
  a set of confirmed exploitable MCP-tool bugs.
- **Cross-tool disjointness holds:** excel-reader-mcp (ToFu V1) is not in the
  CodeQL top list; CodeQL's top repos (IBM/mcp-context-forge 748, derisk 610) are
  not ToFu findings. Each instrument surfaces a different population.
- **Python coverage inverted vs ToFu:** static CodeQL analyzed 129 Python repos
  fine (no runner needed); ToFu's *dynamic* Python arm is broken (item 86), so on
  the same corpus ToFu currently under-measures exactly where CodeQL finds the
  most (py/log-injection, py/path-injection). Fixing the PythonRunner is where
  ToFu would most directly contest CodeQL's Python findings.
