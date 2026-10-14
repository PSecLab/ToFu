# wonderwhy-er/DesktopCommanderMCP — full-filesystem-access-by-default + process/host hazard (CWE-284 / CWE-16, and an alert-volume-vs-truth exemplar)

- **Project**: wonderwhy-er/DesktopCommanderMCP (aka ClaudeComputerCommander / ClaudeDesktopCommander — the repo was renamed; all three names appear in our indices)
- **Tools**: `create_directory`, `list_directory`, `read_file`, `move_file`, `edit_block` (filesystem); `start_process`/`interact_with_process`/`read_process_output`/`kill_process`/`force_terminate`/`list_processes` (process control); `get_config`/`set_config`
- **Class**: OS-control MCP that ships **`allowedDirectories: []` = full filesystem access by default** (server.ts:346) + unrestricted local process spawning
- **Status**: NOT a promoted ToFu finding — its high alert volume was **triaged FP (documented)**. Kept as a **methodology exemplar**, not a vuln claim.
- **Severity (as deployed)**: High capability, but by design; the honest angle is the default config + the operational hazard, not a silent bug.

## Why the user flagged it (and why it belongs with UltimateCoderMCP / tmux-mcp)
It is the third OS-control server that made itself felt on the eval host, but it
plays a **different role in the paper** than the other two: those two are
demonstrated-live destructive bugs; this one is the **"alert volume is not a
proxy for vulnerabilities"** case, plus an operational-safety datapoint.

## What ToFu observed (traceable)
`findings/evidence/sandbox_triage_20260912/index.jsonl` (committed):

| tool | ok | secs | finding_hits | sanitizers |
|---|---|---|---|---|
| `create_directory` | true | 459 | **817** | check_path_traversal |
| `list_directory` | true | 507 | **324** | check_path_traversal, check_process_and_fd_leaks |
| `get_recent_tool_calls` | true | 474 | 54 | check_process_and_fd_leaks, check_resource_exhaustion |
| `interact_with_process` | true | 370 | 26 | check_process_and_fd_leaks |
| `get_config` | true | 480 | 1 | check_resource_exhaustion |

Real alert lines (`..._create_directory.log`):
```
EXEC_SUMMARY tool=create_directory ... success_rate=1.000
Faulty Input : {'path': '..\\..\\..\\..\\windows\\win.ini'}
Analysis     : Silent Bug Alert: Sanitizers ['check_path_traversal'] flagged this
               input as malicious, but the target tool executed successfully
               without raising any exception.
```
817 such alerts on one tool — the traversal string is accepted and acted on.

## Why it is a FALSE POSITIVE (the point)
`findings/sandbox_triage_20260912.md` adjudicated it:
> createDirectory DOES call validatePath, but default `allowedDirectories: []` =
> "full access" per server.ts:346. Traversal is the intended default for an
> OS-control tool, not a bug.

So the tool's **documented semantics permit** the operation. This fails
promotion **condition 1 (Role)** in casestudy.tex: the input is not "dangerous
for the specific argument judged against the tool's documented semantics." 817
raw oracle hits → **0 promoted findings**. This is the cleanest corpus example of
why alert volume must be triaged against documented meaning, and why every
candidate is confirmed by reading the sink.

## Three-way disagreement (nice for the eval)
- **ToFu**: 817 path-traversal alerts (raw oracle fires; correctly unpromoted).
- **vanilla-claude-sonnet-5**: cleared **every** tool (`create_directory ->
  clear | guarded`, others `no-sink`/`read-only-query`) — an LLM audit that
  reaches "not a vuln" but for the wrong reason (it calls the write "guarded";
  the write is not guarded, it is full-access-by-config).
- **Human triage**: FP-**documented** — right conclusion, right reason.
Same verdict, three different routes; only the sink-read triage is correct on the
reasoning, which is the argument for ToFu's role+action+effect promotion gate.

## Operational hazard (why it is on the unsafe-skip list)
DesktopCommander is on `Benchmarks/extraction/set_e2_unsafe_repos.txt` under all
three name variants. Its process-control tools (`start_process`,
`interact_with_process`, `kill_process`, `list_processes`) spawn and manage local
OS processes; under fuzzing they spiked the eval host's load and the corpus
campaign had to be stopped, which is why the repo is skipped. In the final
`runs.gpt41-corpus` index only the **9 benign tools** ran (the process/host-impact
tools are excluded by the unsafe-skip mechanism).

> **Evidence caveat (CLAUDE.md 3):** the exact host load figure I reported
> verbally during the incident is **not** in a committed log — only the
> unsafe-skip-list membership and the 09-12 sandbox evidence above are traceable.
> State the incident qualitatively (host-load spike during fuzzing → repo
> skipped), not with a specific loadavg number.

## Paper value
1. **Alert-volume-vs-truth exemplar** for sec:casestudy / RQ2: 817 raw alerts, 0
   promoted, because the tool documents full access — the counter-example that
   proves the promotion gate does real work.
2. **Operational-safety / isolation motivation** (item 91): OS-control servers
   require cwd + env + process isolation and an unsafe-skip list; DesktopCommander
   is why the skip list exists alongside UltimateCoderMCP (FS delete) and tmux-mcp
   (session kill).
3. **Default-config threat**: `allowedDirectories: []` = full access is a
   ship-it-insecure default; worth a sentence in the discussion even though it is
   not a ToFu silent-bug finding.
