# V4 (potential) — tumf/mcp-text-editor `get_text_file_contents`: unrestricted absolute-path read serves `/etc/passwd` and the server's own `/proc/self/environ`

**Status: POTENTIAL.** First finding from the Python arm (item 86 fix, 2026-09-15).
Classification is argued below; the maintainers may consider "reads any file" by
design. What is NOT by design: the code ships a `base_dir` sandbox that no code
path ever enables, and the tool will read the MCP server process's own
environment — including whatever API keys the host handed it — and return it
as a successful tool result.

| | |
|---|---|
| repo | tumf/mcp-text-editor (113 stars) |
| commit | `2d66b6fa1cf1ab1241b90e8bc71ece19adc615f2` |
| tool | `get_text_file_contents` |
| weakness | CWE-552 (files accessible to external parties) / CWE-200 via `/proc/self/environ`; CWE-22 family |
| oracle | LLM-selected `check_introspection_sensitive_file_access` (introspection tracer, Python arm) + mandatory `check_file_access` |
| run | sandbox (Linux, py3.13), gpt-4.1 temp 0 seed 20260910, 60 s, `eval/sandbox/runs/smoke86/tumf__mcp-text-editor__get_text_file_contents.fuzz.log` (redacted) |

## What ToFu observed (traceable to the log above)
```
EXEC_SUMMARY tool=get_text_file_contents n_exec=80896 n_success=5885 success_rate=0.073
libFuzzer: cov 60 -> 64, corp 7 -> 11, ~1344 exec/s
alerts: 2740
  1225x  /etc/passwd            SUCCESS, content served ("root:x:0:0:root:/root:/bin/bash\n...")
  1105x  /proc/<pid>/environ    SUCCESS, the fuzzer process's full environment served
                                (PATH, HOME, TOFU_LLM_*, OPENAI_API_KEY=<redacted>, ...)
  + mutations that still resolve ("/etc/passwdᘕ" x16 is rejected; "/proc/sel/environ" etc. are ENOENT)
Sanitizers selected by the LLM: ['check_path_traversal',
  'check_introspection_sensitive_file_access', 'check_introspection_symlink_following']
```
Input that produced the environ disclosure:
```json
{"files": [{"file_path": "/proc/self/environ", "ranges": [{"start": 1}]}], "encoding": "ascii"}
```
Evidence (redacted excerpt): `findings/evidence/mcp-text-editor-get_text_file_contents-proc-environ.redacted.log`

## Why this is more than "a text editor reads files"
1. `src/mcp_text_editor/utils.py::normalize_and_validate_path(file_path, base_dir=None)`
   implements a strict sandbox (no absolute paths, no traversal, `relative_to(base)`)
   **when `base_dir` is given** — but no caller in `server.py`, `handlers/*.py` or
   `text_editor.py` ever passes it, and there is no env/config knob
   (`_validate_environment()` is a stub: "Future: Add environment validation if
   needed"). The restriction exists and is dead. With `base_dir=None` absolute
   paths are explicitly allowed.
2. The README's only mitigation is "Proper file system permissions should be set to
   restrict access to authorized directories" — i.e. the OS. `/etc/passwd` is
   world-readable everywhere; `/proc/self/environ` is always readable by the
   process itself.
3. Threat model of an MCP server: the caller is an LLM agent that processes
   untrusted content. A prompt-injected agent asking for
   `/proc/self/environ` receives the MCP host process's secrets (API keys,
   tokens) as ordinary tool output. ToFu demonstrated exactly this: the served
   environment contained the fuzzer's own OpenAI key (redacted in evidence;
   key rotated). No traversal trick is needed — the path is absolute and valid.
4. Semantic silent-success: the tool returns `isError: false` with content for
   these paths. This is the class ToFu's oracle is built for; a static scanner
   sees a `read_file(path)` sink with a validated path and stops.

## Why it is only POTENTIAL
- Reading arbitrary files is the tool's advertised purpose; a maintainer may reply
  "run it with restricted OS permissions". The concrete, non-obvious harm is the
  self-environment disclosure (item 3) and the dead `base_dir` sandbox (item 1).
- Not yet reproduced outside the sandbox harness with a plain MCP client
  (`--test-input` reproduces it in-process; a stdio JSON-RPC repro is the next
  step before disclosure).
- No write primitive here (contrast V1); impact is confidentiality.

## Disclosure / next steps
- Repro over stdio with a standalone client, then report to the maintainer
  suggesting: wire `base_dir` (env `MCP_TEXT_EDITOR_BASE_DIR`) and deny `/proc`,
  `/dev`, `/sys` when unrestricted.
- Paper: first Python-arm finding. Attribution, carefully:
  `check_introspection_sensitive_file_access` WAS in the LLM's selection for
  this tool, but `fuzzer._run_sanitizers` gates every introspection check as
  `if "<check>" in selected or <tracer evidence present>`, so it would have
  fired unselected too (the FileAccessTracer recorded `/etc/passwd`). The
  `/proc/self/environ` alerts were raised by the mandatory `check_file_access`
  layer only. Neither alert is evidence FOR the LLM-selection design
  (attribution trap, HANDOFF §2; mechanism written up under V5 and in
  nazmul.todo 2026-09-15). The finding itself stands on the target's behaviour.
