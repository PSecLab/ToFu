# UltimateCoderMCP — `tool_delete_path`: unrestricted arbitrary file/dir deletion (CWE-22 / CWE-73, destructive)

- **Project**: m-ahmed-elbeskeri/UltimateCoderMCP
- **Tools**: `tool_delete_path` (deletion), `tool_create_directory`, `tool_apply_patch`, `tool_write_file`, `tool_diff_files` — a filesystem-mutation ("coding agent") MCP server
- **Class**: arbitrary path deletion / write outside any root — no path confinement
- **Status**: POTENTIAL, but **DEMONSTRATED LIVE** (see below)
- **Severity**: Critical — an MCP client (or adversarial content steering one) can delete or overwrite any path the server process can reach

## Summary
`tool_delete_path` deletes a caller-supplied path with no confinement to a
project root and no allowlist. Given a traversal / absolute / `.`-relative path
it removes files and directories anywhere the server's user can write.
`tool_create_directory` and `tool_write_file` have the same shape (create/write
anywhere), and `tool_apply_patch` edits arbitrary files.

## How we know it's real (not a static guess)
On 2026-09-18 this tool **destroyed the ToFu evaluation host's working tree
during fuzzing**. ToFu runs each target with `cwd` = the harness repo root
(item 91, cwd isolation not yet landed). When the fuzzer drove
`tool_delete_path` (and `tool_create_directory`) with adversarial path payloads,
the server deleted files *relative to that cwd*: it wiped `eval/configs/` (5830
generated configs), the `.venv`, and 116 tracked repo files, and created
directories with the literal fuzz-payload names (path-traversal strings,
`...; rm -rf /tmp...`). The run's own index shows the exact order:

```
m-ahmed-elbeskeri/UltimateCoderMCP :: tool_apply_patch       ok=True
m-ahmed-elbeskeri/UltimateCoderMCP :: tool_create_directory  ok=True   <- junk dirs
m-ahmed-elbeskeri/UltimateCoderMCP :: tool_delete_path       ok=False  <- tree deleted
<every subsequent config> :: FileNotFoundError (configs gone)
```

That is a runtime proof of unrestricted deletion/creation: the tool did exactly
what the class predicts, on a real host, unprompted beyond fuzz input.

## Why this matters for MCP
An MCP server exposing delete/write/patch tools with no path confinement is a
destructive primitive for any agent that can be steered by untrusted content
(prompt injection, a poisoned document, a malicious tool result). The same tool
that erased our harness erases a user's home directory. This is the file-write/
delete analogue of `mcp-python-interpreter`'s unsandboxed exec (V7).

## Suggested fix (for the maintainer)
Confine every path to an explicit project root: resolve to an absolute real
path and reject anything outside the configured root; refuse `..`, absolute
paths, and symlinks that escape; require explicit opt-in for deletion.

## Note for ToFu (item 91)
This is also the trigger that proved item 91 must land before any further
corpus run: targets must fuzz in a per-config scratch cwd with no access to the
harness tree. Fix filed; re-run is gated on it.
