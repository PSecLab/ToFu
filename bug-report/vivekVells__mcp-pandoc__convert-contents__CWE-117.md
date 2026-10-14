# `convert-contents` writes diagnostics to stdout with `print`; no log sink, so CWE-117 does not fit (likely misclassified)

**Repository:** `vivekVells/mcp-pandoc` · **Tool:** `convert-contents` · **Tested commit:** `7df0519`
**Weakness:** CWE-117 Improper Output Neutralization for Logs (reported by the fuzzer; not confirmed)

## Summary
`convert-contents` converts text or a file between formats with Pandoc. Our fuzzer flagged it for log injection. On review the server has no logging: `server.py` imports no `logging` module and emits diagnostics only with four `print()` calls (`src/mcp_pandoc/server.py`). Those prints go to stdout, which for this stdio server is the JSON-RPC channel, not a log file. So the CWE-117 label does not fit. Caller-controlled strings do reach the `print()` calls without neutralization, which we note below, and the tool reads and writes caller-named file paths with no containment, which is a more substantive concern than the one that was flagged.

## Details
The server runs over stdio (`src/mcp_pandoc/server.py:555-561`) and never configures logging. The only diagnostic output is `print()`:

- `src/mcp_pandoc/server.py:260-263`: prints `yaml_content['to']` (from the caller-named `defaults_file`) and `output_format` when they disagree.
- `src/mcp_pandoc/server.py:337`, `:339`, `:342`: print a resolved filter `path` (derived from a caller entry in `filters`).

```python
print(f"Using filter: {path}")
```

Because `print` writes to stdout and the MCP transport also uses stdout, any of these lines would corrupt the JSON-RPC stream rather than land in a log. There is no `\r`/`\n` neutralization, but there is no log sink either. A filter path only reaches the `print` at `:342` if the path exists and is executable; a non-existent filter instead raises `ValueError(f"Filter not found ...: {filter_path}")` (`:356`), which is returned to the client as the tool's error text, not logged.

Separately, `convert-contents` reads `input_file`, `reference_doc` and `defaults_file`, and writes `output_file`, from caller-supplied paths with no restriction to a base directory (`:224-225`, `:246`, `:417-449`). That matches the other two sanitizers that fired on this tool (`check_file_access`, `check_introspection_sensitive_file_access`) and is worth a hand-check as a path/file-access issue (CWE-22/CWE-73), separate from the CWE-117 label.

## Steps to reproduce
No run log survived, so this is derived from the code at `7df0519`.
1. Prerequisites: Python 3.11+, `uv`/`uvx`, Pandoc installed, and the `mcp` Python package for the client script.
2. Install and start as the README describes (`uvx mcp-pandoc`, stdio transport):

   ```bash
   git clone https://github.com/vivekVells/mcp-pandoc && cd mcp-pandoc
   git checkout 7df0519
   uv sync
   ```
3. A minimal successful conversion:

   ```json
   {"contents": "# tofu-poc", "input_format": "markdown", "output_format": "html"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["--from", "/path/to/mcp-pandoc", "mcp-pandoc"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("convert-contents", {"contents": "# tofu-poc", "input_format": "markdown", "output_format": "html"})
               print(result)

   asyncio.run(main())
   ```
4. To exercise the `print` path a hand-checker can supply a `defaults_file` whose `to:` differs from `output_format`, or an existing `filters` entry, and watch the server's stdout. Expect the printed line to interleave with JSON-RPC traffic rather than appear in a log.

## Expected behavior
Diagnostics go to a dedicated log stream (stderr or a logger), never to stdout on a stdio server, and caller-derived text is neutralized before it is written there.

## Actual behavior
Diagnostics are printed to stdout. No log file is written. We could not reproduce a log-injection sink.

## Impact
No log injection found. The `print`-to-stdout behavior is a protocol-correctness bug (it can break the JSON-RPC stream), not a security issue on its own. The unrestricted file read/write (`input_file`, `output_file`, `reference_doc`, `defaults_file`) is the part a maintainer should weigh: the LLM chooses these paths and prompt injection can steer them, so the tool can read or overwrite any file the server user can access unless the deployment confines it.

## Suggested fix
For the flagged behavior: replace `print()` with a `logging` logger that writes to stderr or a file, and escape CR/LF in any caller-derived field before logging. Separately, consider confining `input_file`/`output_file`/`reference_doc`/`defaults_file` to a configured base directory and rejecting paths that resolve outside it.

## Status on the default branch
The tested commit `7df0519` (2026-08-15) is the current head of the default branch, so the code above is unchanged.

## Prior reports
- #50 "[P2] Replace bare `print()` with stderr logging and tool-result warnings" (issue, open 2026-08-08): reports the same four bare `print()` calls and asks for `logging` to stderr. It also states they do not corrupt the protocol, because the MCP SDK re-points fd 1 at stderr, which contradicts this draft's claim that the prints go to the JSON-RPC stdout. Open, not fixed at `7df0519`.
- #44 "Tracking: gaps surfaced by an agent-driven document workflow (from #40)" (issue, open 2026-08-08): tracking epic that lists the bare `print()` diagnostics as child issue #50.
- #36 "[Security] Arbitrary File Read/Write vulnerability in convert-contents tool" (issue, open 2026-04-17): reports the unrestricted `input_file`, `output_file` and `filters` paths that this draft calls the more substantive concern (CWE-22, CWE-78). Details were withheld for private disclosure. Open, not fixed at `7df0519`.
- Documentation: docs/audits/2026-08-agent-workflow-audit.md: "They are not corrupting the protocol." (Finding 7, verified against the SDK source: `print()` lands on stderr. The same audit names arbitrary filesystem paths and user-supplied filter scripts as a known trust-boundary gap, explicitly out of scope, citing #36 and #33.)
- Documentation: AGENTS.md: "Never `print()` in `src/`." (the project's own rule, which these four calls break)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported. The `print()` diagnostics are #50 (open) and the file-path concern is #36 (open); neither is fixed. The maintainers' audit says the prints reach stderr, not the JSON-RPC stdout, so the draft's main technical claim is contradicted. Do not file.
- ToFu class / sanitizers: log-injection; triggered `check_file_access`, `check_introspection_log_injection`, `check_introspection_sensitive_file_access`.
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`; all of the above is derived from the code at `7df0519`.
- Hand-check hints: ToFu likely misclassified this. There is no `logging` sink in the server; the only output primitive is `print()` to stdout (confirmed: `import logging` is absent, 4 `print` calls). A log-injection write cannot be shown. The 0-success single call suggests the tool raised before producing output. The real, checkable issue is file read/write of caller paths with no base-dir restriction (fits `check_file_access` / `check_introspection_sensitive_file_access`); recommend refiling under CWE-22/CWE-73 if a maintainer confirms. Not executed here.
</details>
