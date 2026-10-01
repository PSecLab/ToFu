# `create_project` accepts CR/LF in `name` and echoes it unneutralized (no server-side log sink found)

**Repository:** `apvlv/davinci-resolve-mcp` · **Tool:** `create_project` · **Tested commit:** `d025e4e`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`create_project` takes a project `name` and passes it to Resolve's `ProjectManager.CreateProject`, then echoes it in the tool result. The name is not checked for control characters, so a name containing `\n` or `\r` is accepted as is. The MCP server itself does not write `name` to its log, so this is not a log injection in the server's own log. It is a missing input check whose effect depends on where Resolve and the MCP client later print the project name.

## Details
The tool hands `name` straight to Resolve and formats it into the reply (`src/davinci_resolve_mcp/server.py:247-265`):

```python
@mcp.tool()
def create_project(name: str) -> str:
    ...
    if not resolve_api.is_connected():
        return "Error: Not connected to DaVinci Resolve."

    success = resolve_api.create_project(name)
    if success:
        return f"Successfully created project '{name}'."
    else:
        return f"Failed to create project '{name}'. The project may already exist."
```

`ResolveAPI.create_project` (`src/davinci_resolve_mcp/resolve_api.py:174-192`) calls `self.project_manager.CreateProject(project_name)` at line 186 with no validation. The server configures a stderr logger (`server.py:14-18`), but no call in `server.py` or `resolve_api.py` logs `name`. There is no check that rejects or strips CR/LF or other control characters from a project name.

## Steps to reproduce
1. Prerequisites: Python 3.10+, `uv`, DaVinci Resolve running with its scripting API available (the tool returns `Error: Not connected to DaVinci Resolve.` otherwise).
2. Install and start as the README describes: `git clone https://github.com/apvlv/davinci-resolve-mcp.git && cd davinci-resolve-mcp && uv sync --all-extras --dev`, then the server runs with `uv run davinci-resolve-mcp`.
3. Call the tool with `{"name": "tofu-poc\r\nFAKE-LOG-ENTRY"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["run", "davinci-resolve-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_project", {"name": "tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the call is not rejected. The result text contains the raw CR/LF, and a project whose name contains a line break is created in (or offered to) Resolve's Project Manager. The server's stderr log has no line with the name.

## Expected behavior
Project names with CR, LF or other control characters are rejected (or the characters are stripped) before they reach `CreateProject` and the reply.

## Actual behavior
The name is passed through unchanged. During fuzzing Resolve was not running, so every call returned the early error and the name never reached `CreateProject`:

```
input:  {'name': 'project\nINFO: User admin logged in'}
output: 'Error: Not connected to DaVinci Resolve.'
```

## Impact
`name` is chosen by the LLM, which can be steered by prompt injection from content it reads. A crafted name could place a line break into anything that later prints project names line by line (Resolve's own logs or project lists, client transcripts). The MCP server's own log is not affected. Low severity, closer to input validation hardening than to a vulnerability.

## Suggested fix
Validate `name` in `create_project` (and the other name-taking tools such as `load_project`, `create_timeline`, `create_folder`): reject strings containing characters below `0x20` or `0x7f`, for example `if any(ord(c) < 0x20 or ord(c) == 0x7f for c in name): return "Error: invalid project name."`. If names are ever logged, log them with `%r`.

## Status on the default branch
Still present at `d025e4e` (2026-04-07). The default branch has no commits after the tested commit.

## Prior reports
None found. Searched the 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch (README.md, AGENTS.md, src/davinci_resolve_mcp/AGENTS.md).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection` only. This is the static input-pattern check ("flagged this input as malicious, but the target tool executed successfully"), not the introspection check that inspects captured log records. No `check_introspection_log_injection` fired.
- Campaigns and executions: `corpus-sbx` 3,584 execs / 3,584 success (60 s); `e2-0922` 1,024 / 1,024 (60 s).
- Evidence (verbatim, trimmed): `{'name': 'project\nINFO: User admin logged in'}` -> `'Error: Not connected to DaVinci Resolve.'`; `{'name': 'project\nERROR: Sensitive data: password=1234'}` -> same; `{'name': '"{dn@\n\x00'}` -> same.
- Hand-check hints: weak, likely a false positive for CWE-117; recommend not filing as log injection. Every call hit the `is_connected()` early return at `server.py:258-259`, so the input never reached any sink. "Success" here only means no exception. By code reading, the server never logs `name`; the only sinks are `CreateProject` (Resolve internals, unknown behavior) and the echoed reply string. I did not check whether the `mcp` SDK version pinned in `uv.lock` (1.26.0) logs tool arguments. Step 4 (what Resolve does with a newline in a project name) is not verified; Resolve may reject it. Reproduction derived from code; not run.
</details>
