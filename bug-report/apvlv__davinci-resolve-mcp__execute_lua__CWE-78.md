# `execute_lua` runs any caller-supplied Lua in Fusion, which allows OS command execution, with no opt-in

**Repository:** `apvlv/davinci-resolve-mcp` · **Tool:** `execute_lua` · **Tested commit:** `d025e4e`
**Weakness:** CWE-78 OS Command Injection

## Summary
`execute_lua` passes its `script` argument to `fusion.Execute()` with no filtering. Any Lua the caller sends runs inside Resolve's Fusion with the user's privileges, including Lua calls that start OS commands. The tool is always registered, so any MCP client connected to the server can do this. I understand this is an intended scripting feature (AGENTS.md calls `execute_python` a privileged surface), so this issue is about exposure by default rather than a parsing bug.

## Details
The tool forwards the string unchanged (`src/davinci_resolve_mcp/server.py:710-731`):

```python
@mcp.tool()
def execute_lua(script: str) -> str:
    ...
    if not resolve_api.is_connected():
        return "Error: Not connected to DaVinci Resolve."

    if not resolve_api.fusion:
        return "Fusion is not available."

    try:
        result = resolve_api.execute_lua(script)
        return str(result) if result is not None else "Script executed successfully."
```

`ResolveAPI.execute_lua` (`src/davinci_resolve_mcp/resolve_api.py:498-511`) ends in `return self.fusion.Execute(script)`. There is no allow-list, no confirmation, and no setting that turns the tool off. `execute_python` (`server.py:659-707`) has the same shape and calls `exec(code, globals(), local_namespace)` at line 686, which runs inside the MCP server process itself.

## Steps to reproduce
1. Prerequisites: Python 3.10+, `uv`, DaVinci Resolve running with its scripting API available and Fusion reachable (the tool returns `Error: Not connected to DaVinci Resolve.` otherwise).
2. Install and start as the README describes: `git clone https://github.com/apvlv/davinci-resolve-mcp.git && cd davinci-resolve-mcp && uv sync --all-extras --dev`, then the server runs with `uv run davinci-resolve-mcp`.
3. Call the tool with `{"script": "os.execute('echo tofu-poc > /tmp/tofu-poc.txt')"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["run", "davinci-resolve-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("execute_lua", {"script": "os.execute('echo tofu-poc > /tmp/tofu-poc.txt')"})
               print(result)

   asyncio.run(main())
   ```
4. Run `cat /tmp/tofu-poc.txt`. It contains `tofu-poc`, written by a shell that the Lua script started.

## Expected behavior
Arbitrary script execution is off unless the user turns it on explicitly, or scripts are limited to the Fusion API without `os`/`io` access.

## Actual behavior
The script is passed to `fusion.Execute()` unchanged. During fuzzing Resolve was not running, so every call returned the early error and no script ran:

```
input:  {'script': "os.execute('ls; cat /etc/passwd')"}
output: 'Error: Not connected to DaVinci Resolve.'
```

## Impact
The `script` argument is written by the LLM, and prompt injection from content the agent reads (a media file name, a web page, a document) can steer it. With Resolve open, that gives command execution on the user's machine with the user's privileges, through `execute_lua` or `execute_python`. The risk exists only while Resolve is running and the server is connected, and it follows from the feature's design. Users who add this server to a client may not expect that it exposes a general code runner.

## Suggested fix
Do not register `execute_lua` and `execute_python` unless an environment variable such as `DAVINCI_MCP_ENABLE_SCRIPTING=1` is set, and document the risk in the README next to the tool list. If Lua stays enabled, consider running scripts in an environment without `os` and `io` (or rejecting scripts that reference them), so the tool can drive the Fusion API but not start processes. Mark the tools as destructive in their MCP annotations so clients ask for confirmation.

## Status on the default branch
Still present at `d025e4e` (2026-04-07). The default branch has no commits after the tested commit.

## Prior reports
- No issue or PR found. Searched the 1 issue and 1 pull request (fetched 2026-10-01); #1 is a Glama Dockerfile request and #2 is a project-structure migration, neither related.
- Documentation: AGENTS.md: "Includes privileged scripting tools (`execute_python`, `execute_lua`) as first-class MCP tools." (the maintainers know these tools are privileged; this is developer guidance, not a warning to users).
- Documentation: src/davinci_resolve_mcp/AGENTS.md: "`execute_python` intentionally executes arbitrary code with direct object handles; treat as privileged surface." (documents arbitrary code execution as intended for `execute_python`; `execute_lua` is not named there).
- Documentation: README.md lists "Advanced scripting (`execute_python`, `execute_lua`)" as a feature with no warning and no opt-in setting.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: os-command-injection via `check_blocked_command_bypass` (all 3 samples); `check_command_injection` also fired for this tool. Both are static input-pattern checks, not runtime observations.
- Campaigns and executions: `corpus-sbx` 3,072 execs / 3,070 success (60 s); `e2-0922` 1,024 / 986 (60 s).
- Evidence (verbatim, trimmed): `{'script': "os.execute('ls; cat /etc/passwd')"}` -> `'Error: Not connected to DaVinci Resolve.'`; `{'script': "require('io').open('../../../../etc/passwd','r'):read('*a')"}` -> same; `{'script': "local f=io.open('/etc/passwd\\0','r') if f then return f:read('*a') end"}` -> same.
- Hand-check hints: weak as a bug report. The capability is real by code reading (`script` reaches `fusion.Execute` unchecked), but it is the tool's purpose, and AGENTS.md (`src/davinci_resolve_mcp/AGENTS.md:40`) already calls `execute_python` a privileged surface. The class is better described as CWE-94 / unrestricted code execution than CWE-78; there is no command string being built. No call reached the sink: Resolve was not running, so all calls hit the `is_connected()` early return (`server.py:721-722`). Not verified: that Fusion's Lua exposes `os.execute` (I believe it does, but did not confirm from a primary source), and whether `fusion.Execute` defaults to Lua. If filed, frame as "opt-in gate for scripting tools", not as a vulnerability. Reproduction derived from code; not run.
</details>
