# Missing output encoding in `get-logs`: `container_name` echoed unescaped in debug output

**Repository:** `QuantGeekDev/docker-mcp` · **Tool:** `get-logs` · **Tested commit:** `6dada7f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get-logs` retrieves logs for a caller-supplied `container_name`. The debug output reflects `container_name` back verbatim. Caller-controlled input is returned without encoding. Exploitability depends on how the MCP client renders tool output; in the captured evidence the reflection lands in a plain-text string.

## Details
The handler appends the raw container name to the returned debug text (`src/docker_mcp/handlers.py:173-177`):

```python
debug_info.append(f"Fetching logs for container '{container_name}'")
logs = await asyncio.to_thread(docker_client.container.logs, container_name, tail=100)
return [TextContent(type="text", text=f"Logs for container '{container_name}':\n{logs}\n\nDebug Info:\n{chr(10).join(debug_info)}")]
```

On error the same `container_name` is echoed inside `Debug Information`. The value goes verbatim into a `TextContent` string with no HTML/Markdown encoding. The tool does not render output, so this is a missing-output-encoding condition, not a confirmed XSS.

## Steps to reproduce
1. Prerequisites: UV, Python 3.12+. The error path reflects the input without needing Docker.
2. Start the server as the README describes:
   ```json
   { "command": "uvx", "args": ["docker-mcp"] }
   ```
3. Call the tool with markup in `container_name`. Arguments as JSON:
   ```json
   {"container_name": "<img src=x onerror=alert(1)>"}
   ```
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["docker-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get-logs", {"container_name": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the payload returned verbatim after `Fetching logs for container '...'`. If a downstream client renders tool output as HTML or Markdown, the markup is not escaped.

## Expected behavior
Output should not reflect raw caller input, or should encode it for the rendering context.

## Actual behavior
The input is returned unescaped. From the fuzz evidence:

```
Error retrieving logs: The binary 'docker' could not be found ...
Debug Information:
Fetching logs for container '" "${" '
```

## Impact
MCP tool arguments are LLM-controlled and can be steered by prompt injection. If any MCP client renders this output as HTML/Markdown/SVG, reflected markup could execute there. In a plain-text/JSON client there is no script execution, so severity is low and conditional on the client.

## Suggested fix
Do not echo the raw `container_name` into returned text. Keep debug detail server-side, and HTML-encode any caller input that may be rendered.

## Status on the default branch
Still present at `6dada7f` (2024-12-14). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
No issue or PR reports reflected tool arguments or missing output encoding. Searched all 12 issues and 18 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #35 "Requesting private channel for reporting a vulnerability" (issue, open 2026-09-17) and #34 "Requesting a private channel to report a potential security issue (Windows-specific)" (issue, open 2026-09-10): both withhold technical details, so overlap with this report can be neither confirmed nor ruled out. Both note that the repository has no SECURITY.md and no private vulnerability reporting.
- Documentation: README.md has no security section and says nothing about how tool output or error messages are formatted. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output` (tool set also includes `check_log_injection`). Campaign: corpus-sbx (2560/2560).
- Evidence (verbatim, trimmed): inputs `{'container_name': '" "${" '}` and long `{{{{...` strings → echoed under `Fetching logs for container '...'`; flagged tokens `${` and `{{`.
- Hand-check hints: WEAK. Necessary condition only (unescaped reflection into plain text). No rendering context verified. Real smell: `container_name` is interpolated into the returned debug string.
</details>
