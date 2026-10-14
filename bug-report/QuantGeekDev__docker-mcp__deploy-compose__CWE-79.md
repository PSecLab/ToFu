# Missing output encoding in `deploy-compose`: `compose_yaml` echoed unescaped in debug output

**Repository:** `QuantGeekDev/docker-mcp` · **Tool:** `deploy-compose` · **Tested commit:** `6dada7f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`deploy-compose` takes a caller-supplied `compose_yaml` string and `project_name`. On a YAML parse error it returns a debug block that includes the original YAML verbatim. Caller-controlled input is reflected without encoding. Exploitability depends on how the MCP client renders tool output; in the captured evidence the reflection lands in a plain-text error string.

## Details
The handler appends the raw YAML to a debug list that is returned on error (`src/docker_mcp/handlers.py:95-97` and `:90-92`):

```python
@staticmethod
def _process_yaml(compose_yaml: str, debug_info: List[str]) -> dict:
    debug_info.append("=== Original YAML ===")
    debug_info.append(compose_yaml)          # raw caller input
    ...
except Exception as e:
    debug_output = "\n".join(debug_info)
    return [TextContent(type="text", text=f"Error deploying compose stack: {str(e)}\n\nDebug Information:\n{debug_output}")]
```

The reflected value goes verbatim into a `TextContent` string with no HTML/Markdown encoding. The tool does not render the output, so this is a missing-output-encoding condition, not a confirmed XSS.

## Steps to reproduce
1. Prerequisites: UV, Python 3.12+. An invalid-YAML payload triggers the reflecting error path without needing Docker.
2. Start the server as the README describes:
   ```json
   { "command": "uvx", "args": ["docker-mcp"] }
   ```
3. Call the tool with markup in `compose_yaml`. Arguments as JSON:
   ```json
   {"compose_yaml": "<svg onload=alert(1)>: \u0000", "project_name": "poc"}
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
               result = await session.call_tool("deploy-compose", {"compose_yaml": "<svg onload=alert(1)>: \u0000", "project_name": "poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the payload returned verbatim under `=== Original YAML ===`. If a downstream client renders tool output as HTML or Markdown, the markup is not escaped.

## Expected behavior
Error output should not reflect raw caller input, or should encode it for the rendering context.

## Actual behavior
The input is returned unescaped. From the fuzz evidence:

```
Error deploying compose stack: Invalid YAML format: ... 
Debug Information:
=== Original YAML ===
"`c\x00{{"`c\x00p
```

## Impact
MCP tool arguments are LLM-controlled and can be steered by prompt injection. If any MCP client renders this output as HTML/Markdown/SVG, reflected markup could execute there. In a plain-text/JSON client there is no script execution, so severity is low and conditional on the client.

## Suggested fix
Do not echo the raw `compose_yaml` back to the caller. Keep debug detail in server-side logs, and HTML-encode any caller input that may be rendered.

## Status on the default branch
Still present at `6dada7f` (2024-12-14). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
No issue or PR reports reflected tool arguments or missing output encoding. Searched all 12 issues and 18 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #19 "Security: Command injection via shell=True in WindowsExecutor" (issue, open 2026-04-03): a different bug in the same tool. `project_name` from `deploy-compose` reaches `create_subprocess_shell` on Windows. Does not cover the YAML echo.
- #29 "Security: fix command injection via project_name (Windows shell=True)" (PR, open 2026-06-29): fix for #19 that quotes `project_name` with `shlex.quote` in `docker_executor.py`. Does not touch `_process_yaml` or the debug output, so it would not fix this. Not merged.
- #35 "Requesting private channel for reporting a vulnerability" (issue, open 2026-09-17) and #34 "Requesting a private channel to report a potential security issue (Windows-specific)" (issue, open 2026-09-10): both withhold technical details, so overlap with this report can be neither confirmed nor ruled out. Both note that the repository has no SECURITY.md and no private vulnerability reporting.
- Documentation: README.md has no security section and says nothing about how tool output or error messages are formatted. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output` (also `check_file_access`, `check_introspection_path_traversal`, `check_introspection_sensitive_file_access` in the tool's overall set, but the single evidence item is the reflected-output one). Campaign: corpus-sbx (3072/3072).
- Evidence (verbatim, trimmed): input `{'compose_yaml': '"`c\x00{{"`c\x00p', 'project_name': 'se_yamK"`c\x01'}` → error echoing the YAML under `=== Original YAML ===`; flagged token `{{`.
- Hand-check hints: WEAK. Necessary condition only (unescaped reflection into plain text). No rendering context verified; echoed token is `{{`. Real smell: `_process_yaml` appends raw input to the returned debug block.
</details>
