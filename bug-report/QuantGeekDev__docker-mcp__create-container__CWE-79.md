# Missing output encoding in `create-container`: `image`/`name` echoed unescaped in error output

**Repository:** `QuantGeekDev/docker-mcp` · **Tool:** `create-container` · **Tested commit:** `6dada7f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`create-container` creates a Docker container from caller-supplied `image`, `name`, `ports`, and `environment`. On any error it returns a message that interpolates the raw `arguments` dict back into the text. Caller-controlled input is reflected without encoding. Whether this is exploitable depends entirely on how the MCP client renders tool output; in the captured evidence the reflection lands in a plain-text error string.

## Details
The error path echoes the full arguments dict (`src/docker_mcp/handlers.py:65-66`):

```python
except Exception as e:
    return [TextContent(type="text", text=f"Error creating container: {str(e)} | Arguments: {arguments}")]
```

The dispatcher has an identical outer echo (`src/docker_mcp/server.py:166-167`):

```python
except Exception as e:
    return [types.TextContent(type="text", text=f"Error: {str(e)} | Arguments: {arguments}")]
```

The reflected value is placed verbatim into a `TextContent` string. There is no HTML/Markdown encoding. The tool itself does not render the output, so this is a missing-output-encoding condition rather than a confirmed XSS.

## Steps to reproduce
1. Prerequisites: UV, Python 3.12+. Docker does not need to be installed; an error path still reflects the input.
2. Start the server as the README describes:
   ```json
   { "command": "uvx", "args": ["docker-mcp"] }
   ```
3. Call the tool with a markup payload in `image`/`name`. Arguments as JSON:
   ```json
   {"image": "<img src=x onerror=alert(1)>", "name": "{{7*7}}", "ports": {}, "environment": {}}
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
               result = await session.call_tool("create-container", {"image": "<img src=x onerror=alert(1)>", "name": "{{7*7}}", "ports": {}, "environment": {}})
               print(result)

   asyncio.run(main())
   ```
4. Observe the payload returned verbatim inside the `Arguments: {...}` text. If a downstream client renders tool output as HTML or Markdown, the markup is not escaped.

## Expected behavior
Error messages should not reflect raw caller input, or should encode it for the rendering context. Echoing the full arguments dict is unnecessary.

## Actual behavior
The input is returned unescaped. From the fuzz evidence (`name` contained `{{{{{{`):

```
Error creating container: The binary 'docker' could not be found ... | Arguments: {'image': ..., 'name': '{{{{{{', 'ports': {}, 'environment': {}}
```

## Impact
MCP tool arguments are LLM-controlled and can be steered by prompt injection. If any MCP client renders this tool's output as HTML/Markdown/SVG, reflected markup could execute in that context. In a plain-text/JSON client there is no script execution, so severity is low and conditional on the client.

## Suggested fix
Stop interpolating the raw `arguments` dict into returned text. If echoing is needed for debugging, log it server-side only, and HTML-encode any caller input that may be rendered.

## Status on the default branch
Still present at `6dada7f` (2024-12-14). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
No issue or PR reports reflected tool arguments or missing output encoding. Searched all 12 issues and 18 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #35 "Requesting private channel for reporting a vulnerability" (issue, open 2026-09-17) and #34 "Requesting a private channel to report a potential security issue (Windows-specific)" (issue, open 2026-09-10): both withhold technical details, so overlap with this report can be neither confirmed nor ruled out. Both note that the repository has no SECURITY.md and no private vulnerability reporting.
- Documentation: README.md has no security section and says nothing about how tool output or error messages are formatted. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output`. Campaign: corpus-sbx (3072/3072).
- Evidence (verbatim, trimmed): ToFu flagged echoed tokens `{{` and `${` in the `Arguments: {...}` tail of the error string. docker binary absent in the sandbox, so every call hit the error path.
- Hand-check hints: WEAK. Only a necessary condition (unescaped reflection into plain text/JSON). No rendering context verified; the echoed tokens are `{{`/`${`, not actual script. Real underlying smell is that both the handler and dispatcher echo the full `arguments` dict. Severity low unless a client renders output as HTML/MD.
</details>
