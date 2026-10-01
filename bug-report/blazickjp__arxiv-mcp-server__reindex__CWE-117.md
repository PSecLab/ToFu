# Multi-line `Tool error:` log record from `reindex` when pro dependencies are missing

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `reindex` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
On a default install (without the `[pro]` extra), `reindex` returns a pretty-printed JSON error that says the dependency is missing. `call_tool` in `server.py` logs every error payload as `Tool error: <payload>`, so the event spans four lines in stderr. The tool's only argument is a boolean, so no caller text reaches the log. This is a log-format hardening item, not an injection.

## Details
`rebuild_index` returns a fixed error dict when the pro packages are absent (`src/arxiv_mcp_server/tools/semantic_search.py:341-345`), and the handler serializes it with `indent=2` (`semantic_search.py:376-381`):

```python
async def handle_reindex(arguments: Dict[str, Any]) -> List[types.TextContent]:
    """Handle reindex tool calls."""
    try:
        clear_existing = bool(arguments.get("clear_existing", True))
        result = rebuild_index(clear_existing=clear_existing)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]
```

`call_tool` logs the text (`src/arxiv_mcp_server/server.py:175-180`):

```python
        if error_message := _tool_error_message(result):
            raise RuntimeError(error_message)
        return result
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        raise
```

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. Install without the `[pro]` extra. No network access is needed.
2. Start the server at the tested commit:
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"clear_existing": false}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=[
           "--from", "git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38",
           "arxiv-mcp-server", "--storage-path", "/tmp/tofu-arxiv"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("reindex", {"clear_existing": False})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr: `Tool error: {` followed by the indented `"status"` and `"message"` lines and a closing `}`.

## Expected behavior
One error event produces one log line.

## Actual behavior
From the fuzzing run (newlines rendered as `\n`):

```
Tool error: {\n  "status": "error",\n  "message": "Pro feature dependency missing. Install with `uvx --from 'arxiv-mcp-server[pro]' arxiv-mcp-server` ..."\n}
```

## Impact
None from the caller's side: there is no string argument. The effect is a multi-line record. Low.

## Suggested fix
Log one line in `call_tool`, for example `logger.error("Tool %s error: %r", name, str(e))`, or compact the JSON before logging.

## Status on the default branch
Still present at `454397c` (2026-09-30). `server.py` and `semantic_search.py` are unchanged between the tested commit and HEAD.

## Prior reports
- #95 "fix: set MCP error flag for tool error payloads" (PR, closed 2026-04-26; merged, its `tests/test_mcp_tool_error_semantics.py` is on the default branch): added the conversion of `{"status": "error"}` payloads into exceptions in `call_tool`, which is what sends them to `logger.error("Tool error: ...")`. It is about the MCP `isError` flag and does not mention logging. Origin of the behaviour, not a fix.
- #92 "get_abstract: returns error content but isError flag not set for invalid paper IDs" (issue, closed 2026-04-26): the bug #95 fixed. No mention of logs.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on record format). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only; nothing on logs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` only (fires on any `\n`/`\r` in a captured log record).
- Campaigns and executions: `e2-0922`, 500 execs, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): inputs `{'clear_existing': False}` and `{'clear_existing': True}`, output `None`, logged `'Tool error: {\n  "status": "error",\n  "message": "Pro feature dependency missing. ..."\n}'`.
- Hand-check hints: weak, effectively a false positive. The only input is a bool; the record contains zero caller-controlled bytes. Same root cause (`server.py:179`) as the other arxiv-mcp-server CWE-117 drafts. Recommend dropping. Side note, not this tool: `handle_semantic_search` logs a raw `paper_id` at `semantic_search.py:409-411` and returns `Error: Could not index source paper {paper_id}.` (`:416`), which `call_tool` logs raw; that path needs the `[pro]` extra and was not in ToFu's findings for this group.
</details>
