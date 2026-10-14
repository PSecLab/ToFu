# Multi-line `Tool error:` log records from `get_paper_latex` error results

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `get_paper_latex` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
When `get_paper_latex` rejects a `paper_id`, it returns a pretty-printed JSON error. `call_tool` in `server.py` logs every error payload as `Tool error: <payload>`, so a single event is written as four physical lines. The invalid-ID payload holds no caller data at all, so this is not an injection. It is a log-format hardening item: multi-line records break line-oriented log parsing.

## Details
`get_paper_latex` validates the ID before use and returns a fixed message (`src/arxiv_mcp_server/tools/latex.py:345-350`), serialized with `indent=2` (`latex.py:129-133`):

```python
def _error(message: str, paper_id: str | None = None) -> list[types.TextContent]:
    payload: dict[str, Any] = {"status": "error", "message": message}
    if paper_id:
        payload["paper_id"] = paper_id
    return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]
...
    paper_id = _normalized_paper_id(arguments)
    if paper_id is None:
        return _error("invalid arXiv ID")
```

`call_tool` raises on any `{"status": "error"}` payload and logs the raw text (`src/arxiv_mcp_server/server.py:175-180`):

```python
        if error_message := _tool_error_message(result):
            raise RuntimeError(error_message)
        return result
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        raise
```

The package installs no log handler, so Python's last-resort handler sends this ERROR record to stderr. Later error paths in this tool only add the already-validated ID (`latex.py:366-378`), and `logger.exception` at `latex.py:377` uses that validated ID too.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed for an invalid ID.
2. Start the server at the tested commit:
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"paper_id": "not-an-id\r\nFAKE-LOG-ENTRY", "start": 0, "max_chars": 1000, "return_full_text": false}`:

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
               result = await session.call_tool("get_paper_latex", {"paper_id": "not-an-id\r\nFAKE-LOG-ENTRY", "start": 0, "max_chars": 1000, "return_full_text": False})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr. The record `Tool error: {` / `"status": "error",` / `"message": "invalid arXiv ID"` / `}` spans four lines. `FAKE-LOG-ENTRY` does not appear.

## Expected behavior
One error event produces one log line.

## Actual behavior
From the fuzzing run (newlines rendered as `\n`):

```
Tool error: {\n  "status": "error",\n  "message": "invalid arXiv ID"\n}
```

## Impact
The caller cannot place any text in this record, so there is no log forging through `get_paper_latex`. The only effect is multi-line records in stderr logs. Low.

## Suggested fix
Log one line in `call_tool`, for example `logger.error("Tool %s error: %r", name, str(e))`, or compact the JSON before logging. One change covers all tools.

## Status on the default branch
Still present at `454397c` (2026-09-30). `server.py` is unchanged; `latex.py` still returns `_error("invalid arXiv ID")` (line 351) with the same `indent=2` helper.

## Prior reports
- #95 "fix: set MCP error flag for tool error payloads" (PR, closed 2026-04-26; merged, its `tests/test_mcp_tool_error_semantics.py` is on the default branch): added the conversion of `{"status": "error"}` payloads into exceptions in `call_tool`, which is what sends them to `logger.error("Tool error: ...")`. It is about the MCP `isError` flag and does not mention logging. Origin of the behaviour, not a fix.
- #92 "get_abstract: returns error content but isError flag not set for invalid paper IDs" (issue, closed 2026-04-26): the bug #95 fixed. No mention of logs.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on record format). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only; nothing on logs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` only. That check fires on any `\n`/`\r` in any captured log record, whatever its origin.
- Campaigns and executions: `e2-0922`, 500 execs, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'paper_id': '../../../../etc/passwd', 'start': 0, 'max_chars': 50000, 'return_full_text': True}`, output `None`, logged `'Tool error: {\n  "status": "error",\n  "message": "invalid arXiv ID"\n}'`. Same log for `paper_id` `http://127.0.0.1:8500`.
- Hand-check hints: weak, close to a false positive. The logged record contains zero caller-controlled bytes; the newlines come from `json.dumps(indent=2)`. Same root cause (`server.py:179`) as the other arxiv-mcp-server CWE-117 drafts except `search_papers`. Recommend merging into one hardening issue or dropping. Stderr output above derived from code, not run.
</details>
