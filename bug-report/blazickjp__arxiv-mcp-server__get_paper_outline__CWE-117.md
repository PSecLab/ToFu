# Multi-line `Tool error:` log records from `get_paper_outline` error results

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `get_paper_outline` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
For an unknown paper, `get_paper_outline` returns a pretty-printed JSON error that echoes the requested `paper_id`. `call_tool` in `server.py` logs every error payload as `Tool error: <payload>`, so one event spans several lines in stderr. The echoed `paper_id` is JSON-escaped, so a CR/LF in it shows up as the text `\r\n` and does not start a new log line. This is a log-format hardening item, not an injection.

## Details
`_load_paper` falls back to the stripped, unvalidated ID for the message (`src/arxiv_mcp_server/tools/paper_outline.py:552-568`):

```python
    paper_id = parse_arxiv_id(raw_id) if isinstance(raw_id, str) else None
    if paper_id is None and isinstance(raw_id, str):
        paper_id = normalize_arxiv_id(raw_id)
    ...
    resolved = resolve_stored_stem(paper_id, Path(settings.STORAGE_PATH))
    if resolved is None:
        return _error(
            f"Paper {paper_id} not found in storage. "
            "You may need to download it first using download_paper.",
            paper_id,
        )
```

`_error` serializes with `json.dumps(payload, indent=2)` (`paper_outline.py:153-157`). `call_tool` logs the text (`src/arxiv_mcp_server/server.py:175-180`):

```python
        if error_message := _tool_error_message(result):
            raise RuntimeError(error_message)
        return result
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        raise
```

`normalize_arxiv_id` only strips leading and trailing whitespace, so CR/LF inside the ID survives into the message, but `json.dumps` escapes it before logging. `resolve_stored_stem` validates the ID before any file access (`tools/list_papers.py:138-140`), so there is no path traversal here either.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed.
2. Start the server at the tested commit:
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"paper_id": "not-an-id\r\nFAKE-LOG-ENTRY", "start": 0, "max_sections": 10}`:

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
               result = await session.call_tool("get_paper_outline", {"paper_id": "not-an-id\r\nFAKE-LOG-ENTRY", "start": 0, "max_sections": 10})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr. The `Tool error: {` record spans several lines; the message reads `Paper not-an-id\r\nFAKE-LOG-ENTRY not found in storage.` with `\r\n` as literal text.

## Expected behavior
One error event produces one log line.

## Actual behavior
From the fuzzing run (newlines rendered as `\n`):

```
Tool error: {\n  "status": "error",\n  "message": "Paper ../../../../etc/passwd not found in storage. You may need to download it first using download_paper.",\n  "paper_id": "../../../../etc/passwd"\n}
```

## Impact
Caller text does land in the log, but escaped, so it cannot forge a separate entry. The remaining effect is multi-line records. Low.

## Suggested fix
Log one line in `call_tool`, for example `logger.error("Tool %s error: %r", name, str(e))`, or compact the JSON before logging. Optionally echo only validated IDs in the message.

## Status on the default branch
Still present at `454397c` (2026-09-30). `server.py` and `paper_outline.py` are unchanged between the tested commit and HEAD.

## Prior reports
- #95 "fix: set MCP error flag for tool error payloads" (PR, closed 2026-04-26; merged, its `tests/test_mcp_tool_error_semantics.py` is on the default branch): added the conversion of `{"status": "error"}` payloads into exceptions in `call_tool`, which is what sends them to `logger.error("Tool error: ...")`. It is about the MCP `isError` flag and does not mention logging. Origin of the behaviour, not a fix.
- #92 "get_abstract: returns error content but isError flag not set for invalid paper IDs" (issue, closed 2026-04-26): the bug #95 fixed. No mention of logs.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on record format). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only; nothing on logs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` only (fires on any `\n`/`\r` in a captured log record).
- Campaigns and executions: `e2-0922`, 500 execs, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'paper_id': '/etc/passwd\x00', 'start': 0, 'max_sections': 100}`, output `None`, logged `'Tool error: {\n  "status": "error",\n  "message": "Paper /etc/passwd\u0000 not found in storage. ...",\n  "paper_id": "/etc/passwd\u0000"\n}'`. The `\u0000` shows the JSON escaping at work.
- Hand-check hints: weak. Newlines come from `json.dumps(indent=2)`; caller CR/LF is escaped. Same root cause (`server.py:179`) as the other arxiv-mcp-server CWE-117 drafts except `search_papers`. Merge or drop. Stderr output derived from code, not run.
</details>
