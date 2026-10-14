# Multi-line `Tool error:` log records from `get_paper_latex_section` error results

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `get_paper_latex_section` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_paper_latex_section` returns pretty-printed JSON errors, and `call_tool` in `server.py` logs each one as `Tool error: <payload>`, so one event spans several lines in stderr. Caller input does not reach this record raw: `paper_id` is validated before it is echoed, and `section_id` is echoed with `repr()` inside JSON. This is a log-format hardening item, not an injection.

## Details
Error paths in the handler (`src/arxiv_mcp_server/tools/latex.py:432-452`):

```python
    paper_id = _normalized_paper_id(arguments)
    if paper_id is None:
        return _error("invalid arXiv ID")
    section_id = arguments.get("section_id")
    if not isinstance(section_id, str) or not section_id.strip():
        return _error("section_id is required", paper_id)
    if len(section_id) > MAX_SECTION_ID_CHARS:
        return _error(f"section_id exceeds {MAX_SECTION_ID_CHARS} characters", paper_id)
...
            return _error(
                f"LaTeX section {section_id!r} not found; call list_paper_latex_sections first",
                paper_id,
            )
```

`_error` serializes with `json.dumps(payload, indent=2)` (`latex.py:129-133`). `call_tool` then logs the whole text (`src/arxiv_mcp_server/server.py:175-180`):

```python
        if error_message := _tool_error_message(result):
            raise RuntimeError(error_message)
        return result
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        raise
```

With no handler configured, Python's last-resort handler writes this ERROR record to stderr.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed for an invalid ID.
2. Start the server at the tested commit:
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"paper_id": "validPaper1234", "section_id": "intro\r\nFAKE-LOG-ENTRY", "start": 0, "max_chars": 1000, "return_full_text": false}`:

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
               result = await session.call_tool("get_paper_latex_section", {"paper_id": "validPaper1234", "section_id": "intro\r\nFAKE-LOG-ENTRY", "start": 0, "max_chars": 1000, "return_full_text": False})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr. `Tool error: {` is followed by the indented `"status"` and `"message": "invalid arXiv ID"` lines. No `FAKE-LOG-ENTRY` line appears.

## Expected behavior
One error event produces one log line.

## Actual behavior
From the fuzzing run (newlines rendered as `\n`):

```
Tool error: {\n  "status": "error",\n  "message": "invalid arXiv ID"\n}
```

## Impact
Through this tool the caller cannot get raw CR/LF into the log. The effect is limited to multi-line records. Low.

## Suggested fix
Log one line in `call_tool`, for example `logger.error("Tool %s error: %r", name, str(e))`, or compact the JSON before logging.

## Status on the default branch
Still present at `454397c` (2026-09-30). `server.py` is unchanged; the handler still returns `_error("invalid arXiv ID")` (`latex.py:507`).

## Prior reports
- #95 "fix: set MCP error flag for tool error payloads" (PR, closed 2026-04-26; merged, its `tests/test_mcp_tool_error_semantics.py` is on the default branch): added the conversion of `{"status": "error"}` payloads into exceptions in `call_tool`, which is what sends them to `logger.error("Tool error: ...")`. It is about the MCP `isError` flag and does not mention logging. Origin of the behaviour, not a fix.
- #92 "get_abstract: returns error content but isError flag not set for invalid paper IDs" (issue, closed 2026-04-26): the bug #95 fixed. No mention of logs.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on record format). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only; nothing on logs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` only (fires on any `\n`/`\r` in a captured log record).
- Campaigns and executions: `e2-0922`, 500 execs, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'paper_id': 'validPaper1234', 'section_id': '________', 'start': 0, 'max_chars': 12000, 'return_full_text': False}`, output `None`, logged `'Tool error: {\n  "status": "error",\n  "message": "invalid arXiv ID"\n}'`. All three samples used `validPaper1234`, which fails ID validation, so `section_id` was never even read.
- Hand-check hints: weak, close to a false positive. No caller bytes in the logged record; newlines come from `json.dumps(indent=2)`. Same root cause (`server.py:179`) as the other arxiv-mcp-server CWE-117 drafts except `search_papers`. Merge or drop. Stderr output derived from code, not run.
</details>
