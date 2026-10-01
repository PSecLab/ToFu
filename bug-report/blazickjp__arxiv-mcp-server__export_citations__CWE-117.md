# Multi-line `Tool error:` log records from `export_citations` error results

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `export_citations` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`export_citations` reports invalid IDs in a pretty-printed JSON error payload. `call_tool` in `server.py` turns every `{"status": "error"}` payload into an exception and logs `Tool error: <payload>`, so one log call writes 15 or more physical lines. Caller strings inside the payload are JSON-escaped, so a CR/LF in `paper_ids` does not produce a forged log line. The effect is that one event spans many lines, which breaks line-oriented log parsing and alerting. This is low-severity hardening, not an injection.

## Details
The tool copies each invalid ID into the result as given and serializes with `indent=2` (`src/arxiv_mcp_server/tools/export_citations.py:249-255` and `:313-324`):

```python
            if not candidate or not is_valid_arxiv_id(candidate):
                results.append(
                    {
                        "paper_id": pid,
                        "status": "error",
                        "error": "invalid arXiv ID format",
                    }
                )
...
        return [types.TextContent(type="text", text=json.dumps(payload, indent=2))]
```

`_tool_error_message` (`src/arxiv_mcp_server/server.py:111-124`) returns that text unchanged, and `call_tool` logs it (`server.py:175-180`):

```python
        if error_message := _tool_error_message(result):
            raise RuntimeError(error_message)
        return result
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        raise
```

The package installs no log handler, so Python's last-resort handler writes this ERROR record to stderr. MCP clients such as Claude Desktop keep server stderr in a per-server log file. `json.dumps` escapes control characters, so caller CR/LF appears as the literal text `\r\n`. I found no path in this tool where caller CR/LF reaches the log raw.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed: invalid IDs never reach the arXiv API.
2. Start the server at the tested commit (the README uses `uvx arxiv-mcp-server`):
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"paper_ids": ["not-an-id\r\nFAKE-LOG-ENTRY"]}`:

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
               result = await session.call_tool("export_citations", {"paper_ids": ["not-an-id\r\nFAKE-LOG-ENTRY"]})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (printed in the terminal by `stdio_client`). One `Tool error: {` record spans the whole indented JSON. The `paper_id` value appears as `"not-an-id\r\nFAKE-LOG-ENTRY"` with the escape sequences as text, not as a new line.

## Expected behavior
One error event produces one log line, for example compact JSON or a short summary.

## Actual behavior
One record spans many lines. From the fuzzing run (newlines rendered as `\n`):

```
Tool error: {\n  "status": "error",\n  "format": "bibtex",\n  "bibtex": "",\n  "results": [\n    {\n      "paper_id": "[object Object]",\n      "status": "error",\n      "error": "invalid arXiv ID format"\n    }\n  ], ...
```

## Impact
`paper_ids` is chosen by the LLM and can be steered by prompt injection. Because the value is JSON-escaped, an attacker cannot forge a separate log entry through this tool. What remains is multi-line records that split one event across lines in line-based log tools. Low.

## Suggested fix
Log a single line in `call_tool`, for example `logger.error("Tool %s error: %r", name, str(e))`, or re-serialize the payload compactly (`json.dumps(json.loads(error_message), separators=(",", ":"))`) before logging. This one change covers every tool that returns `{"status": "error"}`.

## Status on the default branch
Still present at `454397c` (2026-09-30). `server.py` is unchanged. `export_citations.py` gained new `except` branches, but the result is still `json.dumps(payload, indent=2)` (line 330).

## Prior reports
- #95 "fix: set MCP error flag for tool error payloads" (PR, closed 2026-04-26; merged, its `tests/test_mcp_tool_error_semantics.py` is on the default branch): added the conversion of `{"status": "error"}` payloads into exceptions in `call_tool`, which is what sends them to `logger.error("Tool error: ...")`. It is about the MCP `isError` flag and does not mention logging. Origin of the behaviour, not a fix.
- #92 "get_abstract: returns error content but isError flag not set for invalid paper IDs" (issue, closed 2026-04-26): the bug #95 fixed. No mention of logs.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on record format). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only; nothing on logs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection`, which fires on any `\n`/`\r` in any captured log record, whatever its origin. Also triggered for this tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_resource_exhaustion` (not part of this claim).
- Campaigns and executions: `e2-0922`, 1 exec, 0 success (error results count as failures), 60 s budget.
- Evidence (verbatim, trimmed): input `{'paper_ids': ['[object Object]']}`, output `None`, logged `'Tool error: {\n  "status": "error",\n  "format": "bibtex", ...'`. Input `{'paper_ids': ['', ' ', '\n', '\x00']}` logged the `"\n"` ID as `"paper_id": "\n"`; ToFu's rendering replaces real newlines with `\n`, so it cannot be told apart from the JSON escape, but by code it is the escape.
- Hand-check hints: weak. The newlines come from `json.dumps(indent=2)`, not from the caller; caller CR/LF is escaped. Same root cause (`server.py:179`) as the drafts for `get_paper_latex`, `get_paper_latex_section`, `get_paper_outline`, `list_paper_latex_sections`, `read_paper_section`, `reindex` and `search_paper_text`. File at most one combined hardening issue, or drop. The real caller-controlled log paths in this repo are in `search_papers` (separate draft). Reproduction stderr output derived from code, not run.
</details>
