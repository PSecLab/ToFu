# Log injection in `search_papers`: CR/LF in `categories` or `date_from`/`date_to` is written raw to the server log

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `search_papers` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`search_papers` logs two caller-supplied values without neutralizing CR/LF: an unknown category prefix, and the parse error for a bad date (python-dateutil puts the raw input string in its error message). A caller can therefore end the current log line and write a line of their choosing into stderr. Both paths run before any request to arXiv, so no network access is needed. Severity is low to moderate, depending on how the client stores and reads server stderr.

## Details
Category validation logs the prefix with an f-string (`src/arxiv_mcp_server/tools/search.py:666-676`):

```python
def _validate_categories(categories: List[str]) -> bool:
    """Validate that all provided categories are valid arXiv categories."""
    for category in categories:
        if "." in category:
            prefix = category.split(".")[0]
        else:
            prefix = category
        if prefix not in VALID_CATEGORIES:
            logger.warning(f"Unknown category prefix: {prefix}")
            return False
    return True
```

It is called on the raw `categories` argument at `search.py:754`. Date parsing logs the dateutil exception text (`search.py:251-263`):

```python
        if date_from:
            start_date = parser.parse(date_from).strftime("%Y%m%d0000")
        ...
    except (ValueError, TypeError) as e:
        logger.error(f"Error parsing dates: {e}")
```

For unparseable input, `dateutil.parser.ParserError` renders as `Unknown string format: <input>` with the input unchanged. The package installs no log handler, so Python's last-resort handler writes these WARNING/ERROR records to stderr as bare messages. MCP clients such as Claude Desktop keep server stderr in a per-server log file.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed.
2. Start the server at the tested commit (the README uses `uvx arxiv-mcp-server`):
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"query": "test", "categories": ["x\r\nFAKE-LOG-ENTRY"]}`, then with `{"query": "test", "date_from": "x\r\nFAKE-LOG-ENTRY"}`:

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
               result = await session.call_tool("search_papers", {"query": "test", "categories": ["x\r\nFAKE-LOG-ENTRY"]})
               print(result)
               result = await session.call_tool("search_papers", {"query": "test", "date_from": "x\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (printed in the terminal by `stdio_client`). `FAKE-LOG-ENTRY` appears at the start of its own line, after `Unknown category prefix: x` and after `Error parsing dates: Unknown string format: x`.

## Expected behavior
Caller-supplied values are escaped (for example with `%r`) or have CR/LF removed before they are logged, so each record stays on one line.

## Actual behavior
Expected stderr from the code above:

```
Unknown category prefix: x
FAKE-LOG-ENTRY
...
Error parsing dates: Unknown string format: x
FAKE-LOG-ENTRY
```

The fuzzing run did not exercise these two paths. It did record multi-line output from the same tool, but those newlines came from the server's own formatting, for example `'Tool error: {\n  "status": "error",\n  "message": "No search criteria provided"\n}'`.

## Impact
`categories`, `date_from` and `date_to` are chosen by the LLM and can be steered by prompt injection from untrusted content, such as a paper abstract or web page the agent read earlier. An attacker can add fake lines to the server log, for example a forged error or success message, which can mislead anyone debugging from that log or any tool that parses it line by line. No code execution or data access follows from this alone.

## Suggested fix
Log caller values with `%r` (`logger.warning("Unknown category prefix: %r", prefix)`), and for dates log `repr(date_from)` instead of the exception text, or strip `\r` and `\n` before logging. Configuring a formatter that escapes control characters for all records would also cover future call sites. Separately, `call_tool` (`server.py:179`) logs pretty-printed JSON over several lines; logging `%r` there keeps every error record on one line.

## Status on the default branch
Still present at `454397c` (2026-09-30). The same code is at `search.py:678-688` (category warning on line 686) and `search.py:274` (date error).

## Prior reports
- #249 "fix: search_papers retry/backoff on arXiv 429 (#238)" (PR, closed 2026-08-23): moved the invalid category/date failures of `search_papers` to `{status: "error"}` JSON. It does not touch the `logger.warning`/`logger.error` f-strings. Not a fix.
- #66 "Add MCP Shield security scan" (PR, closed 2026-07-21; its workflow is not on the default branch): automated scan flagged `search_papers.date_from`/`date_to` as strings without `maxLength` and `query` as a potential injection vector. It does not mention logging or CR/LF. Not a fix.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on neutralizing logged input). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` (fires on any `\n`/`\r` in a captured log record). Also triggered: `check_resource_exhaustion` (arXiv round trips over 2 s), `check_introspection_incomplete_cleanup` and `check_introspection_temp_file_leak` (the leaked file was `/tmp/crash-6e65...`, which looks like a fuzzer crash artifact, not the server's).
- Campaigns and executions: `e2-0922`, 1 exec recorded, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'query': '', 'max_results': 0, ..., 'categories': [], ...}`, logged `'Tool error: {\n  "status": "error",\n  "message": "No search criteria provided"\n}'`. Input `{'query': '../../../../etc/passwd', ..., 'categories': ['cs.AI', 'stat.ML'], 'sort_by': 'date'}`, logged `arXiv API HTTP error: Client error '406 Not Acceptable' for url 'https://export.arxiv.org/api/query?search_query=...'\nFor more information check: ...` (the newline is httpx's own message format; the query is percent-encoded).
- Hand-check hints: real by code reading, but not what ToFu observed. ToFu's evidence only shows server/library-generated newlines (weak on its own). The category path is a plain f-string into `logger.warning` on the raw argument. I confirmed the dateutil message format with a locally installed python-dateutil (`parser.parse('x\r\nFAKE-LOG-ENTRY')` raises `ParserError('Unknown string format: x\r\nFAKE-LOG-ENTRY')`); repo code was not run. Exact stderr layout is derived from code. Other `search_papers` log calls are safe: `%r` at `search.py:744-751`, debug-level calls are below the INFO threshold.
</details>
