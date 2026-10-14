# Multi-line `Tool error:` log records from `list_paper_latex_sections` error results

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `list_paper_latex_sections` · **Tested commit:** `42419c1`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`list_paper_latex_sections` returns pretty-printed JSON errors (invalid ID, arXiv HTTP failure, empty outline), and `call_tool` in `server.py` logs each one as `Tool error: <payload>`. One event therefore spans four or five lines in stderr. The error payloads contain only fixed text, a status code and an already-validated arXiv ID, so the caller cannot inject CR/LF through this tool. This is a log-format hardening item, not an injection.

## Details
Error paths (`src/arxiv_mcp_server/tools/latex.py:384-386` and `:420-429`):

```python
    paper_id = _normalized_paper_id(arguments)
    if paper_id is None:
        return _error("invalid arXiv ID")
...
    except httpx.HTTPStatusError as exc:
        return _error(
            f"arXiv source request failed with HTTP {exc.response.status_code}",
            paper_id,
        )
    except LatexSourceError as exc:
        return _error(str(exc), paper_id)
    except Exception as exc:
        logger.exception("LaTeX outline retrieval failed for %s", paper_id)
        return _error("LaTeX outline retrieval failed", paper_id)
```

`_normalized_paper_id` (`latex.py:136-143`) only returns IDs that match the arXiv ID regex, and `_error` serializes with `json.dumps(payload, indent=2)` (`latex.py:129-133`). `call_tool` logs the text (`src/arxiv_mcp_server/server.py:175-180`):

```python
        if error_message := _tool_error_message(result):
            raise RuntimeError(error_message)
        return result
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        raise
```

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed for an invalid ID.
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
               result = await session.call_tool("list_paper_latex_sections", {"paper_id": "not-an-id\r\nFAKE-LOG-ENTRY", "start": 0, "max_sections": 10})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr. `Tool error: {` is followed by the indented JSON lines; `FAKE-LOG-ENTRY` does not appear.

## Expected behavior
One error event produces one log line.

## Actual behavior
From the fuzzing run (newlines rendered as `\n`):

```
Tool error: {\n  "status": "error",\n  "message": "arXiv source request failed with HTTP 404",\n  "paper_id": "2222.2222"\n}
```

## Impact
No caller-controlled text reaches the record unvalidated. The effect is limited to multi-line records. Low.

## Suggested fix
Log one line in `call_tool`, for example `logger.error("Tool %s error: %r", name, str(e))`, or compact the JSON before logging.

## Status on the default branch
Still present at `454397c` (2026-09-30). `server.py` is unchanged; `latex.py` still returns `_error("invalid arXiv ID")` (line 421) through the same `indent=2` helper.

## Prior reports
- #95 "fix: set MCP error flag for tool error payloads" (PR, closed 2026-04-26; merged, its `tests/test_mcp_tool_error_semantics.py` is on the default branch): added the conversion of `{"status": "error"}` payloads into exceptions in `call_tool`, which is what sends them to `logger.error("Tool error: ...")`. It is about the MCP `isError` flag and does not mention logging. Origin of the behaviour, not a fix.
- #92 "get_abstract: returns error content but isError flag not set for invalid paper IDs" (issue, closed 2026-04-26): the bug #95 fixed. No mention of logs.
- Documentation: CLAUDE.md: "Keep stdio free of ordinary stdout logging" (contributor rule that logs stay off stdout; nothing on record format). SECURITY.md's threat model covers paper content, LaTeX archives and Streamable HTTP only; nothing on logs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` (fires on any `\n`/`\r` in a captured log record). Also triggered for this tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_resource_exhaustion` (not part of this claim).
- Campaigns and executions: `corpus-sbx` 512 execs / 6 success; `repo24` 83,968 / 4,307 and 78,848 / 4,225 (4,200 s budgets); `e2-0922` 512 / 2.
- Evidence (verbatim, trimmed): input `{'paper_id': 'arXiv:2222.2222', 'start': 0, 'max_sections': 1}`, output `None`, logged `'Tool error: {\n  "status": "error",\n  "message": "arXiv source request failed with HTTP 404",\n  "paper_id": "2222.2222"\n}'`. Inputs `/etc/passwd\x00` and `http://127.0.0.1:8500` logged the fixed `invalid arXiv ID` payload.
- Hand-check hints: weak, close to a false positive. No unvalidated caller bytes in the record; newlines come from `json.dumps(indent=2)`. Same root cause (`server.py:179`) as the other arxiv-mcp-server CWE-117 drafts except `search_papers`. Merge or drop. Stderr output derived from code, not run.
</details>
