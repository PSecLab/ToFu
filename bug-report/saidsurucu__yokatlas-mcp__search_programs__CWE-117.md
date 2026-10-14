# Possible log injection in `search_programs`: error messages built from caller filters are logged without CR/LF neutralization

**Repository:** `saidsurucu/yokatlas-mcp` · **Tool:** `search_programs` · **Tested commit:** `6f034ec`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`search_programs` takes free-text filters (`universite`, `program`, `il`, `sort_by`) and passes them to `yokatlas-py`. When filter validation, the fuzzy lookup or the API call fails, the exception is written to the server log with `logger.warning(...)` or `logger.exception(...)`. Nothing strips CR or LF first, so if the library's error message repeats the caller's value, a value containing a line break produces a fake extra line in the log.

## Details
`yokatlas_mcp_server.py:234-254` at `6f034ec`:

```python
    try:
        filters = SearchFilters(**filter_kwargs)
    except Exception as exc:
        logger.warning("Invalid search filters: %s", exc)
        return {"error": "invalid_filters", "details": str(exc)}

    try:
        client = await _get_client()
        result_page = await client.search(
            filters, page=page, size=size, sort_by=sort_by, direction=direction,
        )
        return result_page.model_dump(mode="json")
    except YokAtlasError as exc:
        logger.warning("YÖKATLAS error in search_programs: %s", exc)
        return _format_yok_error(exc)
    except Exception as exc:
        logger.exception("Unexpected error in search_programs")
```

`logging` formats `%s` with `str(exc)` and does not escape control characters. `universite`, `program` and `il` are plain `str` fields with no pattern (`yokatlas_mcp_server.py:142-159`), and `sort_by` is a free string (`yokatlas_mcp_server.py:190-196`). `yokatlas_py.exceptions.LookupError` carries the looked-up `name` (`_format_yok_error`, `yokatlas_mcp_server.py:90-97`), so a lookup failure message is a likely place for the raw value to appear. The same pattern is used in `search_netler` (`yokatlas_mcp_server.py:332-345`).

## Steps to reproduce
1. Prerequisites: Python 3.12 and `uv`. Network access to YÖK Atlas, which the tool needs for normal operation. No accounts or keys.
2. Start the server at the tested commit, as the README describes:
   ```
   uvx --from git+https://github.com/saidsurucu/yokatlas-mcp@6f034eca77152b0e3eab9ad8ee0a48057eb8bcf5 yokatlas-mcp
   ```
3. Call the tool with a university name that contains CR/LF:
   ```json
   {"universite": "tofu-poc\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx",
           args=["--from", "git+https://github.com/saidsurucu/yokatlas-mcp@6f034eca77152b0e3eab9ad8ee0a48057eb8bcf5", "yokatlas-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("search_programs", {"universite": "tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the server's stderr (printed in the same terminal by `stdio_client`). If the lookup error repeats the name, the warning `YÖKATLAS error in search_programs: ...tofu-poc` is followed by a separate line that starts with `FAKE-LOG-ENTRY`. The tool result shows the same message in `details`.

## Expected behavior
Caller-controlled text should be neutralized before it is logged, for example by escaping `\r` and `\n` or logging `repr()` of the value, so one call always produces one log record line.

## Actual behavior
Not observed in a surviving log (see internal notes). From the code, the exception text is logged as is.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. Forged log lines can mislead someone reading the server log. MCP clients often save server stderr to log files, and the README also offers a hosted remote endpoint (`https://yokatlasmcp.fastmcp.app/mcp`), where the logs belong to the operator. The effect is limited to log integrity, so severity is low.

## Suggested fix
Use a logging filter or formatter that replaces `\r` and `\n` in the rendered message, or log `%r` of the exception instead of `%s`. Optionally reject control characters in the free-text filters (`universite`, `program`, `il`, `sort_by`) at the tool boundary, since valid names never contain them.

## Status on the default branch
Still present at `6f034ec` (2026-07-23). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issues and 2 pull requests (fetched 2026-10-01) and the README on the default branch. Issue #2 (closed 2025-08-05) and its fix, PR #3 (closed 2025-08-04), are about empty enum values in the search tools' parameter schema and do not touch logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` (runtime tracer), the only sanitizer listed.
- Campaigns and executions: e2-0922, 1 exec / 0 ok (60 s). No run log survived (`log_available: false`), so there is no recorded input or output; the reproduction is derived from the code.
- Evidence (verbatim, trimmed): none available.
- Hand-check hints: unclear. The logging sink is real and unneutralized, but whether caller CR/LF reaches it depends on `yokatlas-py` 0.7.0 (locked in `uv.lock`), whose exception messages were not checked here: if `SearchFilters` is a pydantic model, its validation errors show input with `repr`, which escapes CR/LF; a `LookupError` message may or may not include the raw name. The fuzzy lookup may also run locally on cached tables or need the network; not verified. The only logged execution failed, so the tracer probably saw the exception path (possibly a network error in the sandbox), not a confirmed injected line. Run the reproduction before filing; if no second line appears, drop this draft.
</details>
