# Log injection in `resource_search`: upstream HTTP error bodies are logged verbatim, CR/LF included

**Repository:** `aviveldan/datagov-mcp` · **Tool:** `resource_search` · **Tested commit:** `31143d3`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`resource_search` searches resources on data.gov.il by field values. When the CKAN API answers with an HTTP error, `ckan_api_call` puts the whole response body into the exception message, and the tool passes that message to `ctx.error()` unchanged. Error pages are multi-line HTML, so every failed call writes a full HTML document, CR/LF included, into the server log and into the log notification sent to the client. The caller cannot choose this content (the base URL is fixed), so the impact is low: multi-line, upstream-controlled log records.

## Details
`datagov_mcp/api.py:69-73` builds the error message from the raw response body:

```python
        except httpx.HTTPStatusError as e:
            last_error = CKANAPIError(
                f"HTTP {e.response.status_code}: {e.response.text}",
                status_code=e.response.status_code,
            )
```

`datagov_mcp/server.py` (lines 161 and 169-172) passes that message to `ctx.error()` (line 171):

```python
    await ctx.info("Searching for resources...")
    ...
        return await ckan_api_call("resource_search", params=params)
    except CKANAPIError as e:
        await ctx.error(f"Failed to search resources: {e.message}")
        raise
```

FastMCP's `Context.info()` and `Context.error()` send the text to the client as a `notifications/message` log entry and also write `Sending <LEVEL> to client: <text>` to the `fastmcp.server.context.to_client` logger. That logger is clamped to DEBUG (I checked fastmcp 3.4.2; `uv.lock` pins 3.2.4), so the server-side copy is printed when `FASTMCP_LOG_LEVEL=DEBUG`. Nothing on this path escapes `\r` or `\n`, and the body is not truncated.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No API key is needed. The CR/LF comes from the upstream response, so the live call only shows the problem while data.gov.il returns an HTTP error page.
2. Install and start the server as the README describes:

   ```bash
   git clone https://github.com/aviveldan/datagov-mcp.git
   cd datagov-mcp
   uv venv && source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```

   The client below starts the server over stdio and sets `FASTMCP_LOG_LEVEL=DEBUG` and `FASTMCP_ENABLE_RICH_LOGGING=false` (setting names as in fastmcp 3.4.2) so the server-side copy of each log message is printed to stderr as plain `LEVEL: message` lines.
3. Call the tool with these arguments:

   ```json
   {"query": "name:tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def on_log(params):
       print("CLIENT LOG NOTIFICATION:", repr(params.data))

   async def main():
       server = StdioServerParameters(
           command="/path/to/datagov-mcp/.venv/bin/python",
           args=["/path/to/datagov-mcp/server.py"],
           env={"FASTMCP_LOG_LEVEL": "DEBUG", "FASTMCP_ENABLE_RICH_LOGGING": "false"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write, logging_callback=on_log) as session:
               await session.initialize()
               result = await session.call_tool("resource_search", {"query": "name:tofu-poc"})
               print(result)

   asyncio.run(main())
   ```

   To reproduce without depending on the live API, add this test to `tests/test_tools.py`, which already defines `MockContext` and uses `respx`:

   ```python
   from datagov_mcp.api import CKANAPIError

   @respx.mock
   async def test_resource_search_error_body_logged_raw():
       respx.get(f"{BASE_URL}/action/resource_search").mock(
           return_value=Response(403, text="<html>\r\nFAKE-LOG-ENTRY\r\n</html>")
       )
       ctx = MockContext()
       with pytest.raises(CKANAPIError):
           await resource_search(ctx, query="name:tofu-poc")
       assert "\r\nFAKE-LOG-ENTRY" in ctx.error_messages[0]
   ```
4. Observe: during our run data.gov.il answered with HTML error pages (HTTP 404). The server's stderr shows the `Sending ERROR to client: ...` record followed by the lines of the HTML page, each without a level prefix of its own, and the client's log callback receives the same multi-line text. The test above passes, which shows the raw `\r\n` reaches `ctx.error()`.

## Expected behavior
Each failed call should produce one single-line log record with the status code and, at most, a short, escaped excerpt of the response body.

## Actual behavior
ToFu's runtime tracer captured this record on the `fastmcp.server.context.to_client` logger for the call `{"query": "", "order_by": "", "offset": 0, "limit": 0}` (trimmed; `\r\n` and `\n` stand for raw CR/LF characters in the record):

```
Sending ERROR to client: Failed to search resources: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\n  <meta name="viewport" content="width=device-width" />\r\n     <meta name="viewport" content="initial-scale=1, maximum-scale=1, user-scalable=no" />\r\n ...
```

## Impact
The caller cannot influence the logged body for this tool: it comes from data.gov.il, or from whatever answers in its place, such as a CDN error page. The practical effect is multi-line, multi-kilobyte log records on every failed call, and upstream-controlled text that looks like separate log lines. Low severity.

## Suggested fix
Neutralize and truncate before logging. In `datagov_mcp/api.py`, keep only a short excerpt of the body and escape line breaks:

```python
def _log_safe(value: object, limit: int = 300) -> str:
    text = str(value)[:limit]
    return text.replace("\r", "\\r").replace("\n", "\\n")

last_error = CKANAPIError(
    f"HTTP {e.response.status_code}: {_log_safe(e.response.text)}",
    status_code=e.response.status_code,
)
```

Apply the same helper to the `CKAN API error: ...` message at `api.py:65`.

## Status on the default branch
Still present at `31143d3` (2026-04-22). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 9 issues and 16 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: `log-injection` (CWE-117), fired by `check_introspection_log_injection` on logger `fastmcp.server.context.to_client`. All sanitizers that fired for this tool: `check_introspection_hardcoded_credentials`, `check_introspection_log_injection`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx: 1 exec / 1 ok (budget 60s); repo24-b: 18944 exec / 18938 ok (budget 4200s); e2-0922: 1 exec / 1 ok (budget 60s).
- Evidence (verbatim, trimmed):
  - [corpus-sbx] input `{'query': '', 'order_by': '', 'offset': 0, 'limit': 0}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to search resources: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\ ...`
  - [corpus-sbx] input `{'query': "1' OR '1'='1", 'order_by': '', 'offset': -1, 'limit': 100}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to search resources: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\ ...`
  - [corpus-sbx] input `{'query': 'test', 'order_by': 'name', 'offset': 999999999, 'limit': 999999999}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to search resources: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\ ...`
- Hand-check hints: weak, low severity. No caller string reaches the log for this tool; the CR/LF comes only from the upstream HTML error page (HTTP 404; the 404 is a gov.il "page not found" HTML page). The server-side copy is DEBUG-only by default. Caller values (`q`/`fq`/`sort` or `query`/`order_by`) are not logged; they would only reach the log if CKAN echoed them in an error body, and CKAN error bodies are JSON, where CR/LF is escaped (not checked against the live API).
- Other alerts: `check_introspection_hardcoded_credentials` is in the triggered list but not in this item's evidence. In sibling tools (`status_show`, `license_list`) it matched the CloudFront `Request ID` against the `sk-` pattern, a false positive; probably the same here. `check_resource_exhaustion` is in the triggered list but not in this item's evidence (siblings show 2.5-5.9 s calls against a 2 s limit, most likely slow upstream responses).
- All 13 `aviveldan/datagov-mcp` drafts share one root cause (`api.py:71` plus unescaped `ctx.info`/`ctx.error` text). Consider filing one consolidated issue that lists the tools instead of 13 issues.
- Fuzzed commit `31143d3077683f997e78257cf0c59c1a4c1ff30c`; `head_sha` is the same commit, so nothing changed upstream since the run.

</details>
