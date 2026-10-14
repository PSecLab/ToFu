# Log injection in `datastore_search`: CR/LF in `resource_id` and in upstream error pages reach the logs unneutralized

**Repository:** `aviveldan/datagov-mcp` · **Tool:** `datastore_search` · **Tested commit:** `31143d3`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`datastore_search` queries the records of a datastore resource. It writes the caller's `resource_id` into a `ctx.info()` message, and when the CKAN API returns an HTTP error it writes the full response body into a `ctx.error()` message. Neither value is stripped of CR/LF. A `resource_id` value or an upstream error page can therefore add extra lines to the server log and to the log notifications the client receives. The impact is low, but forged or broken-up log lines make the logs harder to trust.

## Details
`datagov_mcp/api.py:69-73` builds the error message from the raw response body:

```python
        except httpx.HTTPStatusError as e:
            last_error = CKANAPIError(
                f"HTTP {e.response.status_code}: {e.response.text}",
                status_code=e.response.status_code,
            )
```

`datagov_mcp/server.py` (lines 207-208 and 221-224) logs the caller's `resource_id` (line 207) and then the error message (line 223):

```python
    await ctx.info(f"Searching datastore for resource: {resource_id}")
    try:
    ...
        return await ckan_api_call("datastore_search", params=params)
    except CKANAPIError as e:
        await ctx.error(f"Failed to search datastore: {e.message}")
        raise
```

FastMCP's `Context.info()` and `Context.error()` send the text to the client as a `notifications/message` log entry and also write `Sending <LEVEL> to client: <text>` to the `fastmcp.server.context.to_client` logger. That logger is clamped to DEBUG (I checked fastmcp 3.4.2; `uv.lock` pins 3.2.4), so the server-side copy is printed when `FASTMCP_LOG_LEVEL=DEBUG`. Nothing on this path escapes `\r` or `\n`, and the body is not truncated.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No API key is needed. The `ctx.info()` part does not depend on the API response; the `ctx.error()` part needs data.gov.il to return an HTTP error.
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
   {"resource_id": "tofu-poc\r\nFAKE-LOG-ENTRY"}
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
               result = await session.call_tool("datastore_search", {"resource_id": "tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the server's stderr shows the `ctx.info()` record split in two, with a line that starts with `FAKE-LOG-ENTRY` and has no level prefix of its own. The client's log callback receives a message whose text contains the raw `\r\n`. When data.gov.il answers with an HTTP error, the `ctx.error()` record that follows also contains the raw response body; if that body is an HTML error page, it spans many lines.

## Expected behavior
Each call should produce single-line log records. CR and LF in `resource_id` and in upstream response bodies should be escaped or removed before they are logged, and long upstream bodies should be truncated.

## Actual behavior
ToFu's runtime tracer captured this record on the `fastmcp.server.context.to_client` logger for the call `{"resource_id": "", "q": "", "distinct": false, "plain": false, "limit": 0, "offset": 0, "fields": "", "sort": "", "include_total": false, "records_format": ""}` (trimmed; `\r\n` and `\n` stand for raw CR/LF characters in the record):

```
Sending ERROR to client: Failed to search datastore: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\n  <meta name="viewport" content="width=device-width" />\r\n     <meta name="viewport" content="initial-scale=1, maximum-scale=1, user-scalable=no" />\r\n ...
```

The CR/LF in this record comes from the upstream HTML page. The caller-controlled path through `resource_id` (line 207) follows from the code above; the recorded calls did not include a CR/LF payload.

## Impact
Tool arguments are chosen by the LLM, and prompt injection in content the model reads (for example dataset titles or descriptions) can steer them. A crafted `resource_id` can add a fake line to the server's DEBUG log or to the client's log view, and every failed call dumps the upstream error page into the logs. There is no code execution or data exposure here. This is a low-severity log-integrity issue.

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

Apply the same helper to the `CKAN API error: ...` message at `api.py:65`. Also wrap caller values before they go into log text, for example `await ctx.info(f"... {_log_safe(resource_id)}")` at `datagov_mcp/server.py:207`.

## Status on the default branch
Still present at `31143d3` (2026-04-22). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 9 issues and 16 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: `log-injection` (CWE-117), fired by `check_introspection_log_injection` on logger `fastmcp.server.context.to_client`. All sanitizers that fired for this tool: `check_introspection_hardcoded_credentials`, `check_introspection_log_injection`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx: 1 exec / 1 ok (budget 60s); repo24-b: 25600 exec / 25598 ok (budget 4200s); repo24-b: 31744 exec / 31743 ok (budget 4200s); e2-0922: 1 exec / 1 ok (budget 60s).
- Evidence (verbatim, trimmed):
  - [corpus-sbx] input `{'resource_id': '', 'q': '', 'distinct': False, 'plain': False, 'limit': 0, 'offset': 0, 'fields': '', 'sort': '', 'include_total': False, 'records_format': ''}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to search datastore: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\ ...`
  - [corpus-sbx] input `{'resource_id': 'valid_resource', 'q': '', 'distinct': False, 'plain': True, 'limit': 100, 'offset': 0, 'fields': '', 'sort': '', 'include_total': True, 'records_format': 'prototype'}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to search datastore: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\ ...`
  - [corpus-sbx] input `{'resource_id': '../../../../etc/passwd', 'q': '', 'distinct': False, 'plain': True, 'limit': 1000000000, 'offset': 0, 'fields': '', 'sort': '', 'include_total': True, 'records_format': 'csv'}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to search datastore: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\ ...`
- Hand-check hints: weak as reported, low severity. All evidence records get their CR/LF from the upstream HTML error page (HTTP 404; the 404 is a gov.il "page not found" HTML page), not from caller input. A real caller-controlled variant exists by code reading: `resource_id` is interpolated into `ctx.info()` at `datagov_mcp/server.py:207` with no CR/LF handling. I did not run it. The server-side copy goes to a DEBUG-clamped logger, so it is only visible with DEBUG logging; the client copy is a JSON log notification, and clients that log raw JSON-RPC would show `\r\n` escaped.
- Other alerts: `check_introspection_hardcoded_credentials` is in the triggered list but not in this item's evidence. In sibling tools (`status_show`, `license_list`) it matched the CloudFront `Request ID` against the `sk-` pattern, a false positive; probably the same here. `check_resource_exhaustion` is in the triggered list but not in this item's evidence (siblings show 2.5-5.9 s calls against a 2 s limit, most likely slow upstream responses).
- All 13 `aviveldan/datagov-mcp` drafts share one root cause (`api.py:71` plus unescaped `ctx.info`/`ctx.error` text). Consider filing one consolidated issue that lists the tools instead of 13 issues.
- Fuzzed commit `31143d3077683f997e78257cf0c59c1a4c1ff30c`; `head_sha` is the same commit, so nothing changed upstream since the run.

</details>
