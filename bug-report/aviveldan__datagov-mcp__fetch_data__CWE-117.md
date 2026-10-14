# Log injection in `fetch_data`: CR/LF in `dataset_name` and in upstream error pages reach the logs unneutralized

**Repository:** `aviveldan/datagov-mcp` · **Tool:** `fetch_data` · **Tested commit:** `31143d3`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`fetch_data` looks up a dataset and returns the records of its first resource. It writes the caller's `dataset_name` into a `ctx.info()` message, and when the CKAN API returns an HTTP error it writes the full response body into a `ctx.error()` message. Neither value is stripped of CR/LF. A `dataset_name` value or an upstream error page can therefore add extra lines to the server log and to the log notifications the client receives. The impact is low, but forged or broken-up log lines make the logs harder to trust.

## Details
`datagov_mcp/api.py:69-73` builds the error message from the raw response body:

```python
        except httpx.HTTPStatusError as e:
            last_error = CKANAPIError(
                f"HTTP {e.response.status_code}: {e.response.text}",
                status_code=e.response.status_code,
            )
```

`datagov_mcp/server.py` (lines 248-251 and 277-279) logs the caller's `dataset_name` (line 248) and then the error message (line 278):

```python
    await ctx.info(f"Fetching data for dataset: {dataset_name}")
    try:
        # First, get the dataset metadata
        package_data = await ckan_api_call("package_show", params={"id": dataset_name})
    ...
    except CKANAPIError as e:
        await ctx.error(f"Failed to fetch data: {e.message}")
        return {"error": str(e.message)}
```

FastMCP's `Context.info()` and `Context.error()` send the text to the client as a `notifications/message` log entry and also write `Sending <LEVEL> to client: <text>` to the `fastmcp.server.context.to_client` logger. That logger is clamped to DEBUG (I checked fastmcp 3.4.2; `uv.lock` pins 3.2.4), so the server-side copy is printed when `FASTMCP_LOG_LEVEL=DEBUG`. Nothing on this path escapes `\r` or `\n`, and the body is not truncated. `fetch_data` also returns it to the caller as `{"error": ...}` at line 279.

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
   {"dataset_name": "tofu-poc\r\nFAKE-LOG-ENTRY"}
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
               result = await session.call_tool("fetch_data", {"dataset_name": "tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the server's stderr shows the `ctx.info()` record split in two, with a line that starts with `FAKE-LOG-ENTRY` and has no level prefix of its own. The client's log callback receives a message whose text contains the raw `\r\n`. When data.gov.il answers with an HTTP error, the `ctx.error()` record that follows also contains the raw response body; if that body is an HTML error page, it spans many lines.

## Expected behavior
Each call should produce single-line log records. CR and LF in `dataset_name` and in upstream response bodies should be escaped or removed before they are logged, and long upstream bodies should be truncated.

## Actual behavior
ToFu's runtime tracer captured this record on the `fastmcp.server.context.to_client` logger for the call `{"dataset_name": "", "limit": 0, "offset": 0}` (trimmed; `\r\n` and `\n` stand for raw CR/LF characters in the record):

```
Sending ERROR to client: Failed to fetch data: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\n  <meta name="viewport" content="width=device-width" />\r\n     <meta name="viewport" content="initial-scale=1, maximum-scale=1, user-scalable=no" />\r\n        <lin ...
```

The CR/LF in this record comes from the upstream HTML page. The caller-controlled path through `dataset_name` (line 248) follows from the code above; the recorded calls did not include a CR/LF payload.

## Impact
Tool arguments are chosen by the LLM, and prompt injection in content the model reads (for example dataset titles or descriptions) can steer them. A crafted `dataset_name` can add a fake line to the server's DEBUG log or to the client's log view, and every failed call dumps the upstream error page into the logs. There is no code execution or data exposure here. This is a low-severity log-integrity issue.

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

Apply the same helper to the `CKAN API error: ...` message at `api.py:65`. Also wrap caller values before they go into log text, for example `await ctx.info(f"... {_log_safe(dataset_name)}")` at `datagov_mcp/server.py:248`.

## Status on the default branch
Still present at `31143d3` (2026-04-22). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 9 issues and 16 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: `log-injection` (CWE-117), fired by `check_introspection_log_injection` on logger `fastmcp.server.context.to_client`. All sanitizers that fired for this tool: `check_introspection_hardcoded_credentials`, `check_introspection_log_injection`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx: 1 exec / 1 ok (budget 60s); repo24-b: 26112 exec / 26106 ok (budget 4200s); repo24-b: 32256 exec / 32253 ok (budget 4200s); e2-0922: 1 exec / 1 ok (budget 60s).
- Evidence (verbatim, trimmed):
  - [corpus-sbx] input `{'dataset_name': '', 'limit': 0, 'offset': 0}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to fetch data: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\n  <me ...`
  - [corpus-sbx] input `{'dataset_name': "1' OR '1'='1", 'limit': -1, 'offset': 0}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to fetch data: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\n  <me ...`
  - [corpus-sbx] input `{'dataset_name': 'test_dataset', 'limit': 1000000000, 'offset': 0}`, output `None`, sanitizers ['check_introspection_log_injection']. Logged: `Sending ERROR to client: Failed to fetch data: HTTP 404: <!DOCTYPE html>\r\n<html dir="rtl" lang="he-IL" class="no-js">\r\n    <head>\r\n  <meta charset="UTF-8">\r\n  <me ...`
- Hand-check hints: weak as reported, low severity. All evidence records get their CR/LF from the upstream HTML error page (HTTP 404; the 404 is a gov.il "page not found" HTML page), not from caller input. A real caller-controlled variant exists by code reading: `dataset_name` is interpolated into `ctx.info()` at `datagov_mcp/server.py:248` with no CR/LF handling. I did not run it. The server-side copy goes to a DEBUG-clamped logger, so it is only visible with DEBUG logging; the client copy is a JSON log notification, and clients that log raw JSON-RPC would show `\r\n` escaped.
- Other alerts: `check_introspection_hardcoded_credentials` is in the triggered list but not in this item's evidence. In sibling tools (`status_show`, `license_list`) it matched the CloudFront `Request ID` against the `sk-` pattern, a false positive; probably the same here. `check_resource_exhaustion` is in the triggered list but not in this item's evidence (siblings show 2.5-5.9 s calls against a 2 s limit, most likely slow upstream responses).
- All 13 `aviveldan/datagov-mcp` drafts share one root cause (`api.py:71` plus unescaped `ctx.info`/`ctx.error` text). Consider filing one consolidated issue that lists the tools instead of 13 issues.
- Fuzzed commit `31143d3077683f997e78257cf0c59c1a4c1ff30c`; `head_sha` is the same commit, so nothing changed upstream since the run.

</details>
