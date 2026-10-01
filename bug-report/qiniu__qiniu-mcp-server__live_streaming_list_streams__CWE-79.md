# Missing output encoding in `live_streaming_list_streams`: `bucket_id` is echoed unescaped in the result and spliced unencoded into the API query

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `live_streaming_list_streams` · **Tested commit:** `52dd335`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`live_streaming_list_streams` lists the streams of a live-streaming bucket. It returns the caller's `bucket_id` verbatim in both the success and the error result, so markup, quotes and template braces in `bucket_id` come back unchanged. The output is plain text (a Python `dict` repr), so this only matters if a client renders tool output as HTML or Markdown. The same value is also concatenated into the API query string without URL encoding, and logged unescaped on errors.

## Details
`src/mcp_server/core/live_streaming/live_streaming.py:526-572` (tested commit), trimmed:

```python
async def list_streams(self, bucket_id: str) -> Dict[str, Any]:
    ...
    url = f"https://{endpoint}/?streamlist&bucketId={bucket_id}"
    headers = self._get_auth_header(method="GET", url=url)
    ...
            else:
                logger.error(f"Failed to list streams in bucket: {bucket_id}, status: {status}, response: {text}")
                return {
                    "status": "error",
                    "bucket_id": bucket_id,
                    "message": f"Failed to list streams: {text}",
                    "status_code": status
                }
```

The handler (`src/mcp_server/core/live_streaming/tools.py:237-239`) returns `str(result)`. Three points:
- `bucket_id` is echoed in the result (`:560`, `:569`) without validation or encoding.
- `bucket_id` is inserted into the query at `:546` without `urllib.parse.quote`, so `&` or `#` in it changes the parameters of the authenticated request.
- The error branch at `:566` writes `bucket_id` into the log with an f-string, so CR/LF in it would split the log line.

## Steps to reproduce
1. Prerequisites: Python 3.12, `uv`, and network access to the Qiniu live endpoint (`mls.cn-east-1.qiniumiku.com` by default). No valid credentials are needed: with the placeholder configuration the API answers `401` and the tool returns its error result, which also echoes `bucket_id`.
2. Install and start the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
3. Call the tool with:

   ```json
   {"bucket_id": "b\"><img src=x onerror=alert(1)>{{7*7}}"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["--directory", "/path/to/qiniu-mcp-server", "run", "qiniu-mcp-server"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "live_streaming_list_streams",
                   {"bucket_id": "b\"><img src=x onerror=alert(1)>{{7*7}}"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that `bucket_id` in the returned text contains the `"><img ...>` markup and `{{7*7}}` verbatim.

## Expected behavior
`bucket_id` is validated against the allowed bucket-name characters (or encoded with `quote` before it goes into the URL), and the returned value cannot carry markup.

## Actual behavior
The value is echoed unchanged. From the fuzzing run (placeholder credentials):

```
input:  {'bucket_id': '"u{{'}
output: {'status': 'error', 'bucket_id': '"u{{', 'message': 'Failed to list streams:
         {"code":"1103",...,"message":"invalid header"}', 'status_code': 401}
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. If a client renders tool output as HTML or Markdown, injected markup in `bucket_id` could be displayed or executed there. The unencoded query lets the caller add parameters to the signed API request; the host stays the configured live endpoint. Severity is low.

## Suggested fix
- Validate `bucket_id` against the bucket-name rules and reject anything else.
- Build the query with `urllib.parse.urlencode({"bucketId": bucket_id})`.
- Log with `%r` instead of an f-string, and return JSON (`json.dumps`) instead of a Python `dict` repr.

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 10 issues and 52 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output` and `check_introspection_log_injection`.
- Campaigns and executions: corpus-sbx, recorded as 1 exec / 1 ok (60 s budget), although three evidence calls are listed.
- Evidence (verbatim, trimmed; `connectId` values dropped):
  - `{'bucket_id': '"u{{ccb""k'}` -> `{'status': 'error', 'bucket_id': '"u{{ccb""k', 'message': 'Failed to list streams: {"code":"1103",...,"message":"invalid header"}', 'status_code': 401}`
  - `{'bucket_id': '"u{{'}` -> same shape, 401
  - `{'bucket_id': '"u{{{"u{{cc'}` -> same shape, 401
- Hand-check hints: weak. Only `{{` template braces were observed, echoed into a plain-text `str(dict)` error. The 401 responses confirm the request reached the real Qiniu endpoint with placeholder credentials during fuzzing. The query-parameter splicing and the f-string `logger.error` are read from code, not executed. The `check_introspection_log_injection` hit on this tool was not backed by a recorded log line in the evidence.
</details>
