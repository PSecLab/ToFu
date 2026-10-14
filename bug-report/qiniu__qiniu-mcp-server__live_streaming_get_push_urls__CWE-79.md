# Missing output encoding in `live_streaming_get_push_urls`: `push_domain`, `bucket` and `stream_name` are echoed unescaped into the returned URLs

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `live_streaming_get_push_urls` · **Tested commit:** `52dd335`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`live_streaming_get_push_urls` builds RTMP and WHIP push URLs from `push_domain`, `bucket` and `stream_name` by string interpolation and returns them with the raw inputs. None of the values is validated or encoded, so markup, quotes, template braces and control characters come back verbatim. The output is plain text (a Python `dict` repr) and the schemes are fixed (`rtmp://`, `https://`), so this only matters if a client renders tool output as HTML or Markdown. Severity is low.

## Details
`src/mcp_server/core/live_streaming/live_streaming.py:285-309` (tested commit), trimmed:

```python
def get_push_urls(self, push_domain: str, bucket: str, stream_name: str) -> Dict[str, Any]:
    rtmp_url = f"rtmp://{push_domain}/{bucket}/{stream_name}"
    whip_url = f"https://{push_domain}/{bucket}/{stream_name}.whip"
    logger.info(f"Generated push URLs for stream: {stream_name}")
    return {
        "status": "success",
        "push_domain": push_domain,
        "bucket": bucket,
        "stream_name": stream_name,
        "rtmp_url": rtmp_url,
        "whip_url": whip_url,
        "message": "Push URLs generated successfully"
    }
```

The handler (`src/mcp_server/core/live_streaming/tools.py:145-147`) returns `str(result)`. The schema only requires the three fields to be strings, so empty values are also accepted.

## Steps to reproduce
1. Prerequisites: Python 3.12 and `uv`. No credentials or network access are needed: the tool only builds strings.
2. Install and start the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
3. Call the tool with:

   ```json
   {"push_domain": "push.example.com\"><img src=x onerror=alert(1)>{{7*7}}", "bucket": "b", "stream_name": "s"}
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
                   "live_streaming_get_push_urls",
                   {"push_domain": "push.example.com\"><img src=x onerror=alert(1)>{{7*7}}",
                    "bucket": "b", "stream_name": "s"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that `push_domain`, `rtmp_url` and `whip_url` in the returned text all contain the `"><img ...>` markup and `{{7*7}}` verbatim.

## Expected behavior
`push_domain` is validated as a hostname and `bucket` / `stream_name` as names (or percent-encoded as URL path segments), so the returned URLs are well-formed and cannot carry markup.

## Actual behavior
The inputs are copied into the output unchanged, with `"status": "success"`. From the fuzzing run:

```
input:  {'push_domain': '"push_domain": {{},', 'bucket': '', 'stream_name': ''}
output: {'status': 'success', 'push_domain': '"push_domain": {{},', 'bucket': '', 'stream_name': '',
         'rtmp_url': 'rtmp://"push_domain": {{},//', 'whip_url': 'https://"push_domain": {{},//.whip',
         'message': 'Push URLs generated successfully'}
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. If a client renders tool output or these URLs as HTML or Markdown links, injected markup could be displayed or executed there. The schemes are fixed, so a `javascript:` link cannot be produced. The more practical effect is malformed push URLs reported as a success. Severity is low.

## Suggested fix
- Validate `push_domain` as a hostname, and `bucket` / `stream_name` against the allowed name characters; reject empty values.
- Or at least percent-encode `bucket` and `stream_name` with `urllib.parse.quote` when building the path.
- Return JSON (`json.dumps`) instead of a Python `dict` repr.

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 10 issues and 52 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2367 ok (60 s budget).
- Evidence (verbatim, trimmed): three near-identical calls, `{'push_domain': '"push_domain": {{},', 'bucket': '', 'stream_name': ''}` (and the `punsh_domain` / `punsh_domajn` mutations) -> success dict with the value repeated in `rtmp_url` and `whip_url`. The matched token is `{{` in every case.
- Hand-check hints: weak. Only `{{` template braces were observed, in a plain-text `str(dict)`; there is no HTML or template rendering in the server. The markup payload in the reproduction is reasoned from the f-strings, not executed. Same pattern as `live_streaming_get_play_urls`; consider one combined issue.
</details>
