# Missing output encoding in `live_streaming_get_play_urls`: `play_domain`, `bucket` and `stream_name` are echoed unescaped into the returned URLs

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `live_streaming_get_play_urls` · **Tested commit:** `52dd335`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`live_streaming_get_play_urls` builds FLV, M3U8 and WHEP playback URLs from `play_domain`, `bucket` and `stream_name` by string interpolation and returns them with the raw inputs. None of the values is validated or encoded, so markup, quotes, template braces and control characters come back verbatim. The output is plain text (a Python `dict` repr) and the URL scheme is fixed to `https://`, so this only matters if a client renders tool output as HTML or Markdown. Severity is low.

## Details
`src/mcp_server/core/live_streaming/live_streaming.py:311-337` (tested commit), trimmed:

```python
def get_play_urls(self, play_domain: str, bucket: str, stream_name: str) -> Dict[str, Any]:
    flv_url = f"https://{play_domain}/{bucket}/{stream_name}.flv"
    m3u8_url = f"https://{play_domain}/{bucket}/{stream_name}.m3u8"
    whep_url = f"https://{play_domain}/{bucket}/{stream_name}.whep"
    logger.info(f"Generated playback URLs for stream: {stream_name}")
    return {
        "status": "success",
        "play_domain": play_domain,
        "bucket": bucket,
        "stream_name": stream_name,
        "flv_url": flv_url, "m3u8_url": m3u8_url, "whep_url": whep_url, ...
    }
```

The handler (`src/mcp_server/core/live_streaming/tools.py:173-175`) returns `str(result)`. The schema only requires the three fields to be strings, so empty values are also accepted and produce URLs such as `https://<domain>//.flv`.

## Steps to reproduce
1. Prerequisites: Python 3.12 and `uv`. No credentials or network access are needed: the tool only builds strings.
2. Install and start the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
3. Call the tool with:

   ```json
   {"play_domain": "play.example.com\"><img src=x onerror=alert(1)>{{7*7}}", "bucket": "b", "stream_name": "s"}
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
                   "live_streaming_get_play_urls",
                   {"play_domain": "play.example.com\"><img src=x onerror=alert(1)>{{7*7}}",
                    "bucket": "b", "stream_name": "s"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that `play_domain`, `flv_url`, `m3u8_url` and `whep_url` in the returned text all contain the `"><img ...>` markup and `{{7*7}}` verbatim.

## Expected behavior
`play_domain` is validated as a hostname and `bucket` / `stream_name` as names (or percent-encoded as URL path segments), so the returned URLs are well-formed and cannot carry markup.

## Actual behavior
The inputs are copied into the output unchanged, with `"status": "success"`. From the fuzzing run:

```
input:  {'play_domain': '\x00b2et{{{{{{{{{{{{', 'bucket': '', 'stream_name': ''}
output: {'status': 'success', 'play_domain': '\x00b2et{{{{{{{{{{{{', 'bucket': '', 'stream_name': '',
         'flv_url': 'https://\x00b2et{{{{{{{{{{{{//.flv', ...
         'message': 'Playback URLs generated successfully'}
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. If a client renders tool output or these URLs as HTML or Markdown links, injected markup could be displayed or executed there. Because the scheme is fixed to `https://`, a `javascript:` link cannot be produced. The more practical effect is malformed playback URLs reported as a success. Severity is low.

## Suggested fix
- Validate `play_domain` as a hostname, and `bucket` / `stream_name` against the allowed name characters; reject empty values.
- Or at least percent-encode `bucket` and `stream_name` with `urllib.parse.quote` when building the path.
- Return JSON (`json.dumps`) instead of a Python `dict` repr.

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 10 issues and 52 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2381 ok (60 s budget).
- Evidence (verbatim, trimmed): all three calls are the same pattern, `{'play_domain': '\x00b2et{{{{{{{{{{{{...', 'bucket': '', 'stream_name': ''}` -> success dict with the value repeated in `play_domain`, `flv_url`, `m3u8_url`, `whep_url`. The matched token is `{{` in every case.
- Hand-check hints: weak. Only `{{` template braces were observed, in a plain-text `str(dict)`; there is no HTML or template rendering in the server. The markup payload in the reproduction is reasoned from the f-strings, not executed. Honest framing is "no validation or encoding of URL parts". Same pattern as `live_streaming_get_push_urls`; consider one combined issue.
</details>
