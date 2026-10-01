# Log injection in `get_info`: raw `uri` with CR/LF is written to the debug log

**Repository:** `Xuanwo/mcp-server-opendal` · **Tool:** `get_info` · **Tested commit:** `f49ee92`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_info` returns metadata for an OpenDAL path. Its first statement logs the caller's `uri` with an f-string, before any parsing or validation. A `uri` containing `\r\n` therefore writes extra, attacker-chosen lines to the server log. The line is logged at DEBUG, so it only shows up when the server runs with `LOG_LEVEL=DEBUG`; the impact is low.

## Details
`src/mcp_server_opendal/server.py:13-21` and `:145-157` (tested commit):

```python
default_log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
mcp = FastMCP("opendal_service", log_level=default_log_level)
logging.basicConfig(level=log_level)
logger = logging.getLogger("mcp_server_opendal")
...
    logger.debug(f"Getting file info: {uri}")
    try:
        resource, path = parse_uri(uri)
        ...
    except Exception as e:
        logger.error(f"Failed to get file info: {e!s}")
```

`uri` is logged exactly as received. `parse_uri()` later passes the string through `urllib.parse.urlparse`, which drops CR/LF, but the debug line has already been written by then. The ERROR line logs exception text; the pydantic errors seen in testing quote the value with `repr()`, so they did not carry raw line breaks.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. No storage backend is needed, because the line is logged before the URI is parsed.
2. Start the server as the README describes, with debug logging: `LOG_LEVEL=DEBUG uvx mcp-server-opendal`. The client below does this itself.
3. Call the tool with:

   ```json
   {"uri": "fs://x\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["mcp-server-opendal"], env={"LOG_LEVEL": "DEBUG"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_info", {"uri": "fs://x\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Look at the server's stderr. The debug line is split in two: `Getting file info: fs://x`, then a line that reads only `FAKE-LOG-ENTRY`. With the default `%(message)s` format that second line looks the same as a real log line.

## Expected behavior
Control characters in `uri` are escaped before logging (for example `Getting file info: 'fs://x\r\nFAKE-LOG-ENTRY'`), so one call gives one log line.

## Actual behavior
The raw value is logged. The fuzzing run did not use `LOG_LEVEL=DEBUG`. What it recorded is the ERROR line, which is multi-line because of pydantic's own message format:

```
input:  {'uri': ''}
log:    Failed to get file info: 1 validation error for OpendalResource
        uri
          Input should be a valid URL, relative URL without a base [type=url_parsing, input_value='://', input_type=str]
```

## Impact
The LLM chooses `uri`, and prompt injection in content the agent reads can steer it. With debug logging on, an attacker can add fake lines to the server's stderr log, which makes it harder to trust when reviewing what the agent did. Nothing else is gained. Default deployments log at INFO and are not affected.

## Suggested fix
Log the value with `%r` instead of interpolating it, for example `logger.debug("Getting file info: %r", uri)`. The same applies to the other debug lines that log caller paths (`server.py:58, 95, 123`, `resource.py:85, 104, 109, 141`).

## Status on the default branch
Still present at `f49ee92` (2025-04-10). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 4 issues and 12 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The README documents only how to configure services through `OPENDAL_<ALIAS>_*` variables; it says nothing about path containment under a root, logging, or untrusted input. PR #16 (open) is a third-party scan badge whose only finding is base64 use.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` only.
- Campaigns and executions: corpus-sbx 3584 exec / 3582 ok; e2-0922 1024 exec / 1014 ok (60 s budgets).
- Evidence (verbatim, trimmed): `{'uri': ''}`, `{'uri': '/etc/passwd\x00'}` and `{'uri': 'http://127.0.0.1:8500'}` all returned `Error: 1 validation error for OpendalResource\nuri\n  Input should be a valid URL, ...` and logged `Failed to get file info: 1 validation error for OpendalResource\nuri\n ...` on logger `mcp_server_opendal`.
- Hand-check hints: weak. The fuzzer's alert is a false positive in itself: the newlines in the logged ERROR line come from pydantic's multi-line message, not from the input, and pydantic `repr()`-escapes the input. The real CWE-117 is the DEBUG line at `server.py:145`, confirmed in source but not exercised (the run was at INFO). I did not check whether OpenDAL error messages for a configured backend echo the raw path; if they do, `%0D%0A` in the path (decoded by `unquote()` in `parse_uri`) would reach the ERROR log too. Side observation: `resource.py:54` logs the whole backend option dict, including credentials such as `secret_access_key`, at DEBUG (CWE-532), so turning on DEBUG to reproduce this also dumps secrets to stderr.
</details>
