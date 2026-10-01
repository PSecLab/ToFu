# Log injection in `list`: raw `uri` with CR/LF is written to the debug log

**Repository:** `Xuanwo/mcp-server-opendal` · **Tool:** `list` · **Tested commit:** `f49ee92`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`list` lists entries under an OpenDAL path. Its first statement logs the caller's `uri` with an f-string, before any parsing or validation. A `uri` containing `\r\n` therefore writes extra, attacker-chosen lines to the server log. The line is logged at DEBUG, so it only shows up when the server runs with `LOG_LEVEL=DEBUG`; the impact is low.

## Details
`src/mcp_server_opendal/server.py:13-21` and `:95-108` (tested commit):

```python
default_log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
mcp = FastMCP("opendal_service", log_level=default_log_level)
...
    logger.debug(f"Listing directory content: {uri}")
    try:
        resource, path = parse_uri(uri)
        if path and not path.endswith("/"):
            path = path + "/"
        entries = await resource.list(path)
        return str(entries)
    except Exception as e:
        logger.error(f"Failed to list directory content: {e!s}")
        return f"Error: {e!s}"
```

`uri` is logged exactly as received. `parse_uri()` passes it through `urllib.parse.urlparse`, which drops CR/LF, but only after the debug line is written. `resource.list()` then logs the decoded prefix again at DEBUG (`resource.py:85`); because `parse_uri()` calls `unquote()`, a `%0D%0A` in the URI becomes a real line break in that second line as well.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. No storage backend is needed for the first debug line.
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
               result = await session.call_tool("list", {"uri": "fs://x\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Look at the server's stderr. The debug line is split in two: `Listing directory content: fs://x`, then a line that reads only `FAKE-LOG-ENTRY`.

## Expected behavior
Control characters in `uri` are escaped before logging, so one call gives one log line.

## Actual behavior
The raw value is logged. The fuzzing run did not use `LOG_LEVEL=DEBUG`. What it recorded is the ERROR line, which is multi-line because of pydantic's own message format:

```
input:  {'uri': '[object Object]'}
log:    Failed to list directory content: 1 validation error for OpendalResource
        uri
          Input should be a valid URL, relative URL without a base [type=url_parsing, input_value='://', input_type=str]
```

## Impact
The LLM chooses `uri` and can be steered by prompt injection. With debug logging on, an attacker can add fake lines to the server's stderr log and make it less trustworthy for review. Default deployments log at INFO and are not affected.

## Suggested fix
Use lazy `%r` formatting for caller-controlled values, for example `logger.debug("Listing directory content: %r", uri)`, here and in the other debug lines that log paths (`server.py:58, 123, 145`, `resource.py:85, 104, 109, 141`).

## Status on the default branch
Still present at `f49ee92` (2025-04-10). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 4 issues and 12 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The README documents only how to configure services through `OPENDAL_<ALIAS>_*` variables; it says nothing about path containment under a root, logging, or untrusted input. PR #16 (open) is a third-party scan badge whose only finding is base64 use.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` only.
- Campaigns and executions: corpus-sbx 3584 exec / 3576 ok; e2-0922 1024 exec / 999 ok (60 s budgets).
- Evidence (verbatim, trimmed): `{'uri': ''}`, `{'uri': '[object Object]'}`, `{'uri': '/etc/passwd\x00'}` all returned `Error: 1 validation error for OpendalResource\nuri\n  Input should be a valid URL, relative URL without a base [type=url_parsing, input_value='://', input_type=str] ...` and logged the same text prefixed with `Failed to list directory content: `.
- Hand-check hints: weak. Same situation as `get_info`: the fuzzer's alert fired on pydantic's own multi-line message, which is a false positive as such. The real CWE-117 is the DEBUG line at `server.py:95` (and `resource.py:85` via `unquote()`), confirmed in source, not exercised by the run. The `resource.py:85` line is only reached with a configured backend, because `OpendalResource("fs")` fails without `OPENDAL_FS_TYPE`. Consider filing `list`, `get_info` (and `read`, `server.py:123`) as one issue.
</details>
