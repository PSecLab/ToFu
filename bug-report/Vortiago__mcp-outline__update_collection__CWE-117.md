# `update_collection` forwards CR/LF in `name`/`description` unchanged (possible CWE-117, no log sink found)

**Repository:** `Vortiago/mcp-outline` · **Tool:** `update_collection` · **Tested commit:** `1e80cc9`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`update_collection` passes `collection_id`, `name`, `description` and `color` to Outline's `collections.update` API without checking for control characters. A fuzzer flagged CR/LF in these arguments as possible log injection. I could not find any place in this server where those values are written to a log: in stdio mode logging is limited to CRITICAL, and in HTTP/SSE mode the INFO logs do not include request bodies. This is at most an input-validation note.

## Details
The tool hands the arguments to the client unchanged (`src/mcp_outline/features/documents/collection_tools.py:265-287`):

```python
            try:
                client = await get_outline_client()
                ...
                collection = await client.update_collection(
                    collection_id, name, description, color
                )
                ...
            except OutlineClientError as e:
                return f"Error updating collection: {str(e)}"
```

The client puts them into a JSON body (`src/mcp_outline/utils/outline_client.py:705-716`). Neither function logs. Logging is configured in `src/mcp_outline/server.py:151-172`:

```python
    if transport_mode == "stdio":
        ...
        logging.basicConfig(
            level=logging.CRITICAL,  # Only show critical errors
            format="%(message)s",
            force=True,
        )
```

In SSE/streamable-HTTP mode the level is INFO and `httpx` request logging is on, but `httpx` logs the method, URL and status line, not the JSON body.

## Steps to reproduce
1. Prerequisites: Python and `uv`. An Outline API key is only needed to reach the API; the fuzzing run had none.
2. Start the server as the README describes (`uvx mcp-outline`, stdio), pinned to the tested commit: `uvx --from git+https://github.com/Vortiago/mcp-outline@1e80cc98a703a25885e916fd6229655d442d692d mcp-outline`.
3. Call the tool with `{"collection_id": "tofu-poc", "name": "tofu\r\nFAKE-LOG-ENTRY", "description": "desc", "color": "#FF0000"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["--from", "git+https://github.com/Vortiago/mcp-outline@1e80cc98a703a25885e916fd6229655d442d692d", "mcp-outline"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("update_collection", {"collection_id": "tofu-poc", "name": "tofu\r\nFAKE-LOG-ENTRY", "description": "desc", "color": "#FF0000"})
               print(result)

   asyncio.run(main())
   ```
4. Without a key the tool returns the "Missing API key" message. Check the server's stderr: no line with `FAKE-LOG-ENTRY` appears. With a key and a real collection ID, the name is stored in Outline as given.

## Expected behavior
Control characters in a collection name are rejected or stored as given, and are never logged unescaped.

## Actual behavior
The values are forwarded unchanged. I found no log write of them. Tool output from the fuzzing run:

```
Error updating collection: Outline client error: Missing API key. Set OUTLINE_API_KEY in .mcp-outline.env (project) or ~/.config/mcp-outline/.env (user), ...
```

## Impact
The arguments are chosen by the LLM and can be steered by prompt injection. In this server they do not reach a log, so there is no log forging here. A collection name with embedded line breaks could look odd in Outline's UI or in Outline's own logs, which are outside this repository. Very low.

## Suggested fix
Optional hardening: reject `\r`, `\n` and other control characters in `collection_id` and `name` before calling the API. No logging change is needed at this commit.

## Status on the default branch
Unchanged at `1e80cc9` (2026-07-19). The default branch has no commits after the tested commit.

## Prior reports
No issue or PR reports control characters in tool arguments, log injection, or `update_collection` input handling. Searched all 19 issues and 139 pull requests (fetched 2026-10-01). Related context only:
- #38 "fix: Fix MCP server STDIO output issues" (PR, closed 2025-11-17) and #39 "fix: More log output reduction." (PR, closed 2025-11-17): limit stdio-mode logging to critical messages and force that configuration. This is the `logging.CRITICAL` setup cited above, which is why no log sink exists in stdio mode. Not reports of this issue.
- Documentation: CLAUDE.md: "No stdout/stderr logging (MCP uses stdio)" (a project rule consistent with finding no log write on this path). README.md and docs/ say nothing about validating control characters in collection names. There is no SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, which only checks the input for `\r`/`\n` ("Silent Bug Alert"); it observed no log.
- Campaigns and executions: `corpus-sbx` 2,560 execs / 2,558 success (60 s); `e2-0922` 1,536 / 1,482.
- Evidence (verbatim, trimmed): input `{'collection_id': 'valid-collection-id', 'name': 'test\nInjectedLogEntry', 'description': 'desc\r\nAnotherLogLine', 'color': '#FF0000'}`, output `'Error updating collection: Outline client error: Missing API key. ...'`. Other samples: runs of `\r` and `\x7f` in `collection_id`/`name`.
- Hand-check hints: weak, likely a false positive. No logger call on the tool path, stdio logging is CRITICAL-only, and the Missing-API-key error text contains no caller data. Every fuzzed call stopped at the missing key. Recommend not filing.
</details>
