# `delete-upstream-relation` accepts control characters in its arguments (flagged as CWE-117, no log sink found)

**Repository:** `ocean-zhc/dolphinscheduler-mcp` · **Tool:** `delete-upstream-relation` · **Tested commit:** `d44f0bd`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`delete-upstream-relation` deletes upstream task relations through the DolphinScheduler REST API. Our fuzzer sent `projectCode` values containing CR and other control characters and reported possible log injection because the tool returned normally. On review, the value is rejected by `int()` and the tool returns `Invalid parameter format`; no logger call on this path receives any argument. We do not think this tool has a log injection. The only remaining observation is that the integer types declared on the tool class are not enforced or published, so malformed values reach the handler at all.

## Details
The handler converts the path parameters to integers and returns a fixed message on failure (`src/dolphinscheduler_mcp/tools_generated/process_task_relation_tools.py:247-248` and `:280-284`):

```python
projectCode = int(projectCode) if projectCode is not None else None
taskCode = int(taskCode) if taskCode is not None else None
...
except ValueError:
    return {
        "success": False,
        "error": "Invalid parameter format"
    }
```

`preTaskCodes` is passed to `client.request(..., params=params)` (`:270-278`), which hands it to aiohttp as a query parameter (`src/dolphinscheduler_mcp/client.py:78`); aiohttp percent-encodes it. `client.request` does not log. The module logger is used only at import and registration time (`:15`, `:664`, `:674`).

The class-level `schema` declares `projectCode` and `taskCode` as `integer`, but `FastMCPTool._register` never passes it to `mcp.tool()`. It generates an untyped `tool_fn(projectCode, taskCode, preTaskCodes)` and registers that (`src/dolphinscheduler_mcp/fastmcp_compat.py:62-85`), so FastMCP neither validates nor advertises the integer types.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and the `mcp` Python package for the client script. A DolphinScheduler backend is not needed for this call, because it fails before any request is sent.
2. Install and start the server from a checkout (the README's `ds-mcp` entry point; with no transport argument `mcp.run()` uses stdio):

   ```bash
   git clone https://github.com/ocean-zhc/dolphinscheduler-mcp && cd dolphinscheduler-mcp
   git checkout d44f0bd
   pip install -e .
   ```
   The server writes its own log lines to stdout, so the client may print JSON parse warnings for them; they did not break our fuzzing sessions.
3. Call the tool:

   ```json
   {"projectCode": "1\r\nFAKE-LOG-ENTRY", "taskCode": "1", "preTaskCodes": "1"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="ds-mcp", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("delete-upstream-relation", {"projectCode": "1\r\nFAKE-LOG-ENTRY", "taskCode": "1", "preTaskCodes": "1"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the result text `{'success': False, 'error': 'Invalid parameter format'}`. No `FAKE-LOG-ENTRY` line is written by this tool.

## Expected behavior
Non-integer `projectCode` and `taskCode` values are rejected by schema validation before the handler runs, and the published input schema says they are integers.

## Actual behavior
The value reaches the handler and is rejected there. Output from our run (input `{'projectCode': '^\x0f\r\x10\x15\x1a\x1c\x0fCode:" "proj05', 'taskCode': '', 'preTaskCodes': ''}`):

```
{'success': False, 'error': 'Invalid parameter format'}
```

## Impact
None found for log injection. MCP tool arguments come from the LLM and can be steered by prompt injection, but on this path they never reach a log. The missing type enforcement is a robustness issue.

## Suggested fix
Optional hardening: pass the class `schema` through to registration, or generate `tool_fn` with type annotations (`projectCode: int, taskCode: int, preTaskCodes: str`), so FastMCP validates and advertises the types.

## Status on the default branch
The tested commit `d44f0bd` (2025-05-14) is the current head of the default branch, so the code above is unchanged.

## Prior reports
- #1 "Add MseeP.ai badge to README" (PR, open 2025-05-03): a third-party badge PR whose automated scan flags `exec()` in `src/dolphinscheduler_mcp/fastmcp_compat.py:81`, the code that builds the untyped `tool_fn` wrapper mentioned above. It says nothing about type enforcement or logging, so it is not a report of this behaviour and fixes nothing.
- No other issue or PR exists (0 issues, 2 PRs fetched 2026-10-01). The README and `docs/` say nothing about argument validation or log handling.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; only `check_log_injection` fired. That check (`src/sanitizers/base.py:60-63` in ToFu) only tests whether an input string contains `\r` or `\n`; it does not observe a log sink.
- Campaigns and executions: `corpus-sbx` 3584/3584, `e2-0922` 1024/1024, 60 s budget each.
- Evidence (verbatim, trimmed): input `{'projectCode': '^\x0f\r\x10\x15\x1a\x1c\x0fCode:" "proj05', 'taskCode': '', 'preTaskCodes': ''}` -> output `"{'success': False, 'error': 'Invalid parameter format'}"`. All three evidence calls are the same shape and output.
- Hand-check hints: weak, likely a false positive. Caller input hits `int()` and is discarded; nothing on this path logs it. Probably do not file as a security issue. Separate, server-wide observation (not verified by running): `server.py:19-23` sends all logging to `sys.stdout`, which is the stdio JSON-RPC channel when `mcp.run()` uses its default stdio transport; `update_connection_settings` logs the caller's `api_url` there unescaped (`environment_update_tools.py:58`). If that is worth reporting, it belongs in the `update_connection_settings` issue, not this one.
</details>
