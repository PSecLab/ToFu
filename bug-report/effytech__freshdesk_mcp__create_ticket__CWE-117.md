# Log injection in `create_ticket`: reported by fuzzing, but no log sink for the arguments was found (unconfirmed)

**Repository:** `effytech/freshdesk_mcp` · **Tool:** `create_ticket` · **Tested commit:** `f7e2a00`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`create_ticket` builds a JSON body from its arguments and POSTs it to the Freshdesk API. A fuzzing run flagged it for log injection because arguments containing CR/LF were accepted. On reading the code at the tested commit, none of the `create_ticket` arguments are passed to a logger or printed, so CR/LF in them does not reach a log through this tool. This draft records what was checked; as it stands it does not describe a vulnerability.

## Details
Logging in `src/freshdesk_mcp/server.py` at `f7e2a00` is limited to:

```python
# Set up logging
logging.basicConfig(level=logging.INFO)
...
def main():
    logging.info("Starting Freshdesk MCP server")
    mcp.run(transport='stdio')
```

`create_ticket` (`server.py:224-303`) puts `subject`, `description`, `email`, `custom_fields` and `additional_fields` into a dict and sends it with `client.post(url, headers=headers, json=data)`. The URL comes from the `FRESHDESK_DOMAIN` environment variable, not from the arguments. The JSON encoder escapes CR/LF in the body. With `level=logging.INFO`, httpx logs one `HTTP Request: POST ...` line per call, which contains only that environment-derived URL and the status line. The error branches return `str(e)` to the client but do not log it.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. A Freshdesk account with an API key (`FRESHDESK_API_KEY`) and its domain (`FRESHDESK_DOMAIN`, e.g. `yourcompany.freshdesk.com`). Without them the call still runs, but the request fails before reaching Freshdesk.
2. Install the server from source:
   ```
   git clone https://github.com/effytech/freshdesk_mcp.git
   cd freshdesk_mcp && git checkout f7e2a00c6d92d6a3511153fd56a1afa72b208b41
   uv venv .venv && source .venv/bin/activate
   uv pip install -e .
   ```
   The client script below starts it with `freshdesk-mcp`, passing the two variables through `env`.
3. Call the tool with these arguments:
   ```json
   {"subject": "tofu-poc", "description": "line one\r\nFAKE-LOG-ENTRY", "source": 2, "priority": 1, "status": 2, "email": "tofu-poc@example.com"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="freshdesk-mcp",
           args=[],
           env={"FRESHDESK_API_KEY": "<your test key>", "FRESHDESK_DOMAIN": "<yourcompany>.freshdesk.com"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_ticket", {"subject": "tofu-poc", "description": "line one\r\nFAKE-LOG-ENTRY", "source": 2, "priority": 1, "status": 2, "email": "tofu-poc@example.com"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the server's stderr. Based on the code, it should show only the startup line, the SDK's `Processing request of type CallToolRequest` line and the httpx request line, and no line starting with `FAKE-LOG-ENTRY`. This was not run.

## Expected behavior
CR/LF from tool arguments never reaches a log record unescaped.

## Actual behavior
By code reading, that already holds for `create_ticket` at this commit. The fuzzer's alert came from an input-side check, not from an observed log line.

## Impact
None found for `create_ticket`. If argument logging is added later (for example `logging.info(f"Creating ticket: {subject}")`), `subject` and `description` would need CR/LF escaping, because ticket descriptions commonly contain line breaks.

## Suggested fix
No change is needed for this tool as written. If you add argument logging, log `repr()` of the values or use a `logging.Formatter` that escapes `\r` and `\n`.

## Status on the default branch
Unchanged at `f7e2a00` (2026-07-30). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 14 issues and 36 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection` only. In `src/sanitizers/base.py:60-63` that check returns true whenever the input string contains `\r` or `\n`; it does not observe any log sink. The introspection variant (`check_introspection_log_injection`) did not fire.
- Campaigns and executions: e2-0922 1 exec / 0 ok (60 s).
- Evidence: none. `log_available: false`, no run log survived. The reproduction above is derived entirely from the code at `f7e2a00` and was not run.
- Hand-check hints: weak, almost certainly a false positive. A multi-line `description` is normal input for a ticket, and no logging call receives any `create_ticket` argument (only `logging.basicConfig` at line 12 and `logging.info("Starting Freshdesk MCP server")` at line 1273 exist in the module). I would not file this. Side finding, out of scope for this item and not verified: `update_canned_response_folder` calls `print(folder_id, name)` at `server.py:630`, which writes caller-controlled text to stdout, i.e. the stdio JSON-RPC channel. A `name` containing a newline and a JSON object could inject a message into the client's protocol stream. That deserves its own look.
</details>
