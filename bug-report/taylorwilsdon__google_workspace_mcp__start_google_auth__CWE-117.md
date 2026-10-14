# Log injection via the auth middleware: raw tool-call exceptions (with caller input) are logged unneutralized

**Repository:** `taylorwilsdon/google_workspace_mcp` · **Tool:** `start_google_auth` · **Tested commit:** `54b1c56`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
The auth middleware wraps every tool call and, on any non-auth exception, logs the raw exception string at
error level without neutralizing CR/LF. When a tool argument fails validation, the pydantic error embeds the
caller-supplied value and spans multiple lines, and those bytes are written verbatim to the
`auth.auth_info_middleware` logger. A tool argument that both fails a string constraint and contains CR/LF
can therefore inject forged lines into the log. `start_google_auth` is the tool the fuzzer reached it
through.

## Details
`AuthInfoMiddleware.on_call_tool` logs the exception from the downstream handler
(`auth/auth_info_middleware.py:384`):

```python
async def on_call_tool(self, context, call_next):
    try:
        await self._process_request_for_auth(context)
        result = await call_next(context)      # pydantic arg-validation error raised here
        return result
    except Exception as e:
        if (isinstance(e, GatewayIdentityError)
                or "GoogleAuthenticationError" in str(type(e))
                or "Access denied: Cannot retrieve credentials" in str(e)):
            logger.info(f"Authentication check failed: {e}")
        else:
            logger.error(f"Error in on_call_tool middleware: {e}", exc_info=True)   # 405: raw {e}
        raise
```

`start_google_auth(service_name: str, user_google_email: str = ...)` (`core/server.py:903`) declares
`user_google_email` as `str`. When the caller passes a non-string, FastMCP's pydantic validation raises
before the tool body, the error propagates to line 405, and `{e}` is logged. The pydantic message embeds the
caller value (`input_value=...`) and is multi-line. No CR/LF stripping or encoding is applied to `{e}` on
this path.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`. Run in legacy mode (OAuth 2.1 disabled, the default) so
   `start_google_auth` is enabled. No Google credentials are needed to reach the logged error.
2. Start the server over stdio: `uvx workspace-mcp`.
3. Call the tool with a non-string `user_google_email`. Arguments as JSON:
   `{"service_name": "drive", "user_google_email": 12345}`
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["workspace-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "start_google_auth",
                   {"service_name": "drive", "user_google_email": 12345})
               print(result)

   asyncio.run(main())
   ```
4. Observe the server log (stderr / configured log). The `auth.auth_info_middleware` logger emits an
   ERROR record whose message spans several lines and contains the caller-supplied `input_value`, e.g.
   `Error in on_call_tool middleware: 1 validation error for call[start_google_auth]` followed by newline-separated
   `user_google_email` / `Input should be a valid string [... input_value=12345 ...]`. The line break is in
   the logged record, not escaped. A tool whose string argument fails a length/pattern constraint while
   carrying a literal `\r\nFAKE-LOG-ENTRY` would have that sequence echoed into the same record.

## Expected behavior
Caller-derived text written to logs should have CR/LF removed or encoded, and validation errors should be
summarized rather than logged with raw `input_value` content.

## Actual behavior
The middleware logs the unmodified exception (`logger.error(f"... {e}", exc_info=True)`), so caller-influenced
content and its newlines reach the log unescaped.

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection from untrusted content. An
attacker who can make a string argument fail validation while embedding CR/LF can forge log lines (spoof
entries, split records, break log parsers or downstream SIEM ingestion). Because this is in shared
middleware, the gap applies to every tool, not just `start_google_auth`. Severity is moderate: it is a log
integrity issue, not code execution.

## Suggested fix
Neutralize CR/LF before logging exception text, e.g. log `repr(str(e))` or
`str(e).replace("\r", "\\r").replace("\n", "\\n")`, and avoid logging raw pydantic `input_value`. Apply the
same treatment to the sibling handlers (`on_get_prompt`, `auth/auth_info_middleware.py:429`).

## Status on the default branch
Still present at `724ea91` (2026-09-29). `auth/auth_info_middleware.py` is unchanged between the tested
commit and the current default branch head; line 405 still logs `{e}` without neutralization.

## Prior reports
- #1037 "fix: keep user free-text out of INFO/ERROR logs (queries, find/replace text, subjects, titles)" (PR, closed 2026-08-25): related log-hygiene work. It moves search queries, subjects and other user text out of INFO/ERROR logs and redacts URL query strings in `handle_http_errors`; its test file `tests/test_log_hygiene.py` is on the default branch. It targets privacy (PII and secrets), not CR/LF neutralization, and does not touch `AuthInfoMiddleware.on_call_tool`, which still logs `{e}` raw at `auth/auth_info_middleware.py:405`. Does not fix this.
- #918 "get_events rejects standard camelCase args (calendarId, timeMin, timeMax) — schema uses snake_case with additionalProperties:false" (issue, closed 2026-08-18): a functional report that quotes this same record, `ERROR   Error in on_call_tool middleware: 6 validation errors for call[get_events]`. It shows pydantic validation errors reach this log line in normal use; it says nothing about log injection.
- #446 "Is it possible to remove all logging on partial OAuth state and bearer token from the MCP server?" (issue, closed 2026-02-13; PR #451 "fix: prune logs & persist refresh", closed 2026-02-10, says it closes it): about token values in logs, not about unneutralized caller input. Does not cover this sink.
- Documentation: SECURITY.md: "Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests." (the policy asks for private email to the address given there; nothing documents the logging behaviour).
- Coverage note: the fetch returned 1000 items (#206 to #1210: 331 issues, 669 pull requests); #1 to #205 were not in the data and were not searched.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` fired via the runtime
  tracer on logger `auth.auth_info_middleware`. `check_introspection_sensitive_data_logging` (CWE-779) also
  fired, matching the pattern `'bearer '` in the log message.
- Campaigns and executions: recover-pc (1,024 / 160, 60s) and e2-0922 (1 / 0, 60s).
- Evidence (verbatim, trimmed): input `{'service_name': 'drive', 'user_google_email': None}` -> tracer logged
  `Error in on_call_tool middleware: 1 validation error for call[start_google_auth]\nuser_google_email\n  Input
  should be a valid string [type=string_type, input_value=None, input_type=NoneType] ...`. Same shape for
  `user_google_email` = 12345 and True.
- Hand-check hints: REAL missing-neutralization at the sink (auth/auth_info_middleware.py:405), confirmed and
  unchanged on default branch. But MODERATE/partly-weak on exploitability for THIS tool: in every evidence row
  the newlines come from pydantic's own multi-line formatting, not attacker-injected CR/LF - `user_google_email`
  must be a non-string to fail, so you cannot route attacker CR/LF through this specific field (a valid string
  passes validation and is not logged). A genuine attacker-controlled CR/LF needs a different tool with a
  constrained string field that echoes `input_value`; I did not verify such a field by running. The CWE-779
  `'bearer '` match was not corroborated in the quoted log text (likely from the exc_info traceback or nearby
  frames); treat as unverified. Recommend filing as "log output not neutralized in shared auth middleware"
  rather than specific to start_google_auth.
</details>
