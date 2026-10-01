# Log output not neutralized in `list_models`: multi-line `ReplicateError` text is logged as-is

**Repository:** `gerred/mcp-server-replicate` · **Tool:** `list_models` · **Tested commit:** `568024c`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`list_models` lists models through the `replicate` Python client. When that call fails, the server logs `str(err)` without escaping line breaks. `ReplicateError` formats itself over several lines, so one error becomes four physical log lines. The line breaks and the `detail` text come from the `replicate` library and the Replicate API response, not from the caller. The `owner` argument is never logged. This is a low-severity log-hygiene report.

## Details
`src/mcp_server_replicate/replicate_client.py:172-246` at `568024c`:

```python
    def list_models(self, owner: str | None = None, cursor: str | None = None) -> dict[str, Any]:
        ...
            models = self.client.models.list(**params)
            ...
            # Filter by owner if specified
            if owner:
                models = [m for m in models if m.owner == owner]
            ...
        except Exception as err:
            logger.error(f"Failed to list models: {str(err)}")
            raise Exception(f"Failed to list models: {str(err)}") from err
```

`self.client.models.list()` raises `replicate`'s `ReplicateError` on a 401. Its string form spans several lines (`ReplicateError Details:` / `title:` / `status:` / `detail:`), and the f-string at line 245 passes it through unchanged. The root logger is set up in `server.py:295` and writes to stderr. `owner` is only used for a client-side filter (lines 200-202), so it does not reach the log.

Every client method in `replicate_client.py` uses the same `logger.error(f"...{str(err)}")` pattern (lines 245 to 800).

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. The server refuses to start without `REPLICATE_API_TOKEN` (`server.py:299-303`). Use an invalid value such as `r8_invalid_token_for_testing` so the API answers 401.
2. Check out the tested commit and start the server: `git clone https://github.com/gerred/mcp-server-replicate && cd mcp-server-replicate && git checkout 568024c && REPLICATE_API_TOKEN=r8_invalid_token_for_testing uv run mcp-server-replicate`. The script below starts it for you.
3. Call the tool with `{"owner": "tofu-poc"}`:

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--directory", "/path/to/mcp-server-replicate", "mcp-server-replicate"],
           env={**os.environ, "REPLICATE_API_TOKEN": "r8_invalid_token_for_testing"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("list_models", {"owner": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (`stdio_client` forwards it to your terminal). One `logger.error` call produces lines starting with `Failed to list models: ReplicateError Details:`, `title:`, `status:` and `detail:`.

## Expected behavior
Each log record stays on one line. Line breaks inside interpolated exception text are escaped (for example as `\n`).

## Actual behavior
The record is split across four lines. Logged content captured by ToFu's tracer (each `\n` was a real line break):

```
Failed to list models: ReplicateError Details:\ntitle: Unauthenticated\nstatus: 401\ndetail: You did not pass a valid authentication token
```

## Impact
Low. The caller (the LLM, possibly steered by prompt injection) controls only `owner`, which never reaches the log. The multi-line text comes from the `replicate` library and the API. The practical effect is that line-based log parsers see a broken record. It is mainly a hardening gap: because the code logs `str(err)` verbatim everywhere, any future exception that carries caller text would be logged raw.

## Suggested fix
Escape CR/LF before logging, either per call or once in a formatter:

```python
def _one_line(text: str) -> str:
    return text.replace("\r", "\\r").replace("\n", "\\n")

logger.error("Failed to list models: %s", _one_line(str(err)))
```

A `logging.Formatter` subclass that escapes `\r` and `\n` in `record.getMessage()` would cover every call in `replicate_client.py` at once.

## Status on the default branch
Still present at `568024c` (2025-02-28). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 1 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Fired: `check_introspection_log_injection` (also listed for the tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`).
- Campaigns and executions: `e2-0922`: 1 exec, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): inputs `{'owner': ''}`, `{'owner': None}`, `{'owner': '/etc/passwd\x00'}`, output `None` each. Analysis: "Unneutralized CRLF newline character detected in log output (logger:mcp_server_replicate.replicate_client)! Logged content: 'Failed to list models: ReplicateError Details:\ntitle: Unauthenticated\nstatus: 401\ndetail: You did not pass a valid authentication token'."
- Hand-check hints: **weak, likely a false positive for CWE-117.** The newlines come from `ReplicateError.__str__` in the `replicate` library (format taken from the log; I did not read `replicate` 1.0.4's source). `owner` is not in the request or the log. ToFu's `check_introspection_log_injection` (`src/sanitizers/introspection.py:807`) flags any record containing `\n`/`\r` with no provenance check. Separate functional bug worth its own issue: `server.py:638` does `await client.list_models(owner=owner)`, but `ReplicateClient.list_models` is a plain `def` returning a dict, so on success the `await` should raise `TypeError` and the tool can never return models (read from code, not run). Recommend not filing the CWE-117 part, or folding all nine replicate CWE-117 items into one low-priority hardening issue.
</details>
