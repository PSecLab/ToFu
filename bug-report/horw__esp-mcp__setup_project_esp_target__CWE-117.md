# Log injection in `setup_project_esp_target`: CR/LF in `project_path` forges log lines

**Repository:** `horw/esp-mcp` · **Tool:** `setup_project_esp_target` · **Tested commit:** `28afddf`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`setup_project_esp_target` logs its raw arguments as the first thing it does. `project_path`, `target` and `idf_path` are inserted into the log message unchanged, so a value containing `\r\n` ends the current log line and starts a new one with text the caller chooses. Anyone reading the server log (the MCP client's server log, or a terminal) sees a forged entry that looks like it came from the server.

## Details
`main.py:59-78` at `28afddf`:

```python
@mcp.tool()
async def setup_project_esp_target(project_path: str, target: str, idf_path: str = None) -> Tuple[str, str]:
    ...
    logging.warning(f"setup_project_esp_target called with idf_path={idf_path}, project_path={project_path}, target={target}")
    os.chdir(project_path)
    # Process idf_path parameter
    processed_idf_path = idf_path if (idf_path and idf_path.strip()) else None
    logging.warning(f"processed_idf_path={processed_idf_path}")
```

The f-string at line 74 copies all three arguments into the record with no escaping, and line 78 does the same for `idf_path`. There is no `logging.basicConfig()` in `main.py`, so the root logger's fallback handler writes the record to stderr, which MCP clients usually store in their per-server log. The log call runs before `os.chdir(project_path)`, so it happens even when the path is invalid and the tool then fails.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. ESP-IDF is not needed: the chosen `project_path` does not exist, so the tool stops at `os.chdir` right after logging.
2. Install and start the server as the README describes:

   ```bash
   git clone https://github.com/horw/esp-mcp.git
   cd esp-mcp && git checkout 28afddf
   ```
3. Call the tool with:

   ```json
   {"project_path": "/tmp/tofu-poc/does-not-exist\r\nFAKE-LOG-ENTRY", "target": "esp32", "idf_path": ""}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["--directory", "/path/to/esp-mcp", "run", "main.py"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("setup_project_esp_target", {
                   "project_path": "/tmp/tofu-poc/does-not-exist\r\nFAKE-LOG-ENTRY",
                   "target": "esp32",
                   "idf_path": "",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr. It shows two lines for one record, and the second one starts with the caller's text:

   ```
   setup_project_esp_target called with idf_path=, project_path=/tmp/tofu-poc/does-not-exist
   FAKE-LOG-ENTRY, target=esp32
   ```

   The tool call itself then returns an error for the missing directory.

## Expected behavior
The log record stays on one line, with control characters escaped, for example `project_path='/tmp/tofu-poc/does-not-exist\r\nFAKE-LOG-ENTRY'`.

## Actual behavior
The CR/LF is written to the log unchanged and the caller's text appears as a separate line. In the fuzzing run, a `project_path` containing `\r` and other control bytes reached the log record as-is:

```
setup_project_esp_target called with idf_path=, project_path="project_path": "../../../../etc/passwd", "t\x1f\r\x18\x1a\x0b]E_"esp32", "idf_path": ", target=
```

## Impact
In MCP the LLM fills `project_path`, `target` and `idf_path`, and prompt injection from untrusted content (for example a README in a project the user asks to build) can steer them. An attacker can add fake lines to the server log, for example a fake success message or a misleading instruction, to confuse a developer who is debugging from that log. Other control bytes (such as ANSI escape sequences) can also change how the log looks in a terminal. The impact is limited to log integrity.

## Suggested fix
- Log arguments with `%r` formatting so control characters are escaped: `logging.warning("setup_project_esp_target called with idf_path=%r, project_path=%r, target=%r", idf_path, project_path, target)`. Do the same at line 78.
- Validate `target` against the list of supported chip names (`esp32`, `esp32c3`, `esp32s3`, ...) and reject `project_path` values that contain control characters.

## Status on the default branch
Still present at `28afddf` (2025-12-27). The default branch head is the tested commit.

## Prior reports
- #45 "Fix MCP server startup issues and add tools" (PR, open 2026-02-05): unmerged; its summary mentions "Better error handling, logging" but says nothing about escaping values written to the log. Does not fix this.
- Documentation: test/README.md: "Check logs" in its troubleshooting steps (users are told to debug from the server log; no file documents the log format or any escaping).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection` (only sanitizer listed for this tool).
- Campaigns and executions: e2-0922 500 exec / 0 ok (60 s). 0 ok is expected: every fuzzed `project_path` failed at `os.chdir` after the log call.
- Evidence (verbatim, trimmed): input `{'project_path': '"project_path": "../../../../etc/passwd", "t\x1f\r\x18\x1a\x0b]E_"esp32", "idf_path": "', 'target': '', 'idf_path': ''}` -> output `None`. Tracer: logged content `'setup_project_esp_target called with idf_path=, project_path="project_path": "../../../../etc/passwd", "t\x1f\r\x18\x1a\x0b]E_"esp32", "idf_path": ", target='` (logger:root). Two more calls with the same shape (`esp33`, `project_pat`).
- Hand-check hints: real but low severity. The caller's `\r` reaches `logging.warning` at `main.py:74` unescaped; verified in code and in the tracer record. The repro uses a nonexistent `project_path` on purpose so the handler stops at `os.chdir` right after the log call. I scoped this draft to the logging finding ToFu reported and did not review the rest of the server. Repro not executed; the exact stderr prefix depends on the logging fallback handler (it prints the bare message without a level prefix).
</details>
