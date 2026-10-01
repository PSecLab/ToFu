# Unneutralized multi-line output in the `list_esp_serial_ports` log line

**Repository:** `horw/esp-mcp` · **Tool:** `list_esp_serial_ports` · **Tested commit:** `28afddf`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`list_esp_serial_ports` runs the pyserial port lister and then writes its stdout and stderr into a single `logging.warning(...)` call. The output is inserted as-is, so any newline in it splits one log record into several lines that look like separate entries. The tool takes no arguments, so a caller cannot choose this content directly. This is a small hardening issue rather than an exploitable bug.

## Details
`main.py:137-151` at `28afddf`:

```python
@mcp.tool()
async def list_esp_serial_ports() -> Tuple[str, str]:
    returncode, stdout, stderr = await list_serial_ports()

    # Log the port listing operation
    port_log = f"Port listing - Return code: {returncode}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    open('mcp-ports.log', 'w+').write(port_log)
    logging.warning(f"port listing result - return code: {returncode}, stdout: {stdout}, stderr: {stderr}")

    return stdout, stderr
```

There is no `logging.basicConfig()` in `main.py`, so the root logger's fallback handler writes these records to stderr, which MCP clients usually capture into their server log. `stdout` and `stderr` come from the subprocess and contain raw `\n` characters. The same pattern (`stdout`/`stderr` interpolated into `logging.warning`) appears in the other tools at `main.py:55`, `:82`, `:104`, `:133`, `:202` and `:251`. Separately, the tool writes `mcp-ports.log` into the current working directory with default permissions.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. ESP-IDF and a connected device are not needed for this tool.
2. Install and start the server as the README describes:

   ```bash
   git clone https://github.com/horw/esp-mcp.git
   cd esp-mcp && git checkout 28afddf
   ```
3. Call the tool with no arguments:

   ```json
   {}
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
               result = await session.call_tool("list_esp_serial_ports", {})
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr. The single `port listing result - ...` record is printed across several lines, one per line of the subprocess output.

## Expected behavior
Each log call produces one log line. Embedded newlines in subprocess output are escaped (for example with `repr()` or by replacing `\r` and `\n` with `\\r` and `\\n`) before logging.

## Actual behavior
The record spans several lines. From the fuzzing run, on a host where `python` was not on `PATH`:

```
port listing result - return code: 127, stdout: , stderr: /bin/sh: 1: python: not found
```

followed by a trailing newline from the subprocess stderr inside the same record.

## Impact
Low. The tool has no arguments, so an LLM or a prompt injection cannot choose the logged text through this tool. The content comes from the local port lister. The practical effect is log lines that are harder to parse and could be confused with separate entries. The same unescaped pattern is more relevant in tools that log caller arguments, such as `setup_project_esp_target`.

## Suggested fix
- Log subprocess output with `%r` formatting, for example `logging.warning("port listing result - return code: %s, stdout: %r, stderr: %r", returncode, stdout, stderr)`, or strip `\r` and `\n` first.
- Apply the same change to the other `logging.warning` calls that include `stdout` or `stderr`.
- Optionally configure a logger with a formatter once at startup instead of relying on the root logger's fallback handler.

## Status on the default branch
Still present at `28afddf` (2025-12-27). The default branch head is the tested commit.

## Prior reports
- #45 "Fix MCP server startup issues and add tools" (PR, open 2026-02-05): unmerged; its summary mentions "Better error handling, logging" but says nothing about escaping values written to the log. Does not fix this.
- Documentation: test/README.md: "Check logs" in its troubleshooting steps (users are told to debug from the server log; no file documents the log format or any escaping).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`. Also fired: `check_introspection_insecure_file_permissions` (`mcp-ports.log` created 0o664, which is the default umask, not a code choice), `check_introspection_command_injection` (fired on the fixed string `python -m serial.tools.list_ports`; nothing caller-controlled), `check_introspection_temp_file_leak`, `check_introspection_incomplete_cleanup`.
- Campaigns and executions: corpus-sbx 2048 exec / 2048 ok (60 s); e2-0922 512 exec / 512 ok (60 s).
- Evidence (verbatim, trimmed): input `{}` -> output `'\n/bin/sh: 1: python: not found\n'`. Tracer: logged content `'port listing result - return code: 127, stdout: , stderr: /bin/sh: 1: python: not found\n'`.
- Hand-check hints: weak, likely a ToFu misclassification. ToFu's log-injection check flags any `\n` in a log record, whether or not it came from caller input (`src/sanitizers/introspection.py`, `check_introspection_log_injection`). Here the input is `{}` and the newline came from subprocess stderr, so CWE-117 as defined (caller-controlled CR/LF) is not met. Only worth filing, if at all, as a one-line hardening note bundled with the `setup_project_esp_target` issue. Repro not executed.
</details>
