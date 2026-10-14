# `run_python_code` inline mode: `sys.exit()` in submitted code is not caught and takes down the MCP server

**Repository:** `yzfly/mcp-python-interpreter` · **Tool:** `run_python_code` · **Tested commit:** `84ac42d`
**Weakness:** CWE-117 Improper Output Neutralization for Logs (as flagged by the fuzzer). The defect actually shown is CWE-248 Uncaught Exception.

## Summary
`run_python_code` in its default `inline` mode runs code with `eval`/`exec` inside the server process. The error handler catches `Exception` only. `SystemExit`, raised by `sys.exit()`, `exit()` or `quit()`, is not a subclass of `Exception`, so it escapes the tool, the FastMCP wrapper and the MCP request loop, and the server stops. The fuzzer noticed this through the multi-line asyncio error it logged on the way down. A plain `sys.exit(main())` at the end of a script is enough to trigger it, and the session sets `__name__ = "__main__"`, so the usual `if __name__ == "__main__":` guard does not help.

## Details
`mcp_python_interpreter/server.py:94-106` and `:557-590` (tested commit):

```python
            try:
                try:
                    result_value = eval(code, self.locals)
                    ...
                except SyntaxError:
                    exec(code, self.locals)
            except Exception:          # SystemExit is a BaseException, not caught here
                traceback.print_exc()
                status = 1
...
    if execution_mode == "inline":
        try:
            session = get_session(session_id)
            result = session.execute(code, timeout)
            ...
        except Exception as e:     # not caught here either
            return f"Error in inline execution: {str(e)}\n{traceback.format_exc()}"
```

`ReplSession.__init__` (`server.py:60-65`) sets `"__name__": "__main__"` in the session globals. The `finally` blocks restore `sys.stdout`/`sys.stderr` and the working directory, then the exception keeps propagating. The MCP SDK's request handlers also catch `Exception` only, so the `SystemExit` ends the server's task group.

About the log-injection label: the multi-line log entry the fuzzer saw is asyncio's own message (`unhandled exception during asyncio.run() shutdown\ntask: ...`). The caller's text appears there only inside `repr()` of the exception, which escapes CR/LF. We found no path where a caller-supplied line break reaches a log unescaped.

## Steps to reproduce
1. Prerequisites: Python 3.10+.
2. Install from the repository: `git clone https://github.com/yzfly/mcp-python-interpreter && cd mcp-python-interpreter && pip install .`
3. Call the tool with code that exits, then try a second call:

   ```json
   {"code": "import sys; sys.exit('tofu-poc')", "execution_mode": "inline", "session_id": "default"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mcp-python-interpreter", args=["--dir", "/tmp/tofu-wd"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for tool, args in [
                   ("run_python_code", {"code": "import sys; sys.exit('tofu-poc')",
                                        "execution_mode": "inline", "session_id": "default"}),
                   ("list_sessions", {}),
               ]:
                   try:
                       result = await asyncio.wait_for(session.call_tool(tool, args), timeout=10)
                       print(tool, "->", result)
                   except Exception as e:
                       print(tool, "failed:", type(e).__name__, e)

   asyncio.run(main())
   ```
4. Observe: the first call gets no result, the second call fails or times out, and the server's stderr shows an unhandled `SystemExit('tofu-poc')` wrapped in `BaseExceptionGroup('unhandled errors in a TaskGroup', ...)`. The server process is gone and the client has to restart it.

## Expected behavior
`sys.exit()` in submitted code ends that snippet only. The tool returns something like `--- Error ---\nSystemExit: tofu-poc` and the session and server keep running.

## Actual behavior
The tool returns nothing and the server's run loop ends. From the fuzzing run (paths trimmed):

```
input:  {'code': "import sys; sys.exit('Sensitive error leak!')", 'execution_mode': 'inline', 'session_id': 'default', ...}
output: None
log (asyncio): unhandled exception during asyncio.run() shutdown
task: <Task finished name='mcp.server.lowlevel.server.Server.run' ... exception=BaseExceptionGroup('unhandled errors in a TaskGroup', [BaseExceptionGroup('unhandled errors in a TaskGroup', [SystemExit('Sensitive error leak!')])])>
```

## Impact
The LLM writes the `code` argument, and generated scripts often end in `sys.exit(...)`. Any such call, accidental or steered by prompt injection, kills the server and drops all REPL sessions and their state. This is an availability problem. It gives an attacker nothing beyond what inline mode already allows, since inline code can run anything in the server process.

## Suggested fix
Catch `SystemExit` in `ReplSession.execute` and report it as a normal result, for example:

```python
            except SystemExit as e:
                if e.code not in (None, 0):
                    print(f"SystemExit: {e.code}", file=sys.stderr)
                    status = 1
            except Exception:
                traceback.print_exc()
                status = 1
```

`KeyboardInterrupt` can be handled the same way. `os._exit()` cannot be caught; if the server must survive arbitrary code, run it in `subprocess` mode.

## Status on the default branch
Still present at `84ac42d` (2026-07-02). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 8 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` + `check_introspection_code_injection` on all three evidence calls. Many other introspection sanitizers are listed for this tool (`check_file_access`, `check_introspection_command_injection`, `check_introspection_sensitive_file_access`, ...); they follow from the tool executing arbitrary code by design and are not separate findings.
- Campaigns and executions: corpus-sbx 2048 exec / 2029 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed): three near-identical calls, `{'code': "import sys; sys.exit('Sensitive error leak!')", 'execution_mode': 'inline', 'session_id': 'default', 'environment': 'system', 'save_as': None, 'timeout': -1}` (and `leik`, `timeout: -2` variants), output `None`, asyncio log as quoted above. One log names the task `src.runners.python_runner.PythonRunner.execute.<locals>.run_test` (ToFu harness), one names `mcp.server.lowlevel.server.Server.run`.
- Hand-check hints: real, but as a crash (CWE-248), not as log injection. The CWE-117 label is a false positive: the newline is asyncio's own format and caller text is `repr()`-escaped. The crash is confirmed by source (`except Exception` at `server.py:104` and `:589`) and by the `Server.run` task ending with `SystemExit` in the log. I did not confirm the exact client-side symptom (timeout vs. closed connection) in a real stdio deployment; check that when reproducing. Side note, not filed: `MCP_TRANSPORT=streamable-http` binds `0.0.0.0:8000` by default (`main.py`), which would expose this code-execution server on all interfaces.
</details>
