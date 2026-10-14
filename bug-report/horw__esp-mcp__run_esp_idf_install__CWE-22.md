# `run_esp_idf_install`: `idf_path` is used without validation or containment

**Repository:** `horw/esp-mcp` · **Tool:** `run_esp_idf_install` · **Tested commit:** `28afddf`
**Weakness:** CWE-22 Path Traversal

## Summary
`run_esp_idf_install` takes an optional `idf_path`, joins it with `install.sh`, checks whether that file exists, and echoes the joined path back in its error message. The value is not normalized, not checked against `IDF_PATH` or any allowed location, and `..` segments are accepted. The error reply tells the caller whether `<any directory>/install.sh` exists. This is a low-severity finding; whether `idf_path` should be restricted at all is a design question for the maintainers.

## Details
`main.py:153-182` at `28afddf`, with `get_esp_idf_dir()` from `esp_utils.py:29-45`:

```python
@mcp.tool()
async def run_esp_idf_install(idf_path: str = None) -> Tuple[str, str]:
    ...
    try:
        esp_idf_dir = get_esp_idf_dir(idf_path if (idf_path and idf_path.strip()) else None)
    ...
    install_script = os.path.join(esp_idf_dir, "install.sh")

    if not os.path.exists(install_script):
        error_msg = f"install.sh not found at {install_script}. Please verify the ESP-IDF path is correct."
        logging.error(error_msg)
        return "", error_msg
```

`get_esp_idf_dir()` returns the caller's `idf_path` unchanged whenever it is non-empty, so the `IDF_PATH` configured by the user in the client config is silently overridden. Relative values resolve against the server's current working directory, which other tools in this server change with `os.chdir(project_path)`. There is no `os.path.realpath()` and no comparison with `IDF_PATH` or an allow-list.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. ESP-IDF is not needed. Create an empty working folder and make sure no file named `install.sh` exists in `/tmp/tofu-poc`:

   ```bash
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install as the README describes and create the virtual environment:

   ```bash
   git clone https://github.com/horw/esp-mcp.git
   cd esp-mcp && git checkout 28afddf
   uv sync
   ```
3. Start the server with `/tmp/tofu-poc/root` as its working directory and call the tool with:

   ```json
   {"idf_path": "../"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="/path/to/esp-mcp/.venv/bin/python",
           args=["/path/to/esp-mcp/main.py"],
           cwd="/tmp/tofu-poc/root",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("run_esp_idf_install", {"idf_path": "../"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the reply is `install.sh not found at ../install.sh. Please verify the ESP-IDF path is correct.` The `../` value was accepted and checked outside the working folder, with no rejection.

## Expected behavior
`idf_path` is resolved with `os.path.realpath()` and rejected unless it points to a recognized ESP-IDF installation (for example it equals `IDF_PATH`, or is on a configured list of allowed ESP-IDF roots). Error messages do not reveal whether files exist at arbitrary locations.

## Actual behavior
Any string is accepted. From the fuzzing run:

```
input:  {"idf_path": "../../../../etc/passwd"}
output: install.sh not found at ../../../../etc/passwd/install.sh. Please verify the ESP-IDF path is correct.
```

## Impact
In MCP the LLM chooses `idf_path`, and prompt injection from untrusted content can steer it. Through this tool's error path, a caller learns whether an `install.sh` file exists at any location and overrides the user's configured `IDF_PATH`. The disclosure on its own is minor.

## Suggested fix
- Resolve `idf_path` with `os.path.realpath()` and accept it only if it equals the configured `IDF_PATH` or is in an explicit allow-list (for example an `ESP_MCP_ALLOWED_IDF_PATHS` env var). Otherwise return a generic error.
- Optionally check for ESP-IDF markers (`tools/idf.py`, `export.sh`) before treating a directory as an ESP-IDF root.
- Apply the same helper wherever `get_esp_idf_dir()` or `get_export_script()` is called with a caller value.

## Status on the default branch
Still present at `28afddf` (2025-12-27). The default branch head is the tested commit.

## Prior reports
- #43 "feat: add install, pytest and idf_path argument" (PR, merged/closed 2025-12-27): the PR that added `run_esp_idf_install` and the per-call `idf_path` argument (the default-branch head `28afddf` is its merge commit). Its summary lists "Per-project ESP-IDF version selection support"; validation of `idf_path` is not discussed. Not a report of this issue.
- #45 "Fix MCP server startup issues and add tools" (PR, open 2026-02-05): unmerged; its body mentions "Per-project and dynamic ESP-IDF path support" but nothing about normalizing or restricting `idf_path`. Does not fix this.
- Documentation: README.md: "All tools support an `idf_path` parameter that can be manually specified when calling the tool" (a caller-chosen ESP-IDF directory overriding `IDF_PATH` is documented behaviour; frame the report around missing validation and the existence oracle, not the override itself).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22), `check_path_traversal` (input-pattern match only). Also fired for this tool: `check_introspection_log_injection`, `check_introspection_temp_file_leak`, `check_introspection_incomplete_cleanup`, `check_reflected_output` (the error message echoes `idf_path`).
- Campaigns and executions: corpus-sbx 2560 exec / 2552 ok (60 s); e2-0922 512 exec / 508 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'idf_path': '/etc/passwd\x00'}` -> `'\ninstall.sh not found at /etc/passwd\x00/install.sh. Please verify the ESP-IDF path is correct.'`
  - `{'idf_path': '../../../../dev/mem'}` -> `'\ninstall.sh not found at ../../../../dev/mem/install.sh. ...'`
  - `{'idf_path': '../../../../etc/passwd'}` -> `'\ninstall.sh not found at ../../../../etc/passwd/install.sh. ...'`
- Hand-check hints: weak. Every logged call stopped at the `os.path.exists` check; nothing was read or written. The alert is input-pattern only. The tool is designed to accept a user-chosen ESP-IDF directory, so a maintainer may reasonably treat an unrestricted `idf_path` as intended; this draft only covers the validation gap and the existence oracle. I scoped this draft to the path-handling finding ToFu reported and did not review the rest of the server. Repro not executed.
</details>
