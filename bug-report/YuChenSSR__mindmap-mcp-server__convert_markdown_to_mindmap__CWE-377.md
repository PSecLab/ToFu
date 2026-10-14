# Temporary files in `convert_markdown_to_mindmap` are never removed: every call leaves the Markdown input and HTML output in `/tmp/mindmap-*`

**Repository:** `YuChenSSR/mindmap-mcp-server` · **Tool:** `convert_markdown_to_mindmap` · **Tested commit:** `f61f76f`
**Weakness:** CWE-377 Insecure Temporary File (the closer fit is CWE-459 Incomplete Cleanup)

## Summary
`convert_markdown_to_mindmap` writes the caller's Markdown to a new temporary directory, runs `markmap-cli` on it and returns the generated HTML (or its path). The temporary directory, with both `input.md` and `input.html`, is never deleted. Each call leaves another `/tmp/mindmap-XXXXXXXX/` behind, so the user's Markdown content stays on disk after the call and the temp directory grows without bound. The directory itself is created securely, so this is a cleanup problem, not a permissions problem.

## Details
`mindmap_mcp_server/server.py` (tested commit), lines 28-36 and 84-96:

```python
async def create_temp_file(content: str, extension: str) -> str:
    """Create a temporary file with the given content and extension."""
    temp_dir = tempfile.mkdtemp(prefix='mindmap-')
    file_path = os.path.join(temp_dir, f"input{extension}")
    with open(file_path, mode='w') as f:
        f.write(content)
    return file_path
# ...
        input_file = await create_temp_file(markdown_content, '.md')
        output_file = await run_mindmap(input_file)
        # ... existence check of output_file, lines 89-91
        if RETURN_TYPE == 'html':
            html_content = await get_html_content(output_file)
            return html_content
```

(Blank lines and comments removed.) `run_mindmap` (lines 38-62) writes `input.html` next to `input.md`. No code path calls `shutil.rmtree` or `os.remove`; `shutil` is imported at line 8 but unused. `tempfile.mkdtemp` creates the directory with mode `0700`, so other local users cannot read the files; `input.md` itself gets the default mode from the umask (`0664` under umask `002`), which is only a problem if the directory is later made accessible.

## Steps to reproduce
1. Prerequisites: Python 3.10+, Node.js (the tool runs `npx -y markmap-cli`, which downloads the CLI on first use). No accounts or env vars.
2. Install and start the tested commit:
   ```bash
   pip install "git+https://github.com/YuChenSSR/mindmap-mcp-server@f61f76f"
   # server entry point: mindmap-mcp-server --return-type html
   ls -d /tmp/mindmap-* 2>/dev/null | wc -l   # note the count before
   ```
3. Call the tool:
   ```json
   {"markdown_content": "# tofu-poc\n- temp file cleanup check"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mindmap-mcp-server", args=["--return-type", "html"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("convert_markdown_to_mindmap",
                   {"markdown_content": "# tofu-poc\n- temp file cleanup check"})
               print(str(result)[:200])

   asyncio.run(main())
   ```
4. Observe: after the call, `ls -la /tmp/mindmap-*/` shows a new directory containing `input.md` (with the `tofu-poc` text) and `input.html`. It is still there after the server exits. Repeat the call and the count grows by one each time. (On macOS, look under `$TMPDIR` instead of `/tmp`.)

## Expected behavior
In `html` mode the temporary directory is removed once the HTML has been read. In `filePath` mode the output is written to a documented output location (or the caller is told it owns cleanup), and the Markdown input is removed.

## Actual behavior
Every call leaves its temp directory behind. From the fuzzing run, ToFu's tracer reported after a call with `markdown_content: "test"`:

```
left 1 uncleaned temporary resource(s) on disk: ['/tmp/mindmap-ivhix5fj']
... file '/tmp/mindmap-ivhix5fj/input.md' with insecure permissive mode octal '0o664'
```

## Impact
Low. The Markdown passed to the tool can contain whatever the user or agent is summarizing (notes, documents, internal plans), and it stays on disk in plain text until the OS cleans `/tmp`. Because the directory is `0700`, the exposure is limited to the same user, root, backups and anything that later scans the temp directory. Heavy use fills the temp directory over time. Tool arguments are chosen by the LLM, but no attacker control is needed for this.

## Suggested fix
- In `html` mode, use `with tempfile.TemporaryDirectory(prefix="mindmap-") as d:` around the whole conversion so the directory is removed even on errors.
- In `filePath` mode, delete `input.md` after `markmap-cli` finishes and write the HTML to a configurable output directory instead of a throwaway temp dir.
- Optionally create the input file with `os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)`.

## Status on the default branch
Still present at `f61f76f` (2025-05-20). The tested commit is the current head of the default branch.

## Prior reports
- Documentation: README.md, "using `uvx`": "`filePath` will save the mindmap to a file and return the file path,which you can open in your browser." So in `filePath` mode a persistent HTML file is the documented behaviour; the README does not say where it goes, that `input.md` is also kept, or that nothing is cleaned up in `html` mode.
- No issue or PR reports leftover temporary files. Searched all 5 issues and 4 pull requests (fetched 2026-10-01). The other reports on this tool, #2 and #5 ("Failed to run markmap-cli" on Windows) and #3 (an error under agents-sdk), are unrelated.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: insecure-temp-file; `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_insecure_temp_permissions`, `check_introspection_temp_file_leak`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 1 exec / 1 ok (60 s budget). The three evidence calls below are all logged under corpus-sbx, which does not match an exec count of 1; check how the exec counter was taken for this tool before quoting it.
- Evidence (verbatim, trimmed); each call returned the full markmap HTML (`<!doctype html> ... <title>Markmap</title> ...`):
  - `{'markdown_content': ''}` -> 11.35 s; leftovers `['/tmp/node-compile-cache', '/tmp/mindmap-lcjlo0fr']`; `/tmp/mindmap-lcjlo0fr/input.md` mode `0o664`
  - `{'markdown_content': 'test'}` -> 2.17 s; leftover `['/tmp/mindmap-ivhix5fj']`; `input.md` mode `0o664`
  - `{'markdown_content': 'http://[::1]:8080'}` -> 2.24 s; leftover `['/tmp/mindmap-mzkq6jl_']`; `input.md` mode `0o664`
- Hand-check hints: weak as CWE-377. The cleanup leak is real (no removal anywhere in `server.py`) but low severity. The "insecure permissions" alerts overstate it: `mkdtemp` makes the parent `0700`, so a `0664` file inside is not reachable by other users. `/tmp/node-compile-cache` comes from Node/npx, not this server. The "resource exhaustion" alert is the `npx -y markmap-cli` download and startup time, not a bug. Unrelated observation: the tool runs an unpinned `npx -y markmap-cli` on every call. Not run by us.
</details>
