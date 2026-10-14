# Path traversal in `parse_reaper_project`: `project_path` opens files outside `--reaper-projects-dir`

**Repository:** `dschuler36/reaper-mcp-server` · **Tool:** `parse_reaper_project` · **Tested commit:** `96be16d`
**Weakness:** CWE-22 Path Traversal

## Summary
`parse_reaper_project` parses a REAPER `.RPP` file and returns its structure as JSON. The server is configured with `--reaper-projects-dir`, but `project_path` is opened as given, with no check that it lies under that directory or ends in `.RPP`. Any readable file on the host is opened and parsed. For non-RPP files only the file name comes back, but the call still reveals whether the file exists, and any RPP-formatted file anywhere on disk is fully disclosed.

## Details
`src/reaper_mcp_server/server.py:33-36` (tested commit):

```python
@server.tool()
def parse_reaper_project(project_path: str):
    rpp_parser = RPPParser(project_path)
    return _serialize(asdict(rpp_parser.project))
```

`RPPParser.__init__` (`src/reaper_mcp_server/rpp_parser.py:53-66`) passes the path to `tokenize_file`, which does (`src/reaper_mcp_server/rpp_chunks.py:134-136`):

```python
with open(file_path, 'r', encoding='utf-8', errors='replace') as handle:
    return tokenize(handle.read().splitlines())
```

`args.reaper_projects_dir` is only used by `find_reaper_projects` (`server.py:28-31`); no tool checks paths against it. `handle.read()` also reads the whole file into memory with no size limit.

## Steps to reproduce
1. Prerequisites: `uv` installed. Create a harmless RPP file outside the projects directory:
   `printf '<REAPER_PROJECT 0.1 "7.0"\n  <TRACK\n    NAME "outside-projects-dir"\n  >\n>\n' > /tmp/tofu-poc.RPP` and `mkdir -p /tmp/tofu-projects`.
2. Start the server as the README describes:
   `uvx --from git+https://github.com/dschuler36/reaper-mcp-server reaper-mcp-server --reaper-projects-dir /tmp/tofu-projects`
3. Call the tool with a traversal path to the file, and with a plain system file:

   ```json
   {"project_path": "/tmp/tofu-projects/../tofu-poc.RPP"}
   ```
   ```json
   {"project_path": "/etc/hostname"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=[
           "--from", "git+https://github.com/dschuler36/reaper-mcp-server",
           "reaper-mcp-server", "--reaper-projects-dir", "/tmp/tofu-projects"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for p in ["/tmp/tofu-projects/../tofu-poc.RPP", "/etc/hostname"]:
                   print(p, await session.call_tool("parse_reaper_project", {"project_path": p}))

   asyncio.run(main())
   ```
4. Observe that the first call returns a track named `outside-projects-dir`, and the second returns `{"name": "hostname", "location": "/etc/hostname", ...}` (file opened, nothing parsed). A path that does not exist returns an error instead, which gives an existence check.

## Expected behavior
The tool resolves `project_path` (`os.path.realpath`) and rejects it unless it is inside `--reaper-projects-dir` and has an `.RPP` extension.

## Actual behavior
Any readable path is opened. From the fuzzing run, ToFu's runtime tracer recorded the server opening `../../../../etc/passwd`, and the tool returned:

```
{"name": "passwd", "location": "../../../../etc/passwd", "tempo": 0.0, "total_length": 0.0, "has_tempo_changes": false}
```

## Impact
The LLM chooses `project_path`, and prompt injection in content the agent reads can steer it. An attacker can probe for the existence of files anywhere on the host and read any RPP-formatted file outside the configured projects directory (track names, plugin chains, referenced media paths). The content of non-RPP files is not returned. Low.

## Suggested fix
```python
base = os.path.realpath(args.reaper_projects_dir)
real = os.path.realpath(project_path)
if os.path.commonpath([base, real]) != base or not real.lower().endswith('.rpp'):
    raise ValueError("project_path must be an .RPP file inside --reaper-projects-dir")
```
Apply the same check in `analyze_audio_files`, and consider a maximum file size before `read()`.

## Status on the default branch
Still present at `96be16d` (2026-09-01). The tested commit is the current default branch head.

## Prior reports
- No issue or pull request covers this. Searched all 2 issues and 9 pull requests (fetched 2026-10-01).
- Documentation: README.md: `--reaper-projects-dir` is "the directory holding your Reaper projects", and "`find_reaper_projects`: Finds all Reaper projects in the directory you specified in the config." (the projects directory is documented only as the search root for `find_reaper_projects`; the README neither promises nor disclaims that `parse_reaper_project` is limited to it). It also states "This server is read-only by design.", which matches the read-only impact here.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, `check_file_access`, `check_introspection_sensitive_file_access`.
- Campaigns and executions: corpus-sbx 2560 exec / 46 ok; e2-0922 1024 exec / 17 ok (60 s budgets). Low success rate: most fuzzed paths did not exist and raised.
- Evidence (verbatim, trimmed):
  - `{'project_path': '../../../../etc/passwd'}` -> `{"name": "passwd", "location": "../../../../etc/passwd", "tempo": 0.0, "total_length": 0.0, "has_tempo_changes": false}`; tracer: "Access to restricted system file detected: '../../../../etc/passwd'".
  - `{'project_path': '/../etc/passwd'}` -> same shape, `"location": "/../etc/passwd"`.
- Hand-check hints: real, low severity. The tracer saw the open, and the code has no containment despite having `--reaper-projects-dir`. Disclosure is limited to RPP-parseable content; `/etc/passwd` yielded only its name. Untested thought: `handle.read()` on a special file such as `/dev/zero` would likely exhaust memory (DoS); I did not include it as a repro.
</details>
