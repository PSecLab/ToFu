# Path traversal in `analyze_audio_files`: `project_path` and the media paths it references are not confined to `--reaper-projects-dir`

**Repository:** `dschuler36/reaper-mcp-server` · **Tool:** `analyze_audio_files` · **Tested commit:** `96be16d`
**Weakness:** CWE-22 Path Traversal

## Summary
`analyze_audio_files` parses a REAPER project and measures the audio files its items reference. `project_path` is opened as given, with no check against `--reaper-projects-dir`, and every `FILE` path inside the project (absolute, or relative with `../`) is opened with `soundfile` without containment. Any readable file is opened. The tool returns loudness and spectrum measurements, not raw bytes, but it confirms which files exist and analyzes audio anywhere the process can read.

## Details
`src/reaper_mcp_server/server.py:38-126` (tested commit):

```python
def analyze_audio_files(project_path: str, track_filter: Optional[str] = None, whole_file: bool = False):
    rpp_parser = RPPParser(project_path)
    ...
    for track in tracks:
        for item in track.items:
            ...
            cache[key] = AudioAnalyzer(item.audio_filepath, start, length).analyze()
            entry = {..., 'audio_file': item.audio_filepath, ...}
```

`RPPParser` opens `project_path` with `open(file_path, 'r')` (`src/reaper_mcp_server/rpp_chunks.py:134-136`). Media paths come from the project's `FILE` lines and are resolved with `os.path.abspath(os.path.join(base_dir, path))` when relative, or used as is when absolute (`src/reaper_mcp_server/rpp_parser.py:284-297`). `AudioAnalyzer.analyze` then checks `os.path.exists` and opens the file with `sf.SoundFile` (`src/reaper_mcp_server/audio_analyzer.py:63-70`, `:124`). A missing file is reported back as `File not found: <path>`.

## Steps to reproduce
1. Prerequisites: `uv` installed. Create a projects dir and a harmless RPP file outside it whose item points at a missing path:
   `mkdir -p /tmp/tofu-projects && printf '<REAPER_PROJECT 0.1 "7.0"\n  <TRACK\n    NAME "t"\n    <ITEM\n      POSITION 0\n      LENGTH 1\n      <SOURCE WAVE\n        FILE "/tmp/tofu-does-not-exist.wav"\n      >\n    >\n  >\n>\n' > /tmp/tofu-poc.RPP`
2. Start the server as the README describes:
   `uvx --from git+https://github.com/dschuler36/reaper-mcp-server reaper-mcp-server --reaper-projects-dir /tmp/tofu-projects`
3. Call the tool with a traversal path to the project:

   ```json
   {"project_path": "/tmp/tofu-projects/../tofu-poc.RPP", "whole_file": true}
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
               result = await session.call_tool("analyze_audio_files",
                   {"project_path": "/tmp/tofu-projects/../tofu-poc.RPP", "whole_file": True})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the project outside `--reaper-projects-dir` is parsed and the referenced media path is probed: the reply lists it under `errors` with `File not found: /tmp/tofu-does-not-exist.wav`. Pointing `FILE` at any existing audio file outside the projects dir returns its analysis.

## Expected behavior
`project_path` must resolve (`os.path.realpath`) to an `.RPP` file inside `--reaper-projects-dir`. Media paths should be checked against an allowed set of roots (the projects dir, or the project's own folder) before they are opened.

## Actual behavior
Any readable path is opened. From the fuzzing run, ToFu's runtime tracer recorded the server opening `../../../../etc/passwd`, and the tool returned:

```
{"project_name": "passwd", "signal_stage": "pre-fx (raw source files, before FX chain and fader)", "distinct_regions_analyzed": 0}
```

## Impact
The LLM chooses `project_path`, and prompt injection can steer it; a project file received from someone else also controls the `FILE` paths. An attacker can learn whether files exist anywhere on the host and obtain audio measurements of audio files outside the projects directory. File contents are not returned verbatim. Low.

## Suggested fix
```python
base = os.path.realpath(args.reaper_projects_dir)
def inside(p: str) -> bool:
    real = os.path.realpath(p)
    return os.path.commonpath([base, real]) == base
```
Reject `project_path` unless `inside(project_path)` and it ends in `.RPP`; skip media files that are not `inside(...)` (or not under the project's folder) and report them as skipped. Do not echo full paths of missing files.

## Status on the default branch
Still present at `96be16d` (2026-09-01). The tested commit is the current default branch head.

## Prior reports
- No issue or pull request covers this. Searched all 2 issues and 9 pull requests (fetched 2026-10-01). PR #6 "adds audio analysis tool" (PR, closed 2026-02-01) introduced this tool; its body describes the feature only and says nothing about path limits.
- Documentation: README.md: "`project_path` (required): Path to the .RPP project file" and "Analysis reads the source files from disk" (no limit on either path is documented; `--reaper-projects-dir` is described only as "the directory holding your Reaper projects"). It also states "This server is read-only by design.", which matches the read-only impact here.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, `check_file_access`, `check_introspection_sensitive_file_access`.
- Campaigns and executions: corpus-sbx 3072 exec / 79 ok; e2-0922 1024 exec / 19 ok (60 s budgets). Most fuzzed paths did not exist and raised.
- Evidence (verbatim, trimmed):
  - `{'project_path': '../../../../etc/passwd', 'track_filter': None, 'whole_file': False}` -> `{"project_name": "passwd", "signal_stage": "pre-fx ...", "distinct_regions_analyzed": 0}`; tracer: "Access to restricted system file detected: '../../../../etc/passwd'".
  - Same input with `'track_filter': ''` -> same output.
- Hand-check hints: real, low severity. The tracer saw the open; there is no containment despite `--reaper-projects-dir`. Only RPP-parseable content and audio statistics come back. The media-path half (`FILE` lines) is from source reading and was not exercised by ToFu. I traced the repro RPP snippet through `_parse_item`/`_parse_take`/`_source_file` by reading; it should yield one item with that `audio_filepath`, but it was not run. This overlaps with the `parse_reaper_project` report; consider one combined issue.
</details>
