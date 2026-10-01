# Temporary directory left in `/tmp` after `deep_research_ddgs`: matplotlib falls back to a temp cache dir because the Docker user has no home

**Repository:** `nkapila6/mcp-local-rag` · **Tool:** `deep_research_ddgs` · **Tested commit:** `aabb55d`
**Weakness:** CWE-377 Insecure Temporary File

## Summary
The first call to `deep_research_ddgs` imports `mediapipe`, which pulls in matplotlib. When matplotlib cannot write to `~/.config/matplotlib`, it creates a `/tmp/matplotlib-XXXXXXXX` directory and uses it for the rest of the process lifetime. The Docker image runs as a system user with no home directory, so this fallback happens on every start. This is a low-severity hygiene issue, not an exploitable flaw: the directory is created with `tempfile.mkdtemp` (random name, mode 0700) and matplotlib removes it at normal interpreter exit.

## Details
The tool's arguments play no part. The directory is a side effect of the lazy imports at the start of every tool call. `deep_research_ddgs` (`src/mcp_local_rag/main.py:265-289`) calls `_deep_research_internal`, which starts with:

`src/mcp_local_rag/main.py:127-130`
```python
    # lazy load
    from ddgs import DDGS
    from .utils.fetch import fetch_all_content
    from .utils.tools import sort_by_score
```
`src/mcp_local_rag/utils/fetch.py:15-16` imports mediapipe at module level:
```python
from mediapipe.tasks import python
from mediapipe.tasks.python import text
```
`uv.lock` lists `matplotlib` as a dependency of `mediapipe 0.10.35`. The repository itself contains no `tempfile`, `/tmp` or `random` usage.

The Docker image creates the runtime user without a home directory (`useradd -r` does not create one):

`Dockerfile:40,49`
```dockerfile
RUN groupadd -r app && useradd -r -g app app
...
USER app
```
matplotlib's `_get_config_or_cache_dir()` then fails to create `$HOME/.config/matplotlib`, calls `tempfile.mkdtemp(prefix="matplotlib-")`, sets `MPLCONFIGDIR` to it and registers `atexit.register(shutil.rmtree, tmpdir)`. It also logs a warning telling the user to set `MPLCONFIGDIR`.

## Steps to reproduce
1. Prerequisites: Docker. No API keys. The arguments below make no network requests.
2. Build the image from the tested commit:
   ```bash
   git clone https://github.com/nkapila6/mcp-local-rag && cd mcp-local-rag
   git checkout aabb55d
   docker build -t mcp-local-rag:aabb55d .
   ```
3. Call the tool with these arguments:
   ```json
   {"search_terms": [], "num_results_per_term": 0, "top_k_per_term": 0, "include_urls": false}
   ```

   ```python
   import asyncio
   import subprocess
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="docker",
           args=["run", "--rm", "-i", "--init", "--name", "tofu-rag", "mcp-local-rag:aabb55d"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("deep_research_ddgs", {
                   "search_terms": [], "num_results_per_term": 0,
                   "top_k_per_term": 0, "include_urls": False,
               })
               print(result)
               # inspect /tmp inside the still-running container
               out = subprocess.run(
                   ["docker", "exec", "tofu-rag", "sh", "-c", "echo HOME=$HOME; ls -ld /tmp/matplotlib-*"],
                   capture_output=True, text=True,
               )
               print(out.stdout, out.stderr)

   asyncio.run(main())
   ```
4. Observe a `drwx------ ... /tmp/matplotlib-XXXXXXXX` directory owned by `app`, and the matplotlib "created a temporary cache directory" warning on the server's stderr.

## Expected behavior
matplotlib (pulled in by mediapipe) uses a stable, app-owned cache directory. The server does not create per-process directories in the shared `/tmp`.

## Actual behavior
A `matplotlib-*` directory appears in `/tmp` after the first tool call and stays until the process exits. ToFu's tracer reported, after a call with the arguments above:
```
Tool execution finished but left 1 uncleaned temporary resource(s) on disk: ['/tmp/matplotlib-v4itsqr2']
```
In the same fuzzing environment the call itself returned an error (`Error calling tool 'deep_research_ddgs': 'function' object is not subscri...`). I could not determine the cause of that error from the code. It may be specific to the fuzzing environment.

## Impact
Low. The tool arguments do not influence the directory, so an LLM or a prompt injection gains nothing from it. Because matplotlib uses `mkdtemp`, other local users cannot predict or pre-create the path. The practical effects are a warning on every start, a cold matplotlib font cache on every start, and a leftover directory if the process is killed without running `atexit` handlers (for example `SIGKILL`). Inside a `--rm` container the leftover is discarded with the container.

## Suggested fix
Give matplotlib a writable, app-owned config directory in the image, for example:
```dockerfile
RUN groupadd -r app && useradd -r -m -g app app
```
or
```dockerfile
ENV MPLCONFIGDIR=/app/.cache/matplotlib
RUN mkdir -p /app/.cache/matplotlib && chown -R app:app /app/.cache
```
For non-Docker installs, the README could mention setting `MPLCONFIGDIR` when the home directory is read-only.

## Status on the default branch
Still present at `aabb55d` (2026-06-10). The tested commit is the current default branch head.

## Prior reports
No issue or PR reports the `/tmp/matplotlib-*` directory, `MPLCONFIGDIR`, or temporary files. Searched all 10 issues and 98 pull requests (fetched 2026-10-01). Related context only:
- #69 "find mediapipe alternative" (issue, open 2026-03-07): the maintainer wants to drop mediapipe because it "tends to import a lot of dependencies". Removing mediapipe would also remove the matplotlib import that creates the directory. Not a report of this bug; nothing linked.
- #55 "Adds 'latest' tag during Docker build" (PR, closed 2026-01-06) and #60 "Improve Docker publishing, LFS setup, and repo metadata" (PR, closed 2026-04-04): both describe switching the runtime container to a non-root `app` user. The default-branch Dockerfile now has `useradd -r -g app app` with no home directory, which is the condition that triggers matplotlib's temp-dir fallback. Hardening changes, not fixes for this; the JSON does not show which of the two landed it.
- Documentation: README.md, skills/ and the Dockerfile comments say nothing about `MPLCONFIGDIR`, temp or cache directories. The README's "Security audits" section only links an external MseeP audit page.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: insecure-temp-file. Evidence call fired `check_introspection_type_confusion`, `check_introspection_incomplete_cleanup`, `check_introspection_weak_prng`, `check_introspection_temp_file_leak` (same as the tool-level triggered set).
- Campaigns and executions: `recover-pc` 500 exec / 0 success (60 s); `e2-0922` 1 exec / 0 success (60 s). The tool never completed successfully in either campaign.
- Evidence (verbatim, trimmed): input `{'search_terms': [], 'num_results_per_term': 0, 'top_k_per_term': 0, 'include_urls': False}`; output `None`; analysis "left 1 uncleaned temporary resource(s) on disk: ['/tmp/matplotlib-v4itsqr2']", "Weak PRNG ... 'random.choice' used", "'function' object is not subscri".
- Hand-check hints: weak, most likely a false positive for CWE-377. The repo has no temp-file code (grep for `tempfile|mkdtemp|/tmp|random|matplotlib` in `src/`, `Dockerfile`, `.devcontainer` finds nothing). The `matplotlib-` prefix is matplotlib's own `mkdtemp` fallback (checked in matplotlib 3.11.1 `__init__.py:584-592`; the lockfile pins 3.10.1, not checked). `mkdtemp` is the secure API, and matplotlib registers `atexit` cleanup. ToFu checks after each call while the process is alive, so it will always see the directory. The bwrap sandbox probably also made `$HOME` unwritable, which is what triggers the fallback. The `random.choice` alert most likely comes from `ddgs`, not repo code (not verified). Not verified by running: that `mediapipe` 0.10.35 actually imports matplotlib at `from mediapipe.tasks import python`, and the cause of the "'function' object is not subscriptable" error. Same root cause as the drafts for `deep_research`, `deep_research_google`, `rag_search_ddgs`, `rag_search_google`: file at most one issue, if any, and frame it as a Dockerfile hygiene fix.
</details>
