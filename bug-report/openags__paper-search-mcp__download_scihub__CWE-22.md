# Path traversal in `download_scihub`: `save_path` creates directories and writes files anywhere

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_scihub` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`download_scihub` builds a `SciHubFetcher` with `output_dir=save_path`. The constructor runs `Path(save_path).mkdir(parents=True, exist_ok=True)` on every call, before any download is tried, and a successful download is written into that directory. Because `identifier` may also be a direct `.pdf` URL, the caller controls both where the file goes and what it contains.

## Details
`paper_search_mcp/server.py:749-750`:

```python
fetcher = SciHubFetcher(base_url=base_url, output_dir=save_path)
result = await asyncio.to_thread(fetcher.download_pdf, identifier)
```

`paper_search_mcp/academic_platforms/sci_hub.py:18-22, 65-69, 81-82`:

```python
def __init__(self, base_url: str = "https://sci-hub.se", output_dir: str = "./downloads"):
    self.base_url = base_url.rstrip("/")
    self.output_dir = Path(output_dir)
    self.output_dir.mkdir(parents=True, exist_ok=True)
...
filename = self._generate_filename(response, identifier)
file_path = self.output_dir / filename
with open(file_path, 'wb') as f:
    f.write(response.content)
...
if identifier.endswith('.pdf'):
    return identifier
```

`save_path` is never resolved or compared to a download root. The file name is `<md5[:8]>_<last URL segment>.pdf`, so it cannot contain `/`, but the directory is fully caller-chosen.

## Steps to reproduce
1. Prerequisites: Python 3.10+. No Sci-Hub access is needed for this test: a local HTTP server stands in for the PDF source.
2. Install the tested commit and use the README's pip start command, plus a local PDF server:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   mkdir -p /tmp/tofu-srv && printf '%%PDF-1.4\n%% tofu-poc\n' > /tmp/tofu-srv/tofu-poc.pdf
   python3 -m http.server 8000 --bind 127.0.0.1 --directory /tmp/tofu-srv &
   ```
3. Call the tool with a `save_path` outside `./downloads`:

   ```json
   {"identifier": "http://127.0.0.1:8000/tofu-poc.pdf", "save_path": "/tmp/tofu-poc-dir"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "paper_search_mcp.server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("download_scihub",
                   {"identifier": "http://127.0.0.1:8000/tofu-poc.pdf", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/` is created and contains `<hash>_tofu-poc.pdf` with the bytes served by the local server, and that this path is returned. With any identifier that fails to download, the directory is still created, because `mkdir` runs in the constructor.

## Expected behavior
`save_path` must resolve inside a configured download directory, and nothing is created on disk unless the download succeeds.

## Actual behavior
The directory is created on every call and the file is written wherever `save_path` points. The logged fuzzing call failed at the Sci-Hub lookup, after the constructor had already called `mkdir` on `../../../../../etc` (a no-op there because the directory exists):

```
{'identifier': 'http://169.254.169.254/latest/meta-data/', 'save_path': '../../../../../etc', 'base_url': 'https://sci-hub.se'}
-> Sci-Hub download failed. Try DOI first, then title, or change mirror URL.
```

## Impact
The LLM chooses these arguments, and prompt injection in untrusted content can steer them. An attacker can create directories anywhere the server user can write and place a file whose content they control (any URL ending in `.pdf` that serves `application/pdf`), with a `.pdf` name. That is enough to plant files in user directories, fill a disk, or drop a lure document. It does not give code execution by itself. Severity: medium-low.

## Suggested fix
- Resolve `save_path` under one download root (`os.path.realpath` plus `os.path.commonpath`) in the tool handler before constructing `SciHubFetcher`, and reject anything outside it.
- Move `mkdir` out of `__init__` so it only runs right before a successful write.
- Separately, consider restricting `identifier` URLs and `base_url` to public hosts; today they can point at any host, including loopback.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `sci_hub.py:19-23` (constructor `mkdir`) and `sci_hub.py:66-70` (write) are unchanged; `server.py` still passes `save_path` straight through.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten". This is the `destructiveHint: True` on the default branch. It labels the risk but adds no check on `save_path`, so it does not fix this.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_log_injection`, `check_introspection_ssrf`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: corpus-sbx 2560 exec / 2545 ok; repo24 180224 / 178003 (4200 s); e2-0922 512 / 506.
- Evidence (verbatim, trimmed): `{'identifier': 'http://169.254.169.254/latest/meta-data/', 'save_path': '../../../../../etc', 'base_url': 'https://sci-hub.se'}` -> `Sci-Hub download failed. Try DOI first, then title, or change mirror URL.`
- Hand-check hints: real. The constructor `mkdir(parents=True)` on a caller path runs unconditionally, and `identifier` ending in `.pdf` is fetched directly, so the local-server repro needs no Sci-Hub. The single retained evidence call did not reach the write. Repro derived from source, not run; check that `http.server` sends `Content-Type: application/pdf` exactly (the code compares with `!=`). The `identifier`/`base_url` fetch of arbitrary hosts (with `verify=False`) is an SSRF issue that ToFu also flagged (`check_introspection_ssrf`); it could be a separate report.
</details>
