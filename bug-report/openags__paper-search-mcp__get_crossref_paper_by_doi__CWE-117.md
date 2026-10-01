# Log injection in `get_crossref_paper_by_doi`: CR/LF in `doi` forges lines in the server log

**Repository:** `openags/paper-search-mcp` · **Tool:** `get_crossref_paper_by_doi` · **Tested commit:** `234678a`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_crossref_paper_by_doi` logs the caller's `doi` verbatim when CrossRef answers 404 or when the request fails. A `doi` containing `\r\n` therefore splits the log record, and the text after the newline appears as a separate line in the server's stderr log. The impact is limited to misleading log readers and log tooling.

## Details
`paper_search_mcp/server.py:698-711` passes `doi` to `CrossRefSearcher.get_paper_by_doi`, `paper_search_mcp/academic_platforms/crossref.py:277-293`:

```python
url = f"{self.BASE_URL}/works/{doi}"
params = {'mailto': 'paper-search@example.org'}

response = self.session.get(url, params=params, timeout=30)

if response.status_code == 404:
    logger.warning(f"DOI not found in CrossRef: {doi}")
    return None

response.raise_for_status()
...
except requests.RequestException as e:
    logger.error(f"Error fetching DOI {doi} from CrossRef: {e}")
```

`doi` is interpolated into the message with no CR/LF stripping. `FastMCP()` sets up logging to stderr (in the `mcp` 1.x SDK I checked, 1.30.0, its `configure_logging()` calls `logging.basicConfig(level="INFO")` with a stderr handler), so these WARNING/ERROR records are emitted in a normal stdio deployment.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `api.crossref.org`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a DOI that contains CR/LF:

   ```json
   {"doi": "10.1038/tofu-poc\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "paper_search_mcp.server"])
       async with stdio_client(server) as (read, write):   # server stderr goes to this process's stderr
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_crossref_paper_by_doi",
                   {"doi": "10.1038/tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe on stderr that the warning (`DOI not found in CrossRef: ...`) or error (`Error fetching DOI ...`) is split, with `FAKE-LOG-ENTRY` starting its own line. The tool itself returns `{}`.

## Expected behavior
User-supplied values are neutralized before logging, for example with `%r` formatting or by replacing `\r` and `\n`.

## Actual behavior
The newline reaches the log handler unchanged. From the fuzzing run (log record captured by our tracer on logger `paper_search_mcp.academic_platforms.crossref`):

```
{'doi': '"\no:" i"20.1038/nure12370'}
-> tool output: {}
-> logged: 'DOI not found in CrossRef: "\no:" i"20.1038/nure12370'
```

## Impact
The LLM chooses `doi`, so prompt injection in untrusted content can put arbitrary text into the server log. An attacker can add fake lines (for example a fake "download complete" or error message) to whatever log the MCP host keeps for this server. There is no code execution or data access. Severity: low.

## Suggested fix
Log the value with `%r` instead of an f-string, which escapes control characters:

```python
logger.warning("DOI not found in CrossRef: %r", doi)
logger.error("Error fetching DOI %r from CrossRef: %s", doi, e)
```

Rejecting DOIs that do not match `^10\.\d{4,9}/\S+$` before the request would also avoid sending odd paths to the CrossRef API.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): the same f-string logging is at `crossref.py:306`, `316` and `319`.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Triggered: `check_introspection_log_injection`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 512 exec / 512 ok; repo24 18944 / 18943 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'doi': '"\no:" i"20.1038/nature12370'}` -> `{}`; logged `Error fetching DOI "\no:" i"20.1038/nature12370 from CrossRef: 429 Client Error: Too Many Requests for url: https://api.crossref.org/works/%22%0Ao:%22%20i%2220.1038/nature12370?mailto=...`
  - `{'doi': '"\no:" i"20.1038/nure12370'}` -> `{}`; logged `DOI not found in CrossRef: "\no:" i"20.1038/nure12370`
  - `{'doi': '"\n\x00\x00\x00:"'}` -> `{}`; logged `Error fetching DOI "\n   :" from CrossRef: 400 Client Error ...`
- Hand-check hints: real, low severity. The tracer captured the actual log records with raw `\n`. Whether the forged line looks identical to a real entry depends on the handler: FastMCP uses `RichHandler` when `rich` is importable, which may lay out continuation lines differently from a plain `StreamHandler` (not checked). I verified the FastMCP logging setup in mcp 1.30.0 only; `uv.lock` pins 1.26.0.
</details>
