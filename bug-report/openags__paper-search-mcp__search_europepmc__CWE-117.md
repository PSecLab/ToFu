# Log injection in `search_europepmc`: CR/LF in `query` forges lines in the server log

**Repository:** `openags/paper-search-mcp` · **Tool:** `search_europepmc` · **Tested commit:** `234678a`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
After every successful Europe PMC search, the connector logs `Europe PMC search returned N papers for query: <query>` with the caller's query inserted verbatim. A query containing `\r\n` splits the record, and the text after the newline appears as its own line in the server's stderr log. The impact is limited to misleading log readers and log tooling.

## Details
`paper_search_mcp/server.py:908-919` passes `query` through `async_search` to `EuropePMCSearcher.search`, `paper_search_mcp/academic_platforms/europepmc.py:69-86`:

```python
response = self.session.get(f"{self.BASE_URL}/search", params=params, timeout=30)
response.raise_for_status()
data = response.json()
...
logger.info(f"Europe PMC search returned {len(papers)} papers for query: {query}")
```

`query` is not stripped of CR/LF. `FastMCP()` configures the root logger at INFO with a stderr handler (checked in the `mcp` 1.x SDK, version 1.30.0: `configure_logging()` calls `logging.basicConfig(level="INFO")`), so this INFO record is emitted in a normal stdio deployment.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `www.ebi.ac.uk`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a query that contains CR/LF (`max_results: 0` matches the fuzzing run):

   ```json
   {"query": "tofu-poc\r\nFAKE-LOG-ENTRY", "max_results": 0}
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
               result = await session.call_tool("search_europepmc",
                   {"query": "tofu-poc\r\nFAKE-LOG-ENTRY", "max_results": 0})
               print(result)

   asyncio.run(main())
   ```
4. Observe on stderr that the `Europe PMC search returned ... for query: tofu-poc` record is split and `FAKE-LOG-ENTRY` starts its own line.

## Expected behavior
User-supplied values are neutralized before logging, for example with `%r` formatting.

## Actual behavior
The newline reaches the log handler unchanged. From the fuzzing run (record captured on logger `paper_search_mcp.academic_platforms.europepmc`):

```
{'query': '"query": K../../../111111111111../etc/passwd ","max_re\nsults": 1', 'max_results': 0}
-> logged: 'Europe PMC search returned 0 papers for query: "query": K../../../111111111111../etc/passwd ","max_re\nsults": 1'
```

## Impact
The LLM chooses `query`, so prompt injection in untrusted content can write arbitrary lines into the log the MCP host keeps for this server, for example to hide activity among fake entries or to confuse log parsers. No code execution or data access. Severity: low.

## Suggested fix
Use lazy `%r` formatting so control characters are escaped:

```python
logger.info("Europe PMC search returned %d papers for query: %r", len(papers), query)
```

The same pattern (f-string logging of caller input) appears in other connectors, for example `pmc.py:66` and `crossref.py:283`, so a repo-wide pass would be worthwhile.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `europepmc.py` is unchanged.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_log_injection`, `check_introspection_temp_file_leak`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 1 / 1 (60 s each).
- Evidence (verbatim, trimmed):
  - `{'query': '"query": K../../../111111111111../etc/passwd ","max_re\nsults": 1', 'max_results': 0}` -> `''`; logged with raw `\n`
  - `{'query': '"query": K../../../001710372955../etc/passwd ","max_re\nsults": 1', 'max_results': 0}` -> `''`; same
  - `{'query': '"query": "\'; DR OPTABLE users; --\x7f\x7f\x7f\x7fmax_re\x01\x00...\n1', 'max_results': 0}` -> `''`; logged `... --max_re      \n1`
- Hand-check hints: real, low severity. The tracer captured the actual log record with a raw `\n`. The log line is only written when the Europe PMC request succeeds; the error branches do not include the query. FastMCP logging setup verified in mcp 1.30.0 only (`uv.lock` pins 1.26.0). I did not confirm Europe PMC accepts `pageSize=0` today; the run shows it did.
</details>
