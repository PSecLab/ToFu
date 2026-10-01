# Log injection in `search_pmc`: CR/LF in `query` forges lines in the server log

**Repository:** `openags/paper-search-mcp` · **Tool:** `search_pmc` · **Tested commit:** `234678a`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
When a PubMed Central search returns no IDs, the connector logs `No PMC results found for query: <query>` with the caller's query inserted verbatim. A query containing `\r\n` splits the record, and the text after the newline appears as its own line in the server's stderr log. The impact is limited to misleading log readers and log tooling.

## Details
`paper_search_mcp/server.py:880-891` passes `query` through `async_search` to `PMCSearcher.search`, `paper_search_mcp/academic_platforms/pmc.py:59-66`:

```python
search_response = self.session.get(self.EUTILS_SEARCH_URL, params=search_params, timeout=30)
search_response.raise_for_status()
search_root = ET.fromstring(search_response.content)

# Get PMC IDs
pmcids = [id_elem.text for id_elem in search_root.findall('.//Id') if id_elem.text]
if not pmcids:
    logger.info(f"No PMC results found for query: {query}")
    return papers
```

`query` is not stripped of CR/LF. `FastMCP()` configures the root logger at INFO with a stderr handler (checked in the `mcp` 1.x SDK, version 1.30.0: `configure_logging()` calls `logging.basicConfig(level="INFO")`), so this record is emitted in a normal stdio deployment. The line is logged whenever the search returns no IDs; in the fuzzing run, `max_results: 0` (sent as `retmax=0`) produced that case.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `eutils.ncbi.nlm.nih.gov`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a query that contains CR/LF:

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
               result = await session.call_tool("search_pmc",
                   {"query": "tofu-poc\r\nFAKE-LOG-ENTRY", "max_results": 0})
               print(result)

   asyncio.run(main())
   ```
4. Observe on stderr that the `No PMC results found for query: tofu-poc` record is split and `FAKE-LOG-ENTRY` starts its own line.

## Expected behavior
User-supplied values are neutralized before logging, for example with `%r` formatting.

## Actual behavior
The CR/LF reaches the log handler unchanged. From the fuzzing run (record captured on logger `paper_search_mcp.academic_platforms.pmc`):

```
{'query': '"quer", "m\r\n\x13\x02s', 'max_results': 0}
-> logged: 'No PMC results found for query: "quer", "m\r\ns'
```

## Impact
The LLM chooses `query`, so prompt injection in untrusted content can write arbitrary lines into the log the MCP host keeps for this server. No code execution or data access. Severity: low.

## Suggested fix
Use lazy `%r` formatting so control characters are escaped:

```python
logger.info("No PMC results found for query: %r", query)
```

Other connectors log caller input the same way (for example `europepmc.py:86`, `crossref.py:283`); one repo-wide change would cover them.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `pmc.py` is unchanged.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Triggered: `check_introspection_log_injection`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'query': '"quer", "m\r\n\x13\x02s', 'max_results': 0}` -> `''`; logged `No PMC results found for query: "quer", "m\r\ns`
  - `{'query': '"quer", "m\r\n\x13\x02s0}er", "m\r\n\x13\x00\x00', 'max_results': 0}` -> `''`; logged with two raw CRLFs
  - `{'query': '"quer\r", 0}er", "m\r\n\x13\x00\x00', 'max_results': 0}` -> `''`; logged with raw `\r` and `\r\n`
- Hand-check hints: real, low severity. The tracer captured the log records with raw CR/LF. The tracer's logged content omits the `\x13\x02` bytes from the input; I did not determine why, but CR/LF survived. FastMCP logging setup verified in mcp 1.30.0 only (`uv.lock` pins 1.26.0). Consider one combined CWE-117 issue with `search_europepmc` and `get_crossref_paper_by_doi`.
</details>
