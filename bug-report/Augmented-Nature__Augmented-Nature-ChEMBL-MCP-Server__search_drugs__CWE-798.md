# `search_drugs` flagged for a hard-coded credential, but none exists in the source (likely false positive)

**Repository:** `Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server` · **Tool:** `search_drugs` · **Tested commit:** `02782d7`
**Weakness:** CWE-798 Use of Hard-coded Credentials

## Summary
`search_drugs` queries the public ChEMBL REST API (`/molecule/search.json`) and returns molecules with `max_phase >= 1`. Our fuzzer's runtime check reported a string matching a secret-key pattern during one `search_drugs` call. We reviewed the whole server at the tested commit and found no API key, token or password: the server talks to ChEMBL without authentication. We believe this report is a false positive and do not suggest a change for it.

## Details
The only HTTP client is created with a fixed base URL and two non-secret headers (`src/index.ts:197-204`):

```ts
this.apiClient = axios.create({
  baseURL: 'https://www.ebi.ac.uk/chembl/api/data',
  timeout: 30000,
  headers: {
    'User-Agent': 'ChEMBL-MCP-Server/1.0.0',
    'Accept': 'application/json',
  },
});
```

`handleSearchDrugs` (`src/index.ts:1274-1310`) sends `q` and `limit` as query parameters and returns the JSON result or a fixed `Failed to search drugs: ...` error. `src/index.ts` does not read `process.env`, and a search of the repository for common key formats (OpenAI-style `sk-`, GitHub `ghp_`, AWS `AKIA`, Google `AIzaSy`, `Bearer` tokens) finds nothing.

## Steps to reproduce
1. Prerequisites: Node.js 16+ and npm, network access to `www.ebi.ac.uk`, and the `mcp` Python package for the client script. No account or key is needed.
2. Install and build as the README describes:

   ```bash
   git clone https://github.com/Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server && cd Augmented-Nature-ChEMBL-MCP-Server
   git checkout 02782d7
   npm install && npm run build
   ```
3. Check the source for secrets, then call the tool:

   ```bash
   grep -rniE 'sk-[a-z0-9]{16,}|ghp_[a-z0-9]{30,}|akia[0-9a-z]{16}|aizasy[a-z0-9_-]{33}|bearer\s+[a-z0-9_.-]{20,}' src/ README.md Dockerfile package.json
   ```

   Arguments:
   ```json
   {"query": "aspirin", "limit": 5}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/Augmented-Nature-ChEMBL-MCP-Server/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("search_drugs", {"query": "aspirin", "limit": 5})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `grep` prints nothing and the result contains only public ChEMBL molecule data.

## Expected behavior
No credentials in source or in tool output.

## Actual behavior
That is what we see in the source. We could not recover the string our fuzzer matched, because the run log did not survive.

## Impact
None identified.

## Suggested fix
No change needed for this report.

## Status on the default branch
The tested commit `02782d7` (2025-12-21) is the current head of the default branch.

## Prior reports
None found. Searched all 0 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The repository is now at `Augmented-Nature/ChEMBL-MCP-Server` (the API returns that name). PR #2 (open) is a third-party scan badge reporting no findings. The README mentions no API key, token or credential.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: hardcoded-creds; triggered `check_introspection_hardcoded_credentials` and `check_resource_exhaustion`.
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`; everything above is derived from the code at `02782d7`.
- Hand-check hints: weak, likely a false positive; recommend not filing. ToFu's check (`src/sanitizers/introspection.py:1244-1278`) regex-matches `str(res.result)` plus captured log messages (`src/fuzzer.py:766`), case-insensitively. With `re.IGNORECASE`, `sk-[a-zA-Z0-9]{16,}` matches any text containing `sk-` followed by 16 alphanumerics (for example inside a word like `task-...`), and `AKIA[0-9A-Z]{16}` matches `akia` plus 16 alphanumerics. The only call failed (0 successes), so the matched string was most likely in an error message or echoed fuzzer input, not in the server. The target source has no match for any of the patterns. Not run here.
</details>
