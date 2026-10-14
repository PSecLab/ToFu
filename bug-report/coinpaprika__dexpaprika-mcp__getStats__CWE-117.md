# `getStats`: `rationale` is described as logged but its schema accepts CR/LF and control characters

**Repository:** `coinpaprika/dexpaprika-mcp` · **Tool:** `getStats` · **Tested commit:** `9ef4a9f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`getStats` returns platform-wide totals (chains, factories, pools, tokens). Its only argument is the shared `rationale` string, which the schema describes as "Logged for MCP improvement". That schema accepts CR, LF and other control characters. In this stdio build the handler ignores the value and nothing logs it. This is a schema-hardening report for a field advertised as logged. It is not an injection observed in this repo.

## Details
Shared schema, `src/index.js:379-384` at `9ef4a9f`:

```js
const RATIONALE_DESCRIPTION =
  'REQUIRED. 1-2 sentence rationale for this call (e.g. "User asked for X; calling Y to fetch Z"). ' +
  'Logged for MCP improvement, never shown to end users. No PII or secrets. ' +
  'See the server `instructions` field for the full convention and worked examples.';

const rationaleZod = z.string().min(20).max(500).describe(RATIONALE_DESCRIPTION);
```

The `getStats` handler (`src/index.js:1257-1268`) takes no arguments and returns `jsonText(await fetchFromAPI('/stats'))`. The comment at `src/index.js:376-377` says rationales are "Accepted by the handler and IGNORED (no analytics sink; no D1 in stdio)". The only log line on this path (`src/index.js:320`) prints the fixed upstream URL and status.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and outbound HTTPS to the DexPaprika API. No API key is needed.
2. Install and start the server:
   ```
   git clone https://github.com/coinpaprika/dexpaprika-mcp.git
   cd dexpaprika-mcp && git checkout 9ef4a9f6f9993e55612ca56de0f7f8e69934945b
   npm install
   node src/bin.js
   ```
   (The README's `npx dexpaprika-mcp@latest` runs the latest published version instead.)
3. Call the tool with these arguments:
   ```json
   {"rationale": "User asked for totals; tofu-poc\r\nFAKE-LOG-ENTRY calling getStats"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["src/bin.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("getStats", {"rationale": "User asked for totals; tofu-poc\r\nFAKE-LOG-ENTRY calling getStats"})
               print(result)

   asyncio.run(main())
   ```
   Run it as `python poc.py 2> /tmp/tofu-poc-stderr.txt` to capture the server's stderr.
4. What to observe: the call succeeds and returns the totals. The CR/LF value passes validation. In this build `FAKE-LOG-ENTRY` does not appear in the captured stderr.

## Expected behavior
A field described as logged should reject or neutralize control characters at the schema boundary. Alternatively, the stdio build should not describe it as logged.

## Actual behavior
Control characters are accepted. From the fuzzing run:

```
input:  {'rationale': ']\r\x1e\x0b\x1c\x1e\x0fling Y toonal\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'}
output: {"chains": 36, "factories": 241, "pools": 42125867, "tokens": 38301404}
```

## Impact
Low in this repo. The value reaches no log. If a deployment stores or logs rationales, the model picks this argument and prompt injection could steer it to forge entries there.

## Suggested fix
Harden the shared schema once, which covers all read tools:

```js
const rationaleZod = z.string().min(20).max(500)
  .regex(/^[^\x00-\x1f\x7f]*$/, 'rationale must be a single line of printable text')
  .describe(RATIONALE_DESCRIPTION);
```

Or normalize with `.transform(s => s.replace(/[\x00-\x1f\x7f]+/g, ' '))`. Consider rewording "Logged for MCP improvement" in the stdio build.

## Status on the default branch
Changed but not fixed. `src/index.js` was modified up to `9428878` (2026-09-29). The `rationale` schema is unchanged (`src/index.js:402-410` at HEAD), and so is the `getStats` handler (`src/index.js:1322-1333` at HEAD).

## Prior reports
No issue or pull request reports control characters in `rationale` or any log-injection problem. Searched all 2 issues and 56 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #18 "Sync self-host package to hosted worker v2.0.0 (full contract parity)" (PR, closed 2026-06-03): introduced the required `rationale` field and states it is "accepted and discarded" with "no analytics sink in self-host". Confirms the stdio build never logs it; no validation was added.
- Documentation: CHANGELOG.md (2.0.0 entry): "The self-host build accepts it to satisfy the schema and does not persist it (no analytics sink)." (documents that this build discards `rationale`, while the tool schema at `9428878` still tells the model it is "Logged for MCP improvement")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, the only sanitizer that fired. It is an input-pattern check reported as a "Silent Bug Alert". No introspection log sink fired.
- Campaigns and executions: corpus-sbx 512 exec / 18 ok (60 s).
- Evidence (verbatim, trimmed):
  - input `{'rationale': ']\r\x1e\x0b\x1c\x1e\x0fling Y toonal\x00...'}` -> `{'content': [{'type': 'text', 'text': '{\n  "chains": 36,\n  "factories": 241,\n  "pools": 42125867,\n  "tokens": 38301404\n}'}], 'structuredContent': {...}}`.
  - input `{'rationale': 'dX; calling Y t\x0e fetch Z. Test\x17\x11\x18_\x19\x10\rWdeadlokc :wiMe(t&rue){}'}` -> same output.
- Hand-check hints: weak, and likely a false positive for this repo. It is the same shared `rationaleZod` as getCapabilities and getNetworks, ignored by the handler. Recommend merging the three into one issue or not filing.
</details>
