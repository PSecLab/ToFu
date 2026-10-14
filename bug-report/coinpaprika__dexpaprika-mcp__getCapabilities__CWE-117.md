# `getCapabilities`: `rationale` is described as logged but its schema accepts CR/LF and control characters

**Repository:** `coinpaprika/dexpaprika-mcp` · **Tool:** `getCapabilities` · **Tested commit:** `9ef4a9f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
Every read tool, `getCapabilities` included, requires a `rationale` string of 20-500 characters. The schema description tells the model the value is "Logged for MCP improvement". The Zod schema accepts any characters, including CR, LF and other control characters. In this stdio build the handler ignores the value and I found no log sink for it. The issue is that a field advertised as logged is not neutralized, which matters wherever rationales are stored, such as the hosted worker this build mirrors. It is not an injection that happens in this repo today.

## Details
`src/index.js:377-384` at `9ef4a9f`:

```js
// Accepted by the handler and IGNORED (no analytics sink; no D1 in stdio).
const RATIONALE_DESCRIPTION =
  'REQUIRED. 1-2 sentence rationale for this call (e.g. "User asked for X; calling Y to fetch Z"). ' +
  'Logged for MCP improvement, never shown to end users. No PII or secrets. ' +
  'See the server `instructions` field for the full convention and worked examples.';

const rationaleZod = z.string().min(20).max(500).describe(RATIONALE_DESCRIPTION);
```

- `registerReadTool` (`src/index.js:762-775`) adds `rationale: rationaleZod` to every read tool.
- The `getCapabilities` handler (`src/index.js:791-803`) takes no arguments and returns `buildCapabilitiesDocument()`.
- The only log line in the server (`src/index.js:320`) prints the upstream URL and HTTP status, not the rationale.
- The header comment (`src/index.js:16-21`) says this build is "contract-aligned 1:1 with the hosted v2.0.0 Cloudflare Worker". The rationale comment refers to a D1 sink that exists outside stdio.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. `getCapabilities` makes no upstream call, so no network access or API key is needed.
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
   {"rationale": "User asked for docs; tofu-poc\r\nFAKE-LOG-ENTRY calling getCapabilities"}
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
               result = await session.call_tool("getCapabilities", {"rationale": "User asked for docs; tofu-poc\r\nFAKE-LOG-ENTRY calling getCapabilities"})
               print(result)

   asyncio.run(main())
   ```
   Run it as `python poc.py 2> /tmp/tofu-poc-stderr.txt` to capture the server's stderr.
4. What to observe: the call succeeds. The schema accepts the CR/LF value without complaint. In this build `FAKE-LOG-ENTRY` does not appear in `/tmp/tofu-poc-stderr.txt`, because the value is never logged.

## Expected behavior
A field described as logged should reject or neutralize control characters at the schema boundary. Alternatively, the self-host build should not describe the field as logged.

## Actual behavior
Any string of 20-500 characters is accepted, including CR/LF. From the fuzzing run:

```
input:  {'rationale': '"e": ".uiardcy systei\x7f\x7f\nso'}
output: {"name": "dexpaprika", "aliases": [...], "server": {"name": "DexPaprika MCP", "version": "2.0.0"}, ...}
```

## Impact
Low in this repo. The value reaches no log here. If a deployment does store or log rationales, the model picks this argument, and prompt injection could steer it to forge entries in that log. The field also tells the model it is "logged for MCP improvement", which models may treat as a promise of telemetry.

## Suggested fix
Tighten the schema so the problem cannot appear in any sink that reuses it:

```js
const rationaleZod = z.string().min(20).max(500)
  .regex(/^[^\x00-\x1f\x7f]*$/, 'rationale must be a single line of printable text')
  .describe(RATIONALE_DESCRIPTION);
```

Or normalize with `.transform(s => s.replace(/[\x00-\x1f\x7f]+/g, ' '))`. In the stdio build, consider rewording "Logged for MCP improvement" to match what the code does.

## Status on the default branch
Changed but not fixed. `src/index.js` was modified up to `9428878` (2026-09-29). The `rationale` schema and the "IGNORED" comment are unchanged (`src/index.js:402-410` at HEAD), and the `getCapabilities` handler is unchanged (`src/index.js:828-839` at HEAD).

## Prior reports
No issue or pull request reports control characters in `rationale` or any log-injection problem. Searched all 2 issues and 56 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #18 "Sync self-host package to hosted worker v2.0.0 (full contract parity)" (PR, closed 2026-06-03): introduced the required `rationale` field and states it is "accepted and discarded" with "no analytics sink in self-host". Confirms the stdio build never logs it; no validation was added.
- Documentation: CHANGELOG.md (2.0.0 entry): "The self-host build accepts it to satisfy the schema and does not persist it (no analytics sink)." (documents that this build discards `rationale`, while the tool schema at `9428878` still tells the model it is "Logged for MCP improvement")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, the only sanitizer that fired. It is an input-pattern check reported as a "Silent Bug Alert". No introspection log sink fired.
- Campaigns and executions: corpus-sbx 2,560 exec / 2,012 ok (60 s). e2-0922 1,024 / 807 (60 s).
- Evidence (verbatim, trimmed): input `{'rationale': '"e": ".uiardcy systei\x7f\x7f\nso'}` -> the normal capabilities JSON (`{"name": "dexpaprika", "aliases": ["dexpapika", ...], "server": {"name": "DexPaprika MCP", "version": "2.0.0"}, "tools_count": 17, ...`). analysis: `Sanitizers ['check_log_injection'] flagged this input as malicious, but the target tool executed successfully without raising any exception.`
- Hand-check hints: weak, and likely a false positive for this repo. The handler ignores `rationale` (code comment at `index.js:377` plus handler body). There is no logging of it anywhere in `src/`. The draft is written as a schema-hardening note. Consider not filing it, or filing one issue for all three dexpaprika tools (getCapabilities, getNetworks, getStats), since the same `rationaleZod` is shared by every read tool. Whether the hosted worker logs rationales is unknown. That code is not in this repo.
</details>
