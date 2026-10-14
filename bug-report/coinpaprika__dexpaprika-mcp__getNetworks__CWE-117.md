# `getNetworks`: `rationale` is described as logged but its schema accepts CR/LF and control characters

**Repository:** `coinpaprika/dexpaprika-mcp` · **Tool:** `getNetworks` · **Tested commit:** `9ef4a9f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`getNetworks` lists the blockchain networks DexPaprika indexes. Like every read tool, it requires a `rationale` string of 20-500 characters, which its schema describes as "Logged for MCP improvement". The Zod schema accepts CR, LF and other control characters. In this stdio build the handler ignores `rationale` and nothing logs it. This report is about a field advertised as logged without neutralization, which matters for any sink that stores rationales. It is not an injection observed in this repo.

## Details
`src/index.js:384` at `9ef4a9f` defines the shared schema:

```js
const rationaleZod = z.string().min(20).max(500).describe(RATIONALE_DESCRIPTION);
```

The description (`src/index.js:379-382`) says "Logged for MCP improvement, never shown to end users". The comment above it (`src/index.js:376-377`) says the value is "Accepted by the handler and IGNORED (no analytics sink; no D1 in stdio)". The handler, `src/index.js:777-789`:

```js
registerReadTool(
  'getNetworks',
  '...',
  {},
  async () => {
    try {
      return jsonText(await fetchFromAPI('/networks'), 'networks');
    } catch (error) {
      return errorText(error);
    }
  },
);
```

The only log line on this path is `fetchFromAPI`'s upstream error line (`src/index.js:320`). It prints the fixed URL and HTTP status, not the rationale.

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
   {"rationale": "User asked for chains; tofu-poc\r\nFAKE-LOG-ENTRY calling getNetworks"}
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
               result = await session.call_tool("getNetworks", {"rationale": "User asked for chains; tofu-poc\r\nFAKE-LOG-ENTRY calling getNetworks"})
               print(result)

   asyncio.run(main())
   ```
   Run it as `python poc.py 2> /tmp/tofu-poc-stderr.txt` to capture the server's stderr.
4. What to observe: the call succeeds and returns the network list. The CR/LF value passes validation. In this build `FAKE-LOG-ENTRY` does not appear in the captured stderr.

## Expected behavior
A field described as logged should reject or neutralize control characters at the schema boundary. Alternatively, the stdio build should not describe it as logged.

## Actual behavior
Any 20-500 character string is accepted, including CR/LF. From the fuzzing run:

```
input:  {'rationale': '"rationale": "U\r\x1cr asked for X; rationale incuyyyldes fil\x7f...\x1de access aw'}
output: [{"display_name": "Fantom", "id": "fantom", ...}, {"display_name": "ZkSync", ...}, ...]
```

## Impact
Low in this repo. The value reaches no log. If a deployment stores or logs rationales, the model picks this argument and prompt injection could steer it to forge log entries there.

## Suggested fix
Harden the shared schema once, which covers all read tools:

```js
const rationaleZod = z.string().min(20).max(500)
  .regex(/^[^\x00-\x1f\x7f]*$/, 'rationale must be a single line of printable text')
  .describe(RATIONALE_DESCRIPTION);
```

Or normalize with `.transform(s => s.replace(/[\x00-\x1f\x7f]+/g, ' '))`. Consider rewording "Logged for MCP improvement" in the stdio build.

## Status on the default branch
Changed but not fixed. `src/index.js` was modified up to `9428878` (2026-09-29). The `rationale` schema is unchanged (`src/index.js:402-410` at HEAD), and so is the `getNetworks` handler (`src/index.js:814-825` at HEAD).

## Prior reports
No issue or pull request reports control characters in `rationale` or any log-injection problem. Searched all 2 issues and 56 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #18 "Sync self-host package to hosted worker v2.0.0 (full contract parity)" (PR, closed 2026-06-03): introduced the required `rationale` field and states it is "accepted and discarded" with "no analytics sink in self-host". Confirms the stdio build never logs it; no validation was added.
- Documentation: CHANGELOG.md (2.0.0 entry): "The self-host build accepts it to satisfy the schema and does not persist it (no analytics sink)." (documents that this build discards `rationale`, while the tool schema at `9428878` still tells the model it is "Logged for MCP improvement")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, the only sanitizer that fired. It is an input-pattern check reported as a "Silent Bug Alert". No introspection log sink fired.
- Campaigns and executions: corpus-sbx 512 exec / 19 ok (60 s). e2-0922 512 / 48 (60 s). The low success rate is probably the 20-char minimum and upstream failures. Not verified.
- Evidence (verbatim, trimmed): input `{'rationale': '"rationale": "U\r\x1cr asked for X; rationale incuyyyldes fil\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x1de access aw'}` -> normal networks list (`[{"display_name": "Fantom", "id": "fantom", "volume_usd_24h": 1.515345, ...`). Second input: 26 `\r` plus `\x7f` runs, same output.
- Hand-check hints: weak, and likely a false positive for this repo. Same root as the getCapabilities and getStats drafts: one shared `rationaleZod`, ignored by every stdio handler. Recommend merging the three into one issue or not filing.
</details>
