# Missing output encoding in `get-station-code-by-names`: unknown `stationNames` are echoed back unescaped

**Repository:** `Joooook/12306-mcp` · **Tool:** `get-station-code-by-names` · **Tested commit:** `ff6439d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get-station-code-by-names` looks up `station_code` values by Chinese station name. Each name the caller sends becomes a key in the JSON result, including names that are not found, so caller text comes back verbatim. `JSON.stringify` escapes quotes and control characters but not `<`, `>` or template braces. The result is a plain-text content block, so this only matters if an MCP client renders tool output as HTML or Markdown. This is a low-severity output-encoding report.

## Details
`src/index.ts:929-944` at `ff6439d`:

```ts
    async ({ stationNames }) => {
        let result: Record<string, object> = {};
        for (let stationName of stationNames.split('|')) {
            stationName = stationName.endsWith('站')
                ? stationName.substring(0, stationName.length - 1)
                : stationName;
            if (!(stationName in NAME_STATIONS)) {
                result[stationName] = { error: '未检索到城市。' };
            } else {
                result[stationName] = NAME_STATIONS[stationName];
            }
        }
        return {
            content: [{ type: 'text', text: JSON.stringify(result) }],
        };
    }
```

The only constraint on `stationNames` is `z.string()` (lines 923-924). Unknown names are kept as object keys and serialized back. Nothing limits the length or the character set of a name.

## Steps to reproduce
1. Prerequisites: Node.js 18+. The server downloads the station list from 12306 at startup (`src/index.ts:49`, `getStations()` at line 1540), so it needs outbound HTTPS to `www.12306.cn` (`WEB_URL`, line 30).
2. Start the server as the README describes: `npx -y 12306-mcp`. To test the exact commit: `git clone https://github.com/Joooook/12306-mcp && cd 12306-mcp && git checkout ff6439d && npm i && node build/index.js`.
3. Call the tool with `{"stationNames": "<img src=x onerror=alert(1)>|{{7*7}}"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "12306-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "get-station-code-by-names",
                   {"stationNames": "<img src=x onerror=alert(1)>|{{7*7}}"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that the text content is `{"<img src=x onerror=alert(1)>":{"error":"未检索到城市。"},"{{7*7}}":{"error":"未检索到城市。"}}`, with the markup and braces unchanged.

## Expected behavior
Names that are not found are not echoed back raw. Either the tool returns a fixed "not found" message, or a client that renders the output escapes it for its own context.

## Actual behavior
Caller text is returned verbatim as a JSON key. Real output from the fuzz run (input `"{\x00,{{"`):

```
{"{\u0000,{{":{"error":"未检索到城市。"}}
```

## Impact
Low. `stationNames` is chosen by the LLM, which can be steered by prompt injection from untrusted content. Script would only run if an MCP client rendered the tool's text output as HTML without escaping. In a normal chat client the echoed text is shown as plain text and nothing happens.

## Suggested fix
Do not reflect unknown names as-is. For example, cap the number of names, and only list a not-found name if it looks like a station name:

```ts
const names = stationNames.split('|').slice(0, 20);
const notFound: string[] = [];
for (let name of names) {
    name = name.endsWith('站') ? name.slice(0, -1) : name;
    if (Object.prototype.hasOwnProperty.call(NAME_STATIONS, name)) {
        result[name] = NAME_STATIONS[name];
    } else if (/^[一-鿿]{1,20}$/.test(name)) {
        notFound.push(name);
    }
}
```

Using `hasOwnProperty` instead of `in` also stops names such as `constructor` or `toString` from matching inherited object properties.

## Status on the default branch
Still present at `ff6439d` (2026-07-31). The default branch has no commits after the tested one.

## Prior reports
- #70 "feat: improve 12306 MCP stability and ticket query tools" (PR, open 2026-09-18): says it will "improve ticket input validation" and adds station search tools; the body does not mention this tool, echoed names or output escaping. Does not fix this as described.
- #56 "Heads-up from a static scan: `eval()` on fetched data in `src/index.ts`" (issue, closed 2026-06-29): the only security report; it is about `eval()` on remote data, different code. There is no `eval(` left in `src/` at the tested head.
- Documentation: `docs/principle.md` describes the tool only as station name to station id via `NAME_STATIONS`. README.md and `docs/` say nothing about unknown names, escaping or untrusted input.
- No issue or PR reports this. Searched all 47 issues and 17 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116). Fired: `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx`: 2560 execs, 2560 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'stationNames': '{\x00,{{'}`, output `{'content': [{'type': 'text', 'text': '{"{\\u0000,{{":{"error":"未检索到城市。"}}'}]}`. Analysis: "input payload token(s) ['{{'] echoed UNESCAPED in the tool output". The other two rows are the same (`{{` inside a longer junk string).
- Hand-check hints: **weak.** Only `{{` was observed, inside a JSON key in a `text` content block. `<img ...>` echo in the repro is derived from `JSON.stringify` semantics, not from a run. No HTML rendering context exists in this server. The `in` vs `hasOwnProperty` point is a side observation from reading the code (for example `toString` would hit the `else` branch and serialize a function, which `JSON.stringify` drops); I did not run it. Probably not worth filing on its own.
</details>
