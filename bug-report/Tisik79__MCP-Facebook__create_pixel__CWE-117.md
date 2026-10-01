# CR/LF not neutralized in `create_pixel`: `name` accepts line breaks

**Repository:** `Tisik79/MCP-Facebook` · **Tool:** `create_pixel` · **Tested commit:** `2ebfbc9`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`create_pixel` creates a Meta pixel on the active ad account using the caller's `name`. The name is accepted with embedded `\r` and `\n` and is sent to the Graph API and echoed back in the success message unchanged. We could not find a logger that receives `name` in this code path, so the log-injection impact is not demonstrated. The finding reduces to missing input validation of a display name.

## Details
`src/index.ts:916-925` and `src/tools/pixel-tools.ts:8-15` (tested commit):

```ts
// src/tools/pixel-tools.ts
export const createPixel = async (name: string) => {
  try {
    if (!name) throw new Error('Chybí název pixelu (name).');
    const act = requireActId();
    const d = await graphPost(`${act}/adspixels`, { name });
    return { success: true, pixelId: d.id, message: `Pixel "${name}" vytvořen. Pixel ID: ${d.id}` };
  } catch (e) { return { success: false, message: formatFbError(e, 'Chyba při vytváření pixelu') }; }
};
```

`name` is only checked for being non-empty. It goes into the POST body (`src/tools/fb-graph.ts:30-33`) and into the returned text. Neither `createPixel`, `graphPost` nor `formatFbError` writes to `console` or a file.

## Steps to reproduce
1. Prerequisites: Node.js 18+, a connected Facebook ad account (`node dist/index.js login`, or `FACEBOOK_ACCESS_TOKEN` and `FACEBOOK_ACCOUNT_ID`). Without an account the call stops at `requireActId()`.
2. Install and build: `git clone https://github.com/Tisik79/MCP-Facebook.git && cd MCP-Facebook && npm install && npm run build`
3. Call the tool with:

   ```json
   {"name": "pixel\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_pixel", {"name": "pixel\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the name is not rejected. With an ad account, a pixel named with a line break is created (if Meta accepts it) and the reply contains the raw `\r\nFAKE-LOG-ENTRY`. Check the server's stderr: no log line containing the name is expected.

## Expected behavior
Control characters (`\r`, `\n`, other C0 characters) in `name` are rejected or stripped before the value is used.

## Actual behavior
The value is accepted. In the fuzzing run without an ad account, the tool returned:

```
Chyba: Chyba při vytváření pixelu: Není k dispozici reklamní účet. V Claude řekni: „Připoj Facebook účet".
```

The name never reached a log in that run.

## Impact
The LLM chooses `name`, and prompt injection can steer it. With no logger on this path, the attacker gains at most a pixel with a misleading multi-line name in the user's own ad account, and a raw line break in the tool reply. Low severity.

## Suggested fix
Reject or strip `\r`, `\n` and other control characters in `name` (for example `name.replace(/[\x00-\x1f\x7f]/g, '')`, or a zod `.regex()`), and apply the same rule to the other name fields that reach `console.error` elsewhere in the server.

## Status on the default branch
Still present at `2ebfbc9` (2026-07-06). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok; e2-0922 1536 exec / 1536 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'name': 'pixel\nInjectedLogEntry'}` -> `Chyba: Chyba při vytváření pixelu: Není k dispozici reklamní účet...`
  - `{'name': 'pixel\r\nAnotherLogEntry'}` -> same error.
  - `{'name': 'j{{\r\x02j'}` -> same error.
- Hand-check hints: weak, likely a false positive. `check_log_injection` fires on any `\r`/`\n` in the input when the tool does not raise; it does not look for a log sink. Every evidence call failed at `requireActId()` (no ad account) before `name` was used. I found no `console.*` or file write that receives `name` in `createPixel`, `graphPost` or `formatFbError`. Probably not worth filing on its own.
</details>
