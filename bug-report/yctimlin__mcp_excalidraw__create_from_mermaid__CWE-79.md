# Missing output encoding in `create_from_mermaid`: the diagram source is echoed back and forwarded to the canvas unchecked

**Repository:** `yctimlin/mcp_excalidraw` · **Tool:** `create_from_mermaid` · **Tested commit:** `713706e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`create_from_mermaid` sends a Mermaid definition to the browser canvas, which converts it with `@excalidraw/mermaid-to-excalidraw`. The server does not validate the diagram text: it broadcasts it to every connected canvas tab and echoes it back in the tool reply. The echo is JSON text in a plain-text MCP reply. Rendering happens in the browser through Mermaid, which applies its own label sanitization, so we have not shown script execution. Low severity.

## Details
`src/core/mcp-dispatch.ts:372-411` (tested commit):

```ts
case 'create_from_mermaid': {
  const params = z.object({ mermaidDiagram: z.string(), config: z.object({ ... }).optional() }).parse(args);
  ...
  const result = await sendMermaid(params.mermaidDiagram, params.config);
  return { content: [{ type: 'text',
    text: `Mermaid diagram sent for conversion!\n\n${JSON.stringify(result, null, 2)}\n\n⚠️  Note: ...` }] };
}
```

The canvas server (`src/server.ts:743-773`) only checks that `mermaidDiagram` is a non-empty string, broadcasts it over WebSocket, and returns it in the response. The browser (`frontend/src/App.tsx:524-530`) passes it to `convertMermaidToExcalidraw`, which calls `parseMermaidToExcalidraw` (`frontend/src/utils/mermaidConverter.ts:21`). There is no length limit beyond what the caller passes in `config.maxTextSize`, and the MCP side lets the caller set `maxTextSize` and `maxEdges` to any number.

## Steps to reproduce
1. Prerequisites: Node.js 18+. Open the canvas at `http://127.0.0.1:3000` in a browser so the conversion runs.
2. Start the server: `npx -y mcp-excalidraw-server` (or from source: `npm ci && npm run build && node dist/index.js`).
3. Call the tool with:

   ```json
   {"mermaidDiagram": "graph TD\n  A[\"<b>bold</b><img src=x onerror=alert(1)>\"] --> B"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "mcp-excalidraw-server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_from_mermaid", {
                   "mermaidDiagram": "graph TD\n  A[\"<b>bold</b><img src=x onerror=alert(1)>\"] --> B",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the markup echoed unchanged in the `"mermaidDiagram"` field of the reply. In the browser tab, check whether any alert fires during conversion (we expect Mermaid's default `securityLevel: 'strict'` to strip it).

## Expected behavior
The server bounds the diagram size, and does not echo raw caller markup back. Any HTML in labels is neutralized before it reaches a DOM.

## Actual behavior
The diagram text is echoed verbatim. From the fuzzing run:

```
Mermaid diagram sent for conversion!

{
  "success": true,
  "mermaidDiagram": "{ww{{www\u0011*\u0011*\u0011w\u0011*\u0011*",
  ...
  "message": "Mermaid diagram sent to frontend for conversion."
}
```

## Impact
The LLM chooses `mermaidDiagram`, and prompt injection can steer it. The echoed text goes back to the same LLM and user as JSON. The more relevant path is the browser canvas, where Mermaid parses and lays out the diagram; whether markup can execute there depends on Mermaid's sanitization, which we did not bypass. A steered call can also push large diagrams to every open canvas tab. Low severity.

## Suggested fix
- Do not echo `mermaidDiagram` in the reply; return the length and status only.
- Cap the diagram length on the server and clamp `maxTextSize`/`maxEdges` to sane maxima.
- Pass an explicit `securityLevel: 'strict'` to Mermaid in the frontend instead of relying on the default.

## Status on the default branch
Still present at `713706e` (2026-09-08). The tested commit is the current default branch head.

## Prior reports
- #74 "security: authentication, path traversal, prompt injection, and hardening fixes" (PR, open 2026-04-16): lists item H2, "Mermaid XSS via frontend", and adds a `Content-Security-Policy` header; it does not cap diagram size or stop the echo, and it is not merged (no CSP or token code in `src/server.ts` on the default branch).
- #39 "Security audit: 7 vulnerabilities (2 critical, 3 high, 2 medium)" (issue, open 2026-02-08): VULN-02 reports the wildcard `app.use(cors())` noted in passing in the internal notes; the readable part of the body (first 4000 characters) does not cover Mermaid. Still open; `cors()` is unchanged on the default branch.
- #32 "refactor: improve type safety in Mermaid integration" (PR, closed 2025-11-07): notes remaining upstream advisories in dompurify, nanoid and mermaid used by `@excalidraw/mermaid-to-excalidraw` and calls the risk acceptable; no server-side validation added.
- #104 "chore: refresh production dependencies before 2.0.0 release" (PR, closed 2026-08-19): bumps Mermaid and reports 12 remaining `npm audit` findings in Excalidraw/Mermaid transitive dependencies; not a fix for this.
- Documentation: README.md: "Mermaid conversion runs in the local browser canvas" (describes where conversion happens; no warning about untrusted diagram text).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: partly reported, not fixed. Open PR #74 (H2) names Mermaid XSS via the frontend and proposes a CSP; it is unmerged and does not cover the echo or size limits.
- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 1536 exec / 944 ok (60 s budget). Not seen in e2-0922.
- Evidence (verbatim, trimmed):
  - `{'mermaidDiagram': '{ww{{www\x11*\x11*\x11w\x11*\x11*', 'config': {...}}` -> reply echoes `"mermaidDiagram": "{ww{{www\\u0011*..."`
  - Two more variants of the same `{{` string, same result.
- Hand-check hints: weak. Only `{{` was echoed, inside JSON, in a plain-text reply. The `<img>` payload and the expected Mermaid behaviour are my reasoning, not run; I did not check which `securityLevel` `parseMermaidToExcalidraw` uses. Noticed in passing, out of scope: `src/server.ts:45` uses `cors()` with defaults (any origin), so a web page could POST to the canvas API on `127.0.0.1:3000`; worth a separate look.
</details>
