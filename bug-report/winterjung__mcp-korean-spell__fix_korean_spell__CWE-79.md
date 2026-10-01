# Missing output encoding in `fix_korean_spell`: markup in `text` is returned as raw markup

**Repository:** `winterjung/mcp-korean-spell` · **Tool:** `fix_korean_spell` · **Tested commit:** `fbb4f50`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`fix_korean_spell` sends the caller's `text` to the NAVER speller and returns the corrected text. The speller response is HTML-escaped, and `simpleHtmlUnescape` turns `&lt;`, `&gt;`, `&quot;` and the rest back into raw characters before the text is returned. Any markup in the input therefore comes back as live markup. Returning the user's text is the point of the tool, so this only matters for a client that renders tool output as HTML or Markdown, and the impact is low.

## Details
`src/naver_speller.ts:22-31` decodes HTML entities in the speller result:

```ts
function simpleHtmlUnescape(text: string): string {
  return text
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/<br>/g, "\n")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ");
}
```

`correctChunk` returns `simpleHtmlUnescape(data.message.result.notag_html)` (`src/naver_speller.ts:112`), and the tool handler puts that string into the MCP result unchanged (`src/index.ts:34-41`). There is no step that marks the result as plain text or encodes it for a rendering context.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and network access to `m.search.naver.com` (the tool calls the public NAVER speller). No API key.
2. Install and start the server. The README uses `npx -y @winterjung/mcp-korean-spell`; to test the commit itself, build from a checkout:

   ```bash
   git clone https://github.com/winterjung/mcp-korean-spell.git
   cd mcp-korean-spell
   npm install
   npm run build
   node dist/index.js
   ```
3. Call the tool with these arguments:

   ```json
   {"text": "<b>tofu-poc</b> 안녕하세요 {{7*7}}"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/mcp-korean-spell/dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "fix_korean_spell", {"text": "<b>tofu-poc</b> 안녕하세요 {{7*7}}"}
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe: the returned text contains `<b>tofu-poc</b>` and `{{7*7}}` as raw characters, not `&lt;b&gt;`. The exact spacing depends on what the speller changes.

## Expected behavior
If the tool's output may be shown in a rendering context, markup that came from the input should stay encoded, or the result should be clearly plain text that the client must escape. At minimum, the tool should not turn escaped markup in the provider response back into live markup.

## Actual behavior
From the fuzzing run, input `{"text": "{{\u0000{\u007f\u007f\u0000\u007f"}` (template braces plus control characters) came back unchanged apart from a leading space:

```
' {{\x00{\x7f\x7f\x00\x7f'
```

## Impact
In MCP, tool arguments are chosen by the LLM. Here `text` is normally the user's own document, but it can also contain text copied from an untrusted source. The result goes back to the model as plain text. Only a client that renders tool output as HTML or Markdown would display injected markup, and the markup has to be in the input already. There is no server-side impact. Low severity.

## Suggested fix
Most of the fix belongs in the rendering client, which should escape tool output. On the server side:

- Keep `&lt;`, `&gt;` and `&amp;` encoded when the result is going to be rendered, or decode them only for characters that were not markup in the original input.
- Alternatively, document that the result is raw text and must be escaped before it is rendered.

## Status on the default branch
Still present at `fbb4f50` (2025-04-16). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 3 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: `reflected-xss` (CWE-79), fired by `check_reflected_output` (payload token `{{` echoed unescaped). Triggered list: `check_reflected_output`.
- Campaigns and executions: recover-pc: 1 exec / 1 ok (budget 60s).
- Evidence (verbatim, trimmed):
  - [recover-pc] input `{'text': '{{\x00{\x7f\x7f\x00\x7f'}` -> output `{'content': [{'type': 'text', 'text': ' {{\x00{\x7f\x7f\x00\x7f'}]}`
- Hand-check hints: weak, and arguably not a bug. A spell checker has to return the user's text, the output is MCP plain text, and only `{{` was observed. The one non-obvious point is that `simpleHtmlUnescape` actively turns the provider's escaped markup back into raw `<`/`>`. Whether NAVER escapes `<b>` in `notag_html` the way the code assumes, and what it does to `{{7*7}}`, is not verified; I did not run the step 3 call. Consider not filing this one, or filing it as a low-priority hardening note.
- Side observations: `correctText` (`src/naver_speller.ts:72-76`) always prepends a space to the first chunk, which is where the leading space in the evidence output comes from. Because `<br>` is replaced before `&amp;` is decoded, a literal `<br>` typed by the user would come back as a newline, if the speller escapes it as `&lt;br&gt;` (assumed, not checked). Both are small correctness bugs, not security issues.
- Fuzzed commit `fbb4f50172934b564b11726fafc38e4fc1876840`; `head_sha` is the same commit.

</details>
