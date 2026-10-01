# Missing output encoding in `format_transcript`: transcript text, including markup and `{{`, is returned unescaped (low impact)

**Repository:** `MushroomFleet/TranscriptionTools-MCP` · **Tool:** `format_transcript` · **Tested commit:** `a51881a`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`format_transcript` takes a timestamped transcript, joins its segments into paragraphs and returns the text. The text is returned as given, apart from whitespace changes. HTML tags, Markdown or template syntax in the transcript therefore appear unchanged in the tool result. The result is MCP `text` content. This only matters if a client renders tool output as HTML or Markdown without escaping it.

## Details
`src/tools/formatting.ts:28-31` reads the input (direct text, or a file when `is_file_path` is true) and splits it into lines. Lines `37-62` strip the `[HH:MM:SS]` prefix and keep the rest of each line verbatim. Lines `68-111` concatenate the segments:

```ts
const textContent = await FileHandler.resolveTextContent(input_text, is_file_path);
const lines = textContent.trim().split('\n');
...
const match = line.match(/\[(\d{2}):(\d{2}):(\d{2})\]\s*(.*)/);
...
return { formatted_text: formattedText };
```

`src/index.ts:185-197` returns `formatResult.formatted_text` directly as `{ type: 'text', text: ... }`. No step escapes HTML-significant characters.

## Steps to reproduce
1. Prerequisites: Node.js 18+.
2. Install and build as the README describes:
   ```bash
   git clone https://github.com/mushroomfleet/TranscriptionTools-MCP
   cd TranscriptionTools-MCP && npm install && npm run build
   ```
   The server is `node build/index.js`.
3. Call the tool:
   ```json
   {"input_text": "[00:00:01] <b>tofu-poc</b> {{7*7}}", "is_file_path": false}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["/path/to/TranscriptionTools-MCP/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("format_transcript", {
                   "input_text": "[00:00:01] <b>tofu-poc</b> {{7*7}}",
                   "is_file_path": False,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the result text is `<b>tofu-poc</b> {{7*7}}`, with the markup and braces unchanged.

## Expected behavior
If tool output may be shown in a rendering client, the server escapes HTML-significant characters (`<`, `>`, `&`, quotes) or documents that it returns raw text and that clients must escape it. Returning the transcript text unchanged is reasonable for a plain-text formatter. Escaping is mostly the renderer's job.

## Actual behavior
Input is echoed verbatim. From the fuzzing run:

```
input_text: '"in{{""1i'            -> text: '"in{{""1i'
input_text: 'u\n{{{{{{{{...{{\x07' -> text: 'u {{{{{{{{...{{\x07'
```

ToFu's only payload token seen in the output was `{{`. No HTML or script markup was observed in the evidence.

## Impact
`input_text` is chosen by the LLM, often from an untrusted transcript or document. A client that renders tool results as HTML or Markdown without sanitizing them could display attacker-controlled markup. MCP clients usually show tool text as plain text, and this tool's purpose is to return the transcript text, so the impact is low.

## Suggested fix
- Document that `format_transcript` returns raw text, so clients treat it as untrusted.
- If an HTML or Markdown rendering is needed, add an opt-in output mode that escapes `<`, `>`, `&` and quotes, and strip control characters such as `\x00` and `\x07` from the formatted text.

## Status on the default branch
Still present at `a51881a` (2026-04-07). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 0 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 3072 exec / 2668 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'input_text': '"in{{""1i', 'is_file_path': False, 'paragraph_gap': 0.0, 'line_gap': 0.0}` -> `'"in{{""1i'`
  - `{'input_text': 'u\n{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{\x07', ...}` -> `'u {{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{\x07'`
  - `{'input_text': 'u\n{{{{...{{\x07{\x01\x00\x00\x00u\n\x00\x07r', ...}` -> `'u {{{{...{{\x07{\x01\x00\x00\x00u \x00\x07r'`
- Hand-check hints: weak. Only `{{` was echoed, into plain-text MCP content, by a tool whose job is to return the input text. There is no rendering context in this server. I recommend not filing as XSS. A more notable issue, outside ToFu's flagged class: with `is_file_path: true`, `input_text` goes to `FileHandler.readTextFile` (`src/utils/file-handler.ts:18-24`, via `resolveTextContent` at `:48-53`) with no path containment. The file's contents come back in the result (lines without timestamps are kept as text), so any file the server user can read is returned to the caller. That is a CWE-22 / arbitrary file read candidate worth checking separately; the same pattern likely applies to `repair_text` and `summary_text`, which also take `is_file_path`. Not verified by running. The reproduction above was derived from the code and has not been run.
</details>
