# Missing output encoding in `generateImageUrl`: the raw `prompt` is echoed back in the tool reply

**Repository:** `pinkpixel-dev/MCPollinations` · **Tool:** `generateImageUrl` · **Tested commit:** `9fd9bc1`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generateImageUrl` builds a Pollinations image URL from a prompt and returns it as JSON. The URL itself is built safely (`encodeURIComponent` for the prompt, `URLSearchParams` for options). The reply also contains the original `prompt` field unchanged. That is plain JSON text in an MCP reply, so this only matters for a client that renders tool output as HTML or Markdown. Very low severity.

## Details
`src/services/imageService.js:51-72` (tested commit):

```js
const encodedPrompt = encodeURIComponent(prompt);
const baseUrl = 'https://image.pollinations.ai';
let url = `${baseUrl}/prompt/${encodedPrompt}`;
url += `?${queryString}`;
return { imageUrl: url, prompt, width, height, model, seed, enhance, private: true, nologo: true, safe };
```

The handler (`pollinations-mcp-server.js:206-214`) returns `JSON.stringify(result, null, 2)` as the text content. JSON encoding escapes quotes and control characters but not `<` or `>`. The `generateImage` handler (`pollinations-mcp-server.js:238`) does the same with `Generated image from prompt: "${prompt}"`.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No API key is needed; the tool does not make a network request.
2. Start the server as the README describes: `npx -y @pinkpixel/mcpollinations`.
3. Call the tool with:

   ```json
   {"prompt": "<img src=x onerror=alert(1)>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "@pinkpixel/mcpollinations"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generateImageUrl",
                   {"prompt": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `imageUrl` contains the percent-encoded prompt, while the `"prompt"` field contains the markup unchanged.

## Expected behavior
Either omit the raw prompt from the reply (the caller already has it), or make sure no client renders it as markup.

## Actual behavior
The prompt is echoed as given. From the fuzzing run:

```
{
  "imageUrl": "https://image.pollinations.ai/prompt/%22pr%7B%7B%7B...%22prompt%22%3A%20%22prom?model=&seed=0&nologo=true&private=true&safe=false",
  "prompt": "\"pr{{{{{{{{{{{{{{{{{{{{{{{{{{\"prompt\": \"prom",
  ...
}
```

## Impact
The LLM chooses `prompt`, and the echo goes back to the same LLM and user. In a client that renders tool output as HTML, markup in the prompt could be injected into the chat view. In a plain-text client there is no effect, and the generated URL is correctly encoded. Very low.

## Suggested fix
Drop `prompt` from the returned object, or return it only inside the encoded URL. If the echo is kept, document that the field is untrusted text.

## Status on the default branch
Still present at `9fd9bc1` (2026-07-11). The tested commit is the current default branch head.

## Prior reports
No issue or PR reports the echoed `prompt` or missing output encoding. Searched all 0 issues and 6 pull requests (fetched 2026-10-01). Related context only:
- #6 "Update README to reflect server status and new link" (PR, merged/closed 2026-07-12): merge commit `9fd9bc1` is the tested head. It adds an archive notice to the README and points users to a successor project. Not about this bug, but it means the project is no longer maintained.
- Documentation: README.md: "This server is archived as it no longer works with Pollinations newer API." A report against this repository is unlikely to be acted on. Nothing in README.md or the other docs mentions escaping the returned `prompt`. There is no SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 3072 exec / 2872 ok (60 s); e2-0922 2048 exec / 1859 ok (300 s).
- Evidence (verbatim, trimmed):
  - `{'prompt': '"prompt{"pr`ompt"{{"prompt"prompt": "prom": "prompt", "', 'model': '', 'seed': 0.0, 'width': 0.0, 'height': 0.0, 'enhance': False, 'safe': False}` -> JSON with encoded `imageUrl` and raw `"prompt"` containing `{{`.
  - `{'prompt': '"pr{{{{{{{{{{{{{{{{{{{{{{{{{{"prompt": "prom', ...}` -> same pattern.
- Hand-check hints: weak, likely not worth filing. Only `{{` was echoed, inside JSON, in a plain-text reply; echoing the prompt is the tool's intended output and the URL is encoded correctly. The `<img>` payload is my substitution and was not run.
</details>
