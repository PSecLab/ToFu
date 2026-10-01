# Missing output encoding in `storeDecision`: `title` is echoed back unescaped in the JSON result (and logged raw)

**Repository:** `aurda012/cursor10x-mcp` · **Tool:** `storeDecision` · **Tested commit:** `0fc2ad7`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`storeDecision` saves a project decision to long-term memory and returns `{"status":"ok","title":...,"timestamp":...}`. The caller's `title` is copied into that result. It is JSON-encoded, but markup is not escaped, so `<b>` or `<script>` in a title comes back unchanged. The same title is also written raw to the server log with `console.error`, so CR/LF in it can forge log lines. Both issues are low impact.

## Details
`index.js:2617-2622`:

```js
            log(`Stored decision: "${title}" with importance: ${importance}`);

            return {
              content: [{ type: "text", text: JSON.stringify({ status: 'ok', title, timestamp: now }) }],
              isError: false
            };
```

`title` comes straight from the arguments (`index.js:2582`). The schema only requires a string (`index.js:1158-1161`). `JSON.stringify` escapes quotes and control characters but leaves `<`, `>` and `&` as they are. `log()` (`index.js:661-665`) writes the message to stderr with `console.error`, so `title` and `importance` reach the log with any CR/LF intact. Stored titles are also returned later by the context-retrieval tools. I did not trace those outputs.

## Steps to reproduce
1. Prerequisites: Node.js. `TURSO_DATABASE_URL` / `TURSO_AUTH_TOKEN` are optional. Without them the server falls back to an in-memory store (`index.js:1361-1364`).
2. Start the server as the README describes: `npx -y cursor10x-mcp`. To test the tested commit, run `npm install` in a checkout at `0fc2ad7`, then `node index.js`. In that case the checked-in `.env` points the server at a local SQLite file.
3. Call the tool:

   ```json
   {"title": "<b>tofu-poc</b>", "content": "c"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "cursor10x-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("storeDecision", {"title": "<b>tofu-poc</b>", "content": "c"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is `{"status":"ok","title":"<b>tofu-poc</b>","timestamp":<n>}`, with the markup unchanged.

## Expected behavior
If the title is echoed at all, `<`, `>` and `&` are escaped (or the field is left out), and the log line neutralizes CR/LF.

## Actual behavior
The title is echoed inside the JSON string with markup intact. From the fuzzing run (title shortened):

```
{"status":"ok","title":"\"title\": \"Prototype Pollution\", [...] \"metadata\": {\"__proto__\": {{","timestamp":1790453215759}
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content can steer them. The result is a JSON string in a plain-text MCP item. It matters only if a client renders tool output as HTML. Whoever controls the title can already write it into memory, so the reflected copy adds little. Low severity.

## Suggested fix
- Return only `status` and an ID or timestamp, or escape `<`, `>` and `&` in `title` before echoing it.
- Log untrusted values with `JSON.stringify(title)`, or strip `\r` and `\n`, so a title cannot start a new log line.

## Status on the default branch
Still present at `0fc2ad7` (2025-05-07). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 7 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on `{{`. `check_invalid_json` and `check_log_injection` also fired for this tool.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2555 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'title': '"title": "Prototype Pollution", "content": "Testing prototype pollution", "reasoning": "ance": "medium", "metadata": {"__proto__": {{', 'content': '', 'reasoning': '', 'importance': '', 'metadata': {}}`
  - output `{'content': [{'type': 'text', 'text': '{"status":"ok","title":"\\"title\\": \\"Prototype Pollution\\", [...] \\"metadata\\": {\\"__proto__\\": {{","timestamp":1790453215759}'}], 'isError': False}`
- Hand-check hints: **weak**. Only `{{` was echoed, inside a correctly JSON-encoded string, in plain-text MCP output. The "prototype pollution" content of the payload is just text: `metadata` was `{}` and the title is a string, so nothing was polluted. The raw `log()` at `index.js:2617` is a real but low-severity CWE-117 issue (same pattern as the `storeMilestone` draft). Consider merging the two.
- Side note: the repo checks in `.env` (no secrets in it, only a local `file:` DB URL and settings) and a packaged `cursor10x-mcp-1.0.0.tgz`.
</details>
