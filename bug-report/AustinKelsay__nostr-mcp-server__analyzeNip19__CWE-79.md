# Missing output encoding in `analyzeNip19`: the text before the first `1` is echoed raw in the error

**Repository:** `AustinKelsay/nostr-mcp-server` · **Tool:** `analyzeNip19` · **Tested commit:** `010b6dc`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`analyzeNip19` decodes a NIP-19 entity (npub, note, nevent and so on) or a hex string and describes it. If the input contains a `1` but has an unknown prefix, the `snstr` decoder throws `Unknown prefix: <prefix>`. The tool forwards that message verbatim. The prefix is everything before the first `1`, so arbitrary caller text, including markup and template syntax, comes back unescaped in the tool result.

## Details
`utils/conversion.ts:366-400` at `010b6dc`:

```ts
    // Try to decode as NIP-19
    if (cleanInput.includes('1')) {
      const decoded = decode(cleanInput as `${string}1${string}`);
      ...
  } catch (error) {
    return {
      success: false,
      message: `Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    };
  }
```

`decode` comes from `snstr` (^0.3.1). In 0.3.1 it computes `prefix = bech32Str.slice(0, bech32Str.indexOf("1"))` and throws `` new Error(`Unknown prefix: ${prefix}`) `` for anything that is not a known NIP-19 prefix. `index.ts:1387-1395` then returns `` `Analysis failed: ${result.message}` `` as text content. Nothing escapes or truncates the prefix. The message also repeats "Analysis failed:".

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. You need no keys or relays for this tool.
2. Install and start the server:
   ```
   git clone https://github.com/AustinKelsay/nostr-mcp-server.git
   cd nostr-mcp-server && git checkout 010b6dcb5aa87d268e0182554e3f9b0055e8fdab
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"input": "<b>tofu-poc</b>{{7*7}}1qqqq"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("analyzeNip19", {"input": "<b>tofu-poc</b>{{7*7}}1qqqq"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Analysis failed: Analysis failed: Unknown prefix: <b>tofu-poc</b>{{7*7}}`.

## Expected behavior
An invalid entity should produce a fixed message, for example "Input is not a valid NIP-19 entity", or one that quotes an escaped and truncated prefix.

## Actual behavior
The prefix is reflected verbatim. From the fuzzing run (input `{{10\x00110\x001`):

```
Analysis failed: Analysis failed: Unknown prefix: {{
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. For example, an injected note asks the model to "analyze" a crafted string. The result then carries caller-chosen markup. This matters only in clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients it is low severity.

## Suggested fix
In `analyzeNip19Entity`, catch decoder errors and return a fixed message. Alternatively, check the prefix against the known NIP-19 prefixes before calling `decode`. If you keep the decoder message, escape it and cap its length. Removing the duplicated "Analysis failed:" prefix would also tidy the output.

## Status on the default branch
Still present at `010b6dc` (2026-04-04). The tested commit is the head of the default branch. The README at that commit says the project is no longer maintained and points to `AustinKelsay/nostr-agent-interface`.

## Prior reports
- No related issue or PR. Searched all 3 issues and 14 pull requests (fetched 2026-10-01).
- Documentation: README.md: "This project is no longer maintained." (the default-branch head `010b6dc` redirects users to `nostr-agent-interface`, so a report here may get no response; no README or `_docs/` text covers this behaviour)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 3,584 exec / 3,584 ok (60 s).
- Evidence (verbatim, trimmed): input `{'input': '{{10\x00110\x001'}` -> `{'content': [{'type': 'text', 'text': 'Analysis failed: Analysis failed: Unknown prefix: {{'}]}`. Two more inputs of the same shape gave the same output.
- Hand-check hints: weak. The output is plain MCP text content, and the logged run only reflected `{{`. The `<b>` reproduction comes from reading `snstr` 0.3.1 (`node_modules/snstr/dist/esm/src/nip19/index.js:676-716` in the local fuzz target copy under `eval/sandbox/targets/`), not from a logged run. The repo is unmaintained and superseded. Filing there may get no response, and the successor `nostr-agent-interface` was not checked.
</details>
