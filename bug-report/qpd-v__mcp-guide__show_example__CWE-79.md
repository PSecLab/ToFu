# Missing output encoding in `show_example`: unknown `feature` values are echoed raw

**Repository:** `qpd-v/mcp-guide` · **Tool:** `show_example` · **Tested commit:** `82342a6`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`show_example` returns a canned code example for a known MCP feature. For an unknown value it replies with a message that quotes the caller's input verbatim (only lower-cased). Markup and template syntax in `feature` come back unchanged in the tool result.

## Details
`src/index.ts:363-429` at `82342a6`:

```ts
  if (name === "show_example" && args) {
    const feature = (args.feature as string).toLowerCase();
    ...
    const example = examples[feature];
    if (!example) {
      return {
        content: [{
          type: "text",
          text: `I don't have an example for "${feature}" yet. Available examples: ${Object.keys(examples).join(", ")}`
        }]
      };
    }
```

`toLowerCase()` does not neutralize markup, and nothing escapes or truncates the value before it is placed in the result.

## Steps to reproduce
1. Prerequisites: Node.js 16 or later. No accounts or keys.
2. Install and start the server:
   ```
   git clone https://github.com/qpd-v/mcp-guide.git
   cd mcp-guide && git checkout 82342a6e4454d3436f9afc33ae0d1b0cdbf5313e
   npm install && npm run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"feature": "<b>tofu-poc</b>${7*7}"}
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
               result = await session.call_tool("show_example", {"feature": "<b>tofu-poc</b>${7*7}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content starts with `I don't have an example for "<b>tofu-poc</b>${7*7}" yet.`

## Expected behavior
An unknown feature should produce a fixed message that lists the available examples, or quote an escaped and length-limited copy of the input.

## Actual behavior
The input is reflected verbatim, apart from lower-casing. From the fuzzing run:

```
I don't have an example for ""ull"${"" yet. Available examples: tool_call, resource_read, prompt_template
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. An attacker who controls `feature` controls part of the result text. This only matters in clients that render tool results as HTML or Markdown, or feed them to a template engine. In plain-text clients it is cosmetic, so severity is low.

## Suggested fix
Return a fixed message for unknown features, for example `Unknown feature. Available examples: ...`. If you want to keep the echo, escape `<`, `>`, `&` and quotes, strip control characters and cap the length first. `Object.hasOwn(examples, feature)` would also avoid matching inherited keys such as `constructor`.

## Status on the default branch
Still present at `82342a6` (2024-12-19). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 2,560 exec / 2,560 ok (60 s).
- Evidence (verbatim, trimmed): input `{'feature': '"ulL"${"'}` -> `I don't have an example for ""ull"${"" yet. Available examples: tool_call, resource_read, prompt_template`; input `{'feature': '"u$L"${"'}` -> `I don't have an example for ""u$l"${"" yet. ...`.
- Hand-check hints: weak. Only `${` was reflected, into plain-text MCP content. The result is a string built at runtime, so `${` in the input is not evaluated by the JS template literal; it is inert text. The `<b>` reproduction is derived from the code, not from a logged run. Same pattern as the `explain_concept` draft for this repo; consider one combined issue.
</details>
