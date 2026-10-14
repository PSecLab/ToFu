# Missing output encoding in `explain_concept`: unknown `concept` values are echoed raw

**Repository:** `qpd-v/mcp-guide` · **Tool:** `explain_concept` · **Tested commit:** `82342a6`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`explain_concept` returns a canned explanation for a known MCP concept. For an unknown value it replies with a message that quotes the caller's input verbatim (only lower-cased). Markup and template syntax in `concept` come back unchanged in the tool result.

## Details
`src/index.ts:309-352` at `82342a6`:

```ts
  if (name === "explain_concept" && args) {
    const concept = (args.concept as string).toLowerCase();
    ...
    const explanation = explanations[concept];
    if (!explanation) {
      return {
        content: [{
          type: "text",
          text: `I don't have an explanation for "${concept}" yet. Available concepts: ${Object.keys(explanations).join(", ")}`
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
   {"concept": "<b>tofu-poc</b>{{7*7}}"}
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
               result = await session.call_tool("explain_concept", {"concept": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content starts with `I don't have an explanation for "<b>tofu-poc</b>{{7*7}}" yet.`

## Expected behavior
An unknown concept should produce a fixed message that lists the available concepts, or quote an escaped and length-limited copy of the input.

## Actual behavior
The input is reflected verbatim. From the fuzzing run:

```
I don't have an explanation for ""{{{{{" yet. Available concepts: tools, resources, prompts, server, client, server_types, frameworks, clients
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. An attacker who controls `concept` controls part of the result text. This only matters in clients that render tool results as HTML or Markdown, or feed them to a template engine. In plain-text clients it is cosmetic, so severity is low.

## Suggested fix
Return a fixed message for unknown concepts, for example `Unknown concept. Available concepts: ...`. If you want to keep the echo, escape `<`, `>`, `&` and quotes, strip control characters and cap the length first. Using `Object.hasOwn(explanations, concept)` for the lookup would also stop keys such as `constructor` from matching inherited properties.

## Status on the default branch
Still present at `82342a6` (2024-12-19). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 2,560 exec / 2,560 ok (60 s).
- Evidence (verbatim, trimmed): input `{'concept': '"c{{"o\x02ccc'}` -> `I don't have an explanation for ""c{{"o\x02ccc" yet. Available concepts: ...`; input `{'concept': '"{{{{{'}` -> `I don't have an explanation for ""{{{{{" yet. Available concepts: ...`.
- Hand-check hints: weak. Only `{{` (and a control byte) was reflected, into plain-text MCP content; the `<b>` reproduction is derived from the code, not from a logged run. Side note, not verified at runtime: `explanations[concept]` is a plain object lookup. After lower-casing, `toString` becomes `tostring` and misses, but `constructor` and `__proto__` match inherited properties and would put a non-string into `text` (likely an SDK validation error, not a security issue). Same pattern as the `show_example` draft for this repo; consider one combined issue.
</details>
