# Missing output encoding in `check_manipulation`: the analysed text is echoed raw, unescaped quotes included

**Repository:** `bmorphism/anti-bullshit-mcp-server` · **Tool:** `check_manipulation` · **Tested commit:** `89f5454`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`check_manipulation` scans text for manipulation patterns and returns suggested validation searches. Each suggestion pastes the full input text inside double quotes with no escaping. Markup comes back unchanged in the plain-text item, and a `"` or a newline in the text breaks out of the quotes and starts new list items. The JSON copy in the second content item is escaped correctly by `JSON.stringify`.

## Details
`src/index.ts:264-302` (tested commit):

```ts
      const validationPrompts = [
        `- Use Exa MCP server to search for factual information: "${args.text}"`,
        `- Use Brave Search for independent fact-checking: "${args.text}"`,
        `- Search ArXiv for technical analysis: "${args.text}"`,
        `- Use Google Scholar MCP server to find peer-reviewed research: "${args.text}"`,
        `- Cross-reference findings across different platforms to establish truth`
      ];
      ...
            text: `Manipulation check results:\n\n` +
                 `Detected patterns: ${detectedPatterns.join(", ") || "None"}\n\n` +
                 `Suggested validation:\n${validationPrompts.join("\n")}`
```

`args.text` is only checked to be a string (`src/index.ts:99`), then interpolated four times.

## Steps to reproduce
1. Prerequisites: Node.js 18+.
2. Install and build as the README describes: `git clone https://github.com/bmorphism/anti-bullshit-mcp-server && cd anti-bullshit-mcp-server && npm install && npm run build`
3. Call the tool with:

   ```json
   {"text": "<img src=x onerror=alert(1)>"}
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
               result = await session.call_tool("check_manipulation", {"text": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the first text item contains `- Use Exa MCP server to search for factual information: "<img src=x onerror=alert(1)>"` (and three more such lines) with the tag intact. With `{"text": "x\"\n- FAKE-LINE"}`, each echo closes the quote early and starts a new list item beginning with `- FAKE-LINE`.

## Expected behavior
The text is quoted safely, for example with `JSON.stringify(args.text)` in place of `"${args.text}"`, and markup is escaped if the output may be rendered.

## Actual behavior
The text is echoed verbatim in the plain-text item. From the fuzzing run:

```
input:  {'text': '{{{{{{'}
output: Manipulation check results:

        Detected patterns: None

        Suggested validation:
        - Use Exa MCP server to search for factual information: "{{{{{{"
        - Use Brave Search for independent fact-checking: "{{{{{{"
        ...
```

## Impact
The analysed text is typically untrusted content (an ad, a post, an email) that the user wants checked. It reaches the reply unescaped. Clients that render tool output as HTML or Markdown would display it as markup. In plain text, the breakout lets the analysed text add list items that read like the server's own suggestions to the LLM. No code execution; severity is low.

## Suggested fix
Quote the text with `JSON.stringify(args.text)` (or strip `"` and line breaks) in each `validationPrompts` template, and consider truncating long inputs in the summary. Escape `<`, `>` and `&` if rendered output is a target.

## Status on the default branch
Still present at `89f5454` (2026-01-16). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 0 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok (60 s budget).
- Evidence (verbatim, trimmed): `{'text': '{{{{{{'}`, `{'text': '====={{{{{{'}`, `{'text': '{{{{{'}`; each echoed four times into the plain-text item and, escaped, into the JSON item.
- Hand-check hints: weak. Only `{{` was reflected, into a plain-text reply; `<img>` and `FAKE-LINE` are my substitutions. Confirmed in source. Same pattern as `analyze_claim`; file both together or not at all.
</details>
