# Missing output encoding in `analyze_claim`: the claim text is echoed raw, unescaped quotes included

**Repository:** `bmorphism/anti-bullshit-mcp-server` · **Tool:** `analyze_claim` · **Tested commit:** `89f5454`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`analyze_claim` builds a checklist and a list of suggested searches around the caller's claim. The claim is pasted into every line inside double quotes, with no escaping. Markup comes back unchanged, and a `"` or a newline in the claim ends the quoted part early and starts new list items. The JSON copy in the second content item is escaped correctly by `JSON.stringify`; the plain-text item is not.

## Details
`src/validation.ts:93-99` and `src/index.ts:118-158` (tested commit):

```ts
// src/validation.ts
  return requirements.map(req => `- Verify if claim "${claim}" meets requirement: ${req}`);

// src/index.ts
      const crossRefPrompts = [
        `- Use Exa MCP server to search for general information: "${args.text}"`,
        `- Use Brave Search for independent web sources: "${args.text}"`,
        ...
      ];
      return { content: [ { type: "text",
            text: `Analysis using ${framework} framework:\n\n` +
                 `Requirements:\n${suggestions.join("\n")}\n\n` + ...
                 `Suggested cross-references:\n${crossRefPrompts.join("\n")}` }, ...
```

`args.text` is only checked to be a string (`src/index.ts:99`). `framework` is safe: anything not in `VALIDATION_FRAMEWORKS` falls back to the configured default, so it is never echoed raw.

## Steps to reproduce
1. Prerequisites: Node.js 18+.
2. Install and build as the README describes: `git clone https://github.com/bmorphism/anti-bullshit-mcp-server && cd anti-bullshit-mcp-server && npm install && npm run build`
3. Call the tool with:

   ```json
   {"text": "<img src=x onerror=alert(1)>", "framework": "empirical"}
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
               result = await session.call_tool("analyze_claim", {"text": "<img src=x onerror=alert(1)>", "framework": "empirical"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the first text item contains lines like `- Verify if claim "<img src=x onerror=alert(1)>" meets requirement: Verifiable evidence from multiple sources`, with the tag intact. With `{"text": "x\"\n- FAKE-LINE"}`, every echo closes the quote early and starts a new list item that begins with `- FAKE-LINE`.

## Expected behavior
The claim is quoted safely: inner quotes and line breaks are escaped (for example by using `JSON.stringify(args.text)` in place of `"${args.text}"`), and markup is escaped if the output may be rendered.

## Actual behavior
The claim is echoed verbatim, and its quotes break the quoting. From the fuzzing run:

```
input:  {'text': '"texXt": "________", "framework": "reo{{ssible', 'framework': 'reo{{ssible'}
output: Analysis using pluralistic framework:
        Requirements:
        - Verify if claim ""texXt": "________", "framework": "reo{{ssible" meets requirement: Consider multiple ways of knowing ...
        ...
        - Use Exa MCP server to search for general information: ""texXt": "________", "framework": "reo{{ssible"
```

## Impact
The claim usually comes from content the user wants checked, such as a web page or a message, which is untrusted by nature. That text reaches the reply unescaped. In a client that renders tool output as HTML or Markdown it is displayed as markup. In plain text, the quote and newline breakout lets the claim add list items that look like the server's own suggested steps, which the LLM may follow. Neither gives code execution; severity is low.

## Suggested fix
Quote the claim with `JSON.stringify(claim)` (or strip `"` and line breaks) in `getValidationSuggestions` and in every `crossRefPrompts` template, and cap its length in the plain-text summary. Escape `<`, `>` and `&` as well if the output is meant for rendered views.

## Status on the default branch
Still present at `89f5454` (2026-01-16). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 0 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch. #1 "Fix TypeScript errors in validation.ts" (PR, open 2025-01-15) touches `validateClaim` in the same file but only adds `claim` to its return object; it does not change the quoting in `getValidationSuggestions` or `crossRefPrompts`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2513 ok (60 s budget).
- Evidence (verbatim, trimmed): three calls with `text` values `'"texXt": "________", "framework": "reo{{ssible'`, `'"texXt": "________", "framework": "reo{{s{{ble'`, `'"texXt":exXt": "________", "framework": "reo{{'`; each echoed into every `Verify if claim "..."` and cross-reference line (see "Actual behavior").
- Hand-check hints: weak. The echo is real and confirmed in source, but only `{{` and quotes were reflected into a plain-text MCP reply; the `<img>` and `FAKE-LINE` payloads are my substitutions. Echoing the claim is the point of the tool, so the only defensible request is proper quoting. Consider filing together with `check_manipulation` (same pattern).
</details>
