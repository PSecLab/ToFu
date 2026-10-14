# Missing output encoding in `get_recommendations`: `prompt` is inserted raw into a Markdown heading

**Repository:** `openSVM/zig-mcp-server` · **Tool:** `get_recommendations` · **Tested commit:** `703cf89`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_recommendations` analyzes Zig `code` and returns a Markdown report. When `prompt` is given, it is inserted verbatim into a `##` heading of that report, outside any code fence. A newline in `prompt` ends the heading, and whatever follows is rendered as Markdown or HTML in clients that render tool output. Our fuzzer only saw `{{` echoed back, which is harmless on its own.

## Details
`src/index.ts:962-969` (tested commit), in `getRecommendations` (`src/index.ts:886-972`), called from the handler at `src/index.ts:374-383`:

```ts
    // Add context-specific recommendations based on the prompt
    if (prompt) {
      recommendations += `\n\n## 🎯 Specific Recommendations for "${prompt}":\n`;
      recommendations += this.getSpecificRecommendations(code, prompt);

      // Add advanced context-specific analysis
      recommendations += this.getAdvancedContextRecommendations(code, prompt);
    }
```

`prompt` is cast to `string | undefined` at `src/index.ts:380` with no type check, and is not escaped or stripped of newlines before it is placed in the heading.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials are needed for this tool.
2. Install and start: `git clone https://github.com/openSVM/zig-mcp-server.git && cd zig-mcp-server && npm install && npm run build`, then the server is `node build/index.js`.
3. Call the tool with:

   ```json
   {"code": "const std = @import(\"std\");", "prompt": "performance\n\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n"}
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
               result = await session.call_tool("get_recommendations", {"code": "const std = @import(\"std\");", "prompt": "performance\n\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n"})
               print(result.content[0].text)

   asyncio.run(main())
   ```
4. Observe near the end of the returned text: the heading `## 🎯 Specific Recommendations for "performance` is cut short, and `<b>TOFU-POC</b>` plus the image link follow as a separate Markdown paragraph. A Markdown renderer that loads images would request `http://127.0.0.1:9/tofu-poc.png`; this only demonstrates that the reply can trigger a request.

## Expected behavior
`prompt` is treated as plain text: newlines are removed and Markdown/HTML metacharacters are escaped (or the value is shown inside inline code) before it goes into the heading.

## Actual behavior
The value is copied verbatim into the report. The fuzzing run sent `prompt` values such as `{{{{{{{{{o` and flagged `{{` in the output. The stored output excerpt is truncated before the heading, so the echo point is taken from the code above.

## Impact
The LLM chooses `prompt`, and prompt injection can steer it. The attacker gains control over a section of Markdown in the reply: links, images (which some clients load automatically) or HTML in clients that render it. No server-side effect. Low severity.

## Suggested fix
Strip CR/LF and escape Markdown and HTML metacharacters in `prompt` before interpolation, or render it as inline code with backticks in the value escaped. Validate that `prompt` is a string, as is already done for `code`.

## Status on the default branch
Still present at `703cf89` (2025-12-23). The tested commit is the current default branch head.

## Prior reports
- #8 "Modernize to Zig 0.15.2+ patterns and fix TypeScript compilation errors" (PR, closed 2025-12-23; its merge commit is the tested head `703cf89`): fixed TypeScript errors and updated the build.zig templates, and its checklist says "Security scan completed - no vulnerabilities". It does not mention validating or escaping tool arguments, and the code at its merge still has this bug. Does not fix this.
- Documentation: CHANGELOG.md, [0.2.0] "Security": "Input Validation: Enhanced parameter validation" (a general claim; the tested head does not check `prompt`). README.md says nothing about escaping, validation or untrusted input.
- No issue reports this. The other 3 issues and 4 pull requests (fetched 2026-10-01) are version, feature and badge work; the "Security Fix" in #4 is an MCP SDK upgrade for DNS rebinding, unrelated.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only, token `{{`.
- Campaigns and executions: repo24-b 133632 / 133632, 136704 / 136704 and 151552 / 151552 exec / ok (4200 s budgets).
- Evidence (verbatim, trimmed):
  - `{'code': '"c\n\n...{{{{...[{{{ode": &/\x1d\x0b{{{{{{{{{{{{', 'prompt': '{{{{{{{{{o'}` -> `# 🔍 Comprehensive Zig Code Analysis\n\n## 📐 Style and Conventions\n**Warnings:**\n- Consider breaking long lines: 1 lines exceed 100 characters\n...` (excerpt truncated before the prompt heading).
  - `{'code': '"c\n\n\n\n\n\n\n = @\x00\x10port(\\"std\\"ance); ...{{{{{{', 'prompt': '{{{{{{{{{{{{{{{{{{{%{{{...ode": "/etc'}` -> same report shape, truncated.
- Hand-check hints: weak. Only `{{` was seen, in plain text MCP output; the stored excerpts do not show the echo itself, I located it from the code (`src/index.ts:964`). Of the four zig-mcp-server findings this is the only one where the value lands in Markdown outside a code fence, so it is the most concrete, but still low severity. The newline payload was not run. Possibly worth one combined issue for the four tools.
</details>
