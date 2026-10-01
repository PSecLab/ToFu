# Missing output encoding in `optimize_code`: `code` can close the Markdown code fence in the reply

**Repository:** `openSVM/zig-mcp-server` · **Tool:** `optimize_code` · **Tested commit:** `703cf89`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`optimize_code` returns a Markdown report that ends with the caller's `code` inside a `zig` code fence under "Optimized Code Suggestions". The code is inserted as is. If it contains a line of three backticks, the fence closes early and the rest of the input renders as Markdown or HTML in clients that render tool output. Our fuzzer only saw `{{` echoed back inside the fence, which is harmless on its own.

## Details
`src/index.ts:604-607` and `src/index.ts:611-628` (tested commit):

```ts
## Optimized Code Suggestions:
\`\`\`zig
${this.generateOptimizedCodeSuggestions(code, level)}
\`\`\`
    `.trim();
  }

  private generateOptimizedCodeSuggestions(code: string, level: OptimizationLevel): string {
    let optimizedCode = code;
    ...
    return optimizedCode;
  }
```

`generateOptimizedCodeSuggestions` returns the input with at most one regex replacement and an optional comment prefix. The handler at `src/index.ts:338-350` only checks that `code` is a string. The fence is always exactly three backticks, so any backtick run of three or more in `code` ends it.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials are needed for this tool.
2. Install and start: `git clone https://github.com/openSVM/zig-mcp-server.git && cd zig-mcp-server && npm install && npm run build`, then the server is `node build/index.js`.
3. Call the tool with:

   ```json
   {"code": "const a = 1;\n```\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n```zig", "optimizationLevel": "ReleaseSafe"}
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
               result = await session.call_tool("optimize_code", {"code": "const a = 1;\n```\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n```zig", "optimizationLevel": "ReleaseSafe"})
               print(result.content[0].text)

   asyncio.run(main())
   ```
4. Observe at the end of the returned text: the `zig` fence closes after `const a = 1;`, and `<b>TOFU-POC</b>` plus the image link sit outside any code block. A Markdown renderer that loads images would request `http://127.0.0.1:9/tofu-poc.png`; this only demonstrates that the reply can trigger a request.

## Expected behavior
The code is shown verbatim inside a fence that the code cannot close, for example a fence with more backticks than the longest backtick run in `code`, or a `~~~` fence when the code contains backticks.

## Actual behavior
The code is pasted into a fixed three-backtick fence. From the fuzzing run:

```
## Optimized Code Suggestions:
~~~zig
const std = @import("std"); pub fn main() void {{ unreachable; }
~~~
```

(shown here with `~~~` so this report renders; the tool emits three backticks).

## Impact
The LLM chooses `code`, and prompt injection (for example code copied from an untrusted web page) can steer it. The attacker gains control over Markdown after the fence: links, images (which some clients load automatically) or HTML in clients that render it. No server-side effect. Low severity.

## Suggested fix
Compute the fence length from the content (one backtick more than the longest run of backticks in `code`, minimum three) before wrapping it. Apply the same helper to the other tools that wrap caller text in fences (`generate_build_zig`, `generate_build_zon`).

## Status on the default branch
Still present at `703cf89` (2025-12-23). The tested commit is the current default branch head.

## Prior reports
- #8 "Modernize to Zig 0.15.2+ patterns and fix TypeScript compilation errors" (PR, closed 2025-12-23; its merge commit is the tested head `703cf89`): fixed TypeScript errors and updated the build.zig templates, and its checklist says "Security scan completed - no vulnerabilities". It does not mention validating or escaping tool arguments, and the code at its merge still has this bug. Does not fix this.
- Documentation: CHANGELOG.md, [0.2.0] "Security": "Input Validation: Enhanced parameter validation" (a general claim; the tested head does not check backtick runs in `code`). README.md says nothing about escaping, validation or untrusted input.
- No issue reports this. The other 3 issues and 4 pull requests (fetched 2026-10-01) are version, feature and badge work; the "Security Fix" in #4 is an MCP SDK upgrade for DNS rebinding, unrelated.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only, token `{{`.
- Campaigns and executions: corpus-sbx 3072 exec / 2897 ok (60 s); repo24-b 263168 exec / 256273 ok (4200 s).
- Evidence (verbatim, trimmed):
  - `{'code': 'const std = @import("std"); pub fn main() void {{ unreachable; }', 'optimizationLevel': 'ReleaseSmall'}` -> `## Optimized Code Suggestions:` followed by the input code verbatim inside a three-backtick `zig` fence.
  - `{'code': '"co\x7f...de": "const std = @import(\\"std\\"); pub fn main() void {{ unreachable; }", "optimizationLev\x1b\x13]E_]-\x1fleaseSmall', 'optimizationLevel': 'Debug'}` -> code echoed verbatim inside the fence, including `\x1b` and other control bytes.
- Hand-check hints: weak. The tool's purpose is to echo the code back; `{{` inside a code fence in plain text is harmless. Only the fence break (from reading the code, not run) is a real, low-severity output-encoding gap. Side note: `src/index.ts:616-619` replaces with `'std.ArrayList($1)...'` using a regex with no capture group, so a literal `$1` is inserted (functional bug). Possibly worth one combined issue for the four tools.
</details>
