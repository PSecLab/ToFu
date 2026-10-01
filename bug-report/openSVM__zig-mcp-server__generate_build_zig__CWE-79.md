# Missing output encoding in `generate_build_zig`: `zigVersion` and `dependencies` are pasted raw into the generated `build.zig` and its Markdown fence

**Repository:** `openSVM/zig-mcp-server` · **Tool:** `generate_build_zig` · **Tested commit:** `703cf89`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generate_build_zig` returns a Markdown reply with a generated `build.zig` inside a `zig` code fence. The caller's `zigVersion` and each `dependencies` entry are interpolated into the Zig source and the Markdown with no validation or escaping. A newline in `zigVersion` ends the `//!` comment and adds arbitrary lines to the generated build script, and a run of three backticks closes the code fence so the rest of the value renders as Markdown or HTML in clients that render tool output. Our fuzzer only saw `{{` echoed back, which is harmless on its own.

## Details
`src/index.ts:1106-1118` and `src/zig-build.ts:31-32` (tested commit):

```ts
// src/index.ts:1106-1118
const config: Partial<ZigBuildConfig> = {
  zigVersion: args.zigVersion || '0.15.2',
  buildMode: args.optimizationLevel || 'ReleaseSafe',
  dependencies: {},
  buildSteps: [],
};
if (Array.isArray(args.dependencies)) {
  for (const dep of args.dependencies) {
    config.dependencies![dep] = `dependency("${dep}")`;
  }
}
// src/zig-build.ts:31-32
    return `//! Build script for Zig project
//! Zig version: ${zigVersion} or later
```

Each dependency name is also used as a Zig identifier and string literal at `src/zig-build.ts:59-63` (`const ${name}_dep = b.dependency("${name}", ...)`). The result is wrapped in a Markdown fence at `src/index.ts:1122-1127`. Nothing checks that `zigVersion` looks like a version, that dependency names are valid identifiers, or that the values contain no newlines, quotes or backticks.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials are needed for this tool.
2. Install and start: `git clone https://github.com/openSVM/zig-mcp-server.git && cd zig-mcp-server && npm install && npm run build`, then the server is `node build/index.js`.
3. Call the tool with:

   ```json
   {"projectType": "executable", "zigVersion": "0.15.2\nconst tofu_poc = 1;\n```\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n```zig", "dependencies": []}
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
               result = await session.call_tool("generate_build_zig", {"projectType": "executable", "zigVersion": "0.15.2\nconst tofu_poc = 1;\n```\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n```zig", "dependencies": []})
               print(result.content[0].text)

   asyncio.run(main())
   ```
4. Observe in the returned text: `const tofu_poc = 1;` appears as a code line of the generated `build.zig` (outside the `//!` comment), the `zig` fence is closed right after it, and `<b>TOFU-POC</b>` plus the image link sit outside any code block. A Markdown renderer that loads images would request `http://127.0.0.1:9/tofu-poc.png`; this only demonstrates that the reply can trigger a request.

## Expected behavior
`zigVersion` is checked against a version pattern (for example `^\d+\.\d+\.\d+(-[0-9A-Za-z.+-]+)?$`), dependency names are checked against a Zig identifier pattern, and invalid values are rejected. User text never ends up outside the code fence.

## Actual behavior
The value is copied verbatim. From the fuzzing run (control characters shown as escapes, trimmed):

````
# Generated build.zig

```zig
//! Build script for Zig project
//! Zig version: \x19\x19...\x19{{\x7f\x7f\x00 or later
//! Modern build system with enhanced module support
````

## Impact
The LLM chooses the arguments, and prompt injection can steer it. The generated `build.zig` is meant to be saved and run with `zig build`, and `build.zig` is executable code, so a user who copies the output without reading it would run any injected lines at build time. In clients that render tool output as Markdown, the fence break allows links, images or HTML in the reply. The user sees the output before using it, so this is low severity.

## Suggested fix
Validate `zigVersion` and dependency names with strict patterns and reject anything else. If free text must be shown, escape it for the target context (Zig string literal escaping inside quotes, no newlines in comments), and build the Markdown fence with more backticks than the longest backtick run in the content.

## Status on the default branch
Still present at `703cf89` (2025-12-23). The tested commit is the current default branch head.

## Prior reports
- #8 "Modernize to Zig 0.15.2+ patterns and fix TypeScript compilation errors" (PR, closed 2025-12-23; its merge commit is the tested head `703cf89`): fixed TypeScript errors and updated the build.zig templates, and its checklist says "Security scan completed - no vulnerabilities". It does not mention validating or escaping tool arguments, and the code at its merge still has this bug. Does not fix this.
- Documentation: CHANGELOG.md, [0.2.0] "Security": "Input Validation: Enhanced parameter validation" (a general claim; the tested head does not check `zigVersion` or dependency names). README.md says nothing about escaping, validation or untrusted input.
- No issue reports this. The other 3 issues and 4 pull requests (fetched 2026-10-01) are version, feature and badge work; the "Security Fix" in #4 is an MCP SDK upgrade for DNS rebinding, unrelated.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only, token `{{`.
- Campaigns and executions: repo24-b 244224 exec / 244224 ok and 265728 exec / 265728 ok (4200 s budgets).
- Evidence (verbatim, trimmed):
  - `{'projectName': '', 'projectType': 'library', 'zigVersion': '\x19...\x19{{\x7f\x7f\x00', 'dependencies': []}` -> `# Generated build.zig\n\n```zig\n//! Build script for Zig project\n//! Zig version: \x19...\x19{{\x7f\x7f\x00 or later\n...`
  - `{'projectName': '\x19...', 'projectType': 'executable', 'zigVersion': '\x19...\x19{{\x7f\x7f', 'dependencies': []}` -> same shape.
- Hand-check hints: weak. Only `{{` was echoed, inside a Zig comment inside a Markdown code fence, in plain text MCP output. Echoing input into generated code is what this tool is for. The newline and fence-break payloads in this draft come from reading the code and were not run. `projectName` and `projectType` are ignored by `generateBuildZig` (exe name is always `main`), a functional bug. Possibly worth one combined low-severity issue for the four zig-mcp-server tools rather than four.
</details>
