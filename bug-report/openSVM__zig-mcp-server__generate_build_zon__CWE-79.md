# Missing output encoding in `generate_build_zon`: dependency `name` and `url` are pasted raw into the generated `build.zig.zon` and its Markdown fence

**Repository:** `openSVM/zig-mcp-server` · **Tool:** `generate_build_zon` · **Tested commit:** `703cf89`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generate_build_zon` returns a Markdown reply with a generated `build.zig.zon` inside a `zig` code fence. Each dependency's `name` is inserted as a bare ZON field name and its `url` inside a string literal, with no validation or escaping. A quote in `url` ends the string literal, a newline in `name` adds arbitrary lines to the file, and three backticks close the code fence so the rest renders as Markdown or HTML in clients that render tool output. Our fuzzer only saw `{{` echoed back, which is harmless on its own.

## Details
`src/zig-build.ts:107-121` (tested commit), called from `src/index.ts:1225-1238`:

```ts
static generateBuildZon(dependencies: ZigModuleDependency[]): string {
  return `.{
    .name = "my-project",
    .version = "0.1.0",
    .minimum_zig_version = "0.15.2",

    .dependencies = .{
${dependencies
  .map(
    dep => `        .${dep.name} = .{
            .url = "${dep.url || `https://github.com/example/${dep.name}`}",
            .hash = "1220000000000000000000000000000000000000000000000000000000000000",
        },`
  )
  .join('\n')}
```

`src/index.ts:1229` only checks that `dependencies` is an array. Nothing checks that `name` is a valid identifier or that `name` and `url` contain no newlines, quotes or backticks. The output goes into a Markdown fence at `src/index.ts:1236-1238`. Separately, `projectName` is read into `_projectName` (`src/index.ts:1228`) and never used, so the file always says `my-project`.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials are needed for this tool.
2. Install and start: `git clone https://github.com/openSVM/zig-mcp-server.git && cd zig-mcp-server && npm install && npm run build`, then the server is `node build/index.js`.
3. Call the tool with:

   ```json
   {"projectName": "demo", "dependencies": [{"name": "tofu\n```\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n```zig\n", "url": "https://example.com/a.tar.gz\", .injected = \"1"}]}
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
               result = await session.call_tool("generate_build_zon", {"projectName": "demo", "dependencies": [{"name": "tofu\n```\n<b>TOFU-POC</b> ![tofu-poc](http://127.0.0.1:9/tofu-poc.png)\n```zig\n", "url": "https://example.com/a.tar.gz\", .injected = \"1"}]})
               print(result.content[0].text)

   asyncio.run(main())
   ```
4. Observe in the returned text: the `zig` fence closes inside the `.dependencies` block, `<b>TOFU-POC</b>` and the image link sit outside any code block, and the `.url` line reads `.url = "https://example.com/a.tar.gz", .injected = "1",` (an extra field). A Markdown renderer that loads images would request `http://127.0.0.1:9/tofu-poc.png`; this only demonstrates that the reply can trigger a request.

## Expected behavior
Dependency names are checked against a Zig identifier pattern, URLs are parsed and checked, and invalid values are rejected. String values are escaped for ZON string literals. User text never ends up outside the code fence.

## Actual behavior
Values are copied verbatim. From the fuzzing run (trimmed):

```
    .dependencies = .{
        .{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ = .{
            .url = "https://github.com/example/{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
```

## Impact
The LLM chooses the arguments, and prompt injection can steer it. The generated `build.zig.zon` controls which packages `zig build --fetch` downloads, so injected fields or URLs in a file the user saves without reading could change what gets fetched. In clients that render tool output as Markdown, the fence break allows links, images or HTML in the reply. The user sees the output before using it, so this is low severity.

## Suggested fix
Validate `name` with an identifier pattern (for example `^[A-Za-z_][A-Za-z0-9_]*$`) and `url` with `new URL()` plus an allowed scheme list, and reject anything else. Escape `"` and `\` in values placed inside ZON string literals. Build the Markdown fence with more backticks than the longest backtick run in the content. Use `projectName` for `.name`, or drop it from the schema.

## Status on the default branch
Still present at `703cf89` (2025-12-23). The tested commit is the current default branch head.

## Prior reports
- #8 "Modernize to Zig 0.15.2+ patterns and fix TypeScript compilation errors" (PR, closed 2025-12-23; its merge commit is the tested head `703cf89`): fixed TypeScript errors and updated the build.zig templates, and its checklist says "Security scan completed - no vulnerabilities". It does not mention validating or escaping tool arguments, and the code at its merge still has this bug. Does not fix this.
- Documentation: CHANGELOG.md, [0.2.0] "Security": "Input Validation: Enhanced parameter validation" (a general claim; the tested head does not check dependency `name` or `url`). README.md says nothing about escaping, validation or untrusted input.
- No issue reports this. The other 3 issues and 4 pull requests (fetched 2026-10-01) are version, feature and badge work; the "Security Fix" in #4 is an MCP SDK upgrade for DNS rebinding, unrelated.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only, token `{{`.
- Campaigns and executions: repo24-b 259072 exec / 259072 ok (4200 s budget).
- Evidence (verbatim, trimmed):
  - `{'projectName': '{{{{...', 'dependencies': [{'name': '{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{', 'url': ''}, {'name': '', 'url': ''}, ...]}` -> `.{{{{...{{ = .{\n            .url = "https://github.com/example/{{{{...{{",` (note `.name = "my-project"` despite `projectName`).
  - `{'projectName': 'jbbbb...{{{{', 'dependencies': [{'name': '{{{{{{!\x00\x00\x00\x00\x00\x00\x00{{{{...', 'url': ''}, ...]}` -> NUL bytes echoed raw into the ZON identifier and URL.
- Hand-check hints: weak. Only `{{` was echoed, inside a Markdown code fence, in plain text MCP output; echoing input into generated config is the tool's purpose. The quote, newline and fence-break payloads in this draft come from reading the code and were not run. Possibly worth one combined low-severity issue for the four zig-mcp-server tools rather than four.
</details>
