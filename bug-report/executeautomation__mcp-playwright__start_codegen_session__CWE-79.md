# Missing output encoding in `start_codegen_session`: `outputPath` is echoed unescaped and used for `mkdir` without validation

**Repository:** `executeautomation/mcp-playwright` · **Tool:** `start_codegen_session` · **Tested commit:** `2349c28`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`start_codegen_session` starts recording Playwright actions and returns the session options plus a message naming the output directory. `options.outputPath` is a free string. It is echoed back twice in the result with no escaping, so markup and template syntax in it come back as they were sent. The same unvalidated value is passed to `fs.mkdir(..., { recursive: true })`, so the call also creates that directory on disk.

## Details
`src/tools/codegen/index.ts:45-75` at `2349c28`:

```ts
      const mergedOptions = { ...DEFAULT_OPTIONS, ...options };
      const workspaceRoot = getWorkspaceRoot();
      const outputPath = path.isAbsolute(mergedOptions.outputPath)
        ? mergedOptions.outputPath
        : path.join(workspaceRoot, mergedOptions.outputPath);
      mergedOptions.outputPath = outputPath;
      try {
        await fs.mkdir(outputPath, { recursive: true });
      ...
      return {
        sessionId,
        options: mergedOptions,
        message: `Started codegen session. Tests will be generated in: ${outputPath}`
      };
```

`handleCodegenResult` (`src/toolHandler.ts:696-705`) returns `JSON.stringify(result)` as text. JSON encoding escapes quotes but leaves `<`, `>` and `{{` intact. `outputPath` is not checked for allowed characters, and it is not confined to the workspace: an absolute path or a `../` relative path is accepted. `end_codegen_session` later writes the generated test file into that directory (`index.ts:108-117`).

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No browser is needed for this call. Create a scratch directory first: `mkdir -p /tmp/tofu-poc`.
2. Install and start the server:
   ```
   git clone https://github.com/executeautomation/mcp-playwright.git
   cd mcp-playwright && git checkout 2349c2891e7c499c8c07b7d78c7f3fb4c797a1da
   npm install && npm run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"options": {"outputPath": "/tmp/tofu-poc/<b>tofu-poc{{7*7}}", "testNamePrefix": "", "includeComments": false}}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {"options": {"outputPath": "/tmp/tofu-poc/<b>tofu-poc{{7*7}}", "testNamePrefix": "", "includeComments": False}}

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("start_codegen_session", ARGS)
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content contains `"outputPath":"/tmp/tofu-poc/<b>tofu-poc{{7*7}}"` and `Tests will be generated in: /tmp/tofu-poc/<b>tofu-poc{{7*7}}`. `ls /tmp/tofu-poc` shows a new directory named `<b>tofu-poc{{7*7}}`.

## Expected behavior
`outputPath` should be validated: resolved, kept inside the workspace or a configured output root, and limited to sensible path characters. Values echoed back should be escaped for the context in which a client may render them.

## Actual behavior
The value is echoed verbatim and the directory is created. From the fuzzing run (trimmed, path anonymised):

```
{"sessionId":"6abf1b5e-...","options":{"outputPath":"<server cwd>/\"options\": {{\"options\": {\"ou\\..\\\\..\\\\.indows\\\\w\"in.iniout\", ", ...},
 "message":"Started codegen session. Tests will be generated in: <server cwd>/\"options\": {{\"options\": ..."}
```

The call returned `isError: false`, so `fs.mkdir` created a directory with that name inside the server's working directory.

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. The reflected markup matters only in clients that render tool results as HTML or Markdown, which makes it low severity on its own. The unvalidated `mkdir` is more practical: a steered call can create directories anywhere the server user can write, and `end_codegen_session` then writes a test file there.

## Suggested fix
- Resolve `outputPath` with `path.resolve(workspaceRoot, outputPath)` and reject it if `path.relative(workspaceRoot, resolved)` starts with `..` or is absolute, or check it against a configurable output root.
- Reject control characters and other unusual characters in the path.
- When echoing the path, escape it or return it only as a JSON field rather than also inside a free-text message.

## Status on the default branch
Still present at `2349c28` (2025-12-13). The tested commit is the head of the default branch.

## Prior reports
- #167 "`start_codegen_session` fails to launch GUI silently while `playwright_navigate` succeeds in a WSL environment" (issue, open 2025-08-20): a functional bug report that notes in passing that the call "created an empty directory at the outputPath". Same `fs.mkdir` behaviour, but it does not raise validation, containment or escaping. Not fixed.
- #208 "fix(security): add SSRF protection with URL validation for API and navigation tools" (PR, open 2026-03-20): its "Additional vulnerabilities" list names path traversal in `screenshot.ts` and `output.ts` and code injection in `codegen/generator.ts`, but not `outputPath` in `codegen/index.ts`. Not merged; does not fix this.
- Documentation: `docs/docs/playwright-web/Supported-Tools.mdx`: `outputPath` is the "Directory path where generated tests will be saved (use absolute path)" (an arbitrary absolute location is the documented usage, so the maintainer may see the missing containment as intended).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 1,024 exec / 603 ok (60 s).
- Evidence (verbatim, trimmed): input `{'options': {'outputPath': '"options": {{"options": {"ou\\..\\\\..\\\\.indows\\\\w"in.iniout", ', 'testNamePrefix': '', 'includeComments': False}}` -> `{"sessionId":"6abf1b5e-6fc0-4d3a-b018-fed517afd9bd","options":{"outputPath":"/home/mza6485/toolfuzzer/eval/targets/executeautomation__mcp-playwright/\"options\": {{\"options\": ...","testNamePrefix":"","includeComments":false},"message":"Started codegen session. Tests will be generated in: ..."}`. Two more inputs of the same shape.
- Hand-check hints: weak as XSS: only `{{` was flagged, and it sits inside JSON-encoded plain text. The unconfined `fs.mkdir(outputPath, { recursive: true })` is the more substantive issue (CWE-22/CWE-73) and is confirmed by the logged success responses, which mean directories with payload names were created on the fuzz host under the target checkout. The tool description says to use an absolute path, so arbitrary locations may be considered intended; the draft frames containment as a request. The `<b>` repro was not run.
</details>
