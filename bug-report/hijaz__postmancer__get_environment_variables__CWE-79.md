# Missing output encoding in `get_environment_variables`: `environment_name` is echoed raw in the result

**Repository:** `hijaz/postmancer` · **Tool:** `get_environment_variables` · **Tested commit:** `d71f38e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_environment_variables` lists the variables stored in a named environment. The caller's `environment_name` is placed into the tool result verbatim, both in the "not found" error and in the header of a successful listing. Stored variable names and non-secret values are echoed the same way. Nothing is escaped, so markup or template syntax supplied by the caller comes back unchanged in the tool output.

## Details
`src/index.ts:325-334` at `d71f38e`:

```ts
    else if (name === "get_environment_variables") {
      const { environment_name } = GetEnvironmentVariablesSchema.parse(args);
      const envName = environment_name || environmentService.DEFAULT_ENVIRONMENT;
      const variables = await environmentService.getAllVariables(envName);
      let output = `Environment variables in '${envName}':\n\n`;
```

When the environment file does not exist, `src/environment-service.ts:84-85` throws ``new EnvironmentError(`Environment '${name}' not found`)`` with the raw name, and the shared handler at `src/index.ts:364-371` returns ``text: `Error: ${err.message}` ``. On success, `src/index.ts:340-344` appends `variable.name` and `variable.value` unescaped. The name is only sanitized for the file path (`sanitizeStorageName` in `src/storage.ts:55-59`), not for output.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No accounts or API keys. Use a throwaway storage directory: `mkdir -p /tmp/tofu-poc-postmancer`.
2. Install and start the server:
   ```
   git clone https://github.com/hijaz/postmancer.git
   cd postmancer && git checkout d71f38e14421a3ff5fa65b335f164c1a0b002d5b
   npm install && npm run build
   COLLECTIONS_PATH=/tmp/tofu-poc-postmancer node dist/src/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"environment_name": "<b>tofu-poc</b>{{7*7}}"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["dist/src/index.js"],
           env={**os.environ, "COLLECTIONS_PATH": "/tmp/tofu-poc-postmancer"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_environment_variables", {"environment_name": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Error: Environment '<b>tofu-poc</b>{{7*7}}' not found`.

## Expected behavior
The environment name should be escaped, or quoted in a form that cannot be read as markup, before it is placed in the result. A fixed message such as "Environment not found" would also work.

## Actual behavior
The name is reflected verbatim. From the fuzzing run (input trimmed):

```
Error: Environment '(UUUUUUUUUUUUUUUU{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{...UUUU' not found
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. An attacker who controls `environment_name` controls part of the result text. This matters only in clients that render tool results as HTML or Markdown, or feed them into a template engine. In plain-text clients the effect is cosmetic, so severity is low.

## Suggested fix
Escape caller-supplied names before building result strings, or use fixed error messages that do not repeat the input. A small helper that escapes `<`, `>`, `&` and quotes and strips control characters, applied in the error handler at `src/index.ts:364-371` and in the listing code, would cover this tool and the other tools that echo names.

## Status on the default branch
Still present at `d71f38e` (2025-08-18). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,048 ok (60 s); repo24-b 251,904 exec / 251,904 ok (4,200 s).
- Evidence (verbatim, trimmed): input `{'environment_name': '(UUUUUUUUUUUUUUUU{{{{...{{{UUUU'}` -> `{'content': [{'type': 'text', 'text': "Error: Environment '(UUUUUUUUUUUUUUUU{{{{...{{{UUUU' not found"}]}`. Two more inputs of the same shape gave the same kind of output.
- Hand-check hints: weak. The logged runs only reflected `{{` into a plain-text MCP error. Postmancer itself uses `{{name}}` for variable substitution (`src/storage.ts:230-240`), but that only runs on saved request fields in `request_from_collection`, not on this output, so the echoed braces are inert. The `<b>` reproduction is derived from the code, not from a logged run. Same root cause as the `list_requests`, `request_from_collection`, `save_request` and `set_environment_variable` drafts; consider filing one combined issue.
</details>
