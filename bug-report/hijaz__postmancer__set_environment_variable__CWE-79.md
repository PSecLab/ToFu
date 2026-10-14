# Missing output encoding in `set_environment_variable`: variable and environment names are echoed raw and stored for later listings

**Repository:** `hijaz/postmancer` · **Tool:** `set_environment_variable` · **Tested commit:** `d71f38e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`set_environment_variable` stores a variable in a named environment. The success message copies the caller's `name` and `environment_name` verbatim into the tool result. The raw name and non-secret value are also saved and printed again by `get_environment_variables`. Nothing is escaped, so markup, template syntax or control characters from the caller come back unchanged.

## Details
`src/index.ts:301-320` at `d71f38e`:

```ts
    else if (name === "set_environment_variable") {
      const { name: varName, value, is_secret, environment_name } = SetEnvironmentVariableSchema.parse(args);
      await environmentService.setVariable(
        varName, value, is_secret,
        environment_name || environmentService.DEFAULT_ENVIRONMENT
      );
      const envName = environment_name || environmentService.DEFAULT_ENVIRONMENT;
      return {
        content: [{
            type: "text",
            text: `Successfully set environment variable '${varName}' in environment '${envName}'.`
```

`setVariable` (`src/environment-service.ts:254-266`) stores `name` and `value` as given. `get_environment_variables` later prints them with `` output += `- ${variable.name}: ` `` and `output += variable.value` (`src/index.ts:340-344`). The schema only requires `name` to be a non-empty string (`src/index.ts:55-60`). `sanitizeStorageName` (`src/storage.ts:55-59`) is applied to the environment file path only.

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
   {"name": "<b>tofu-poc</b>{{7*7}}", "value": "<i>tofu-poc</i>", "is_secret": false}
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
               result = await session.call_tool("set_environment_variable", {
                   "name": "<b>tofu-poc</b>{{7*7}}",
                   "value": "<i>tofu-poc</i>",
                   "is_secret": False})
               print(result)
               print(await session.call_tool("get_environment_variables", {}))

   asyncio.run(main())
   ```
4. What to observe: the first result is `Successfully set environment variable '<b>tofu-poc</b>{{7*7}}' in environment 'default'.` and the `get_environment_variables` result contains `- <b>tofu-poc</b>{{7*7}}: <i>tofu-poc</i>`.

## Expected behavior
Variable names should be validated (for example letters, digits, `_` and `-`), and names and values should be escaped before they are placed in a result.

## Actual behavior
The name is reflected verbatim. From the fuzzing run:

```
Successfully set environment variable '{{"n"nam:\x17\x17\x17\x17\x17\x17' in environment 'default'.
```

The control bytes (`\x17`, and NUL in other logged inputs) were echoed unchanged as well.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. Because the name and value are stored in the `default` environment, a value injected once is printed by every later `get_environment_variables` call. This only matters in clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients it is cosmetic, so severity is low.

## Suggested fix
Restrict variable names to a safe pattern in `SetEnvironmentVariableSchema`. A name containing `}` can never be referenced by the `{{name}}` substitution regex in `src/storage.ts:235` anyway. Escape names and values before placing them in result strings.

## Status on the default branch
Still present at `d71f38e` (2025-08-18). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 1,536 exec / 1,536 ok (60 s); repo24-b 49,664 exec / 49,664 ok (4,200 s).
- Evidence (verbatim, trimmed): input `{'name': '{{"n"nam:\x17\x17\x17\x17\x17\x17', 'value': '', 'is_secret': False, 'environment_name': ''}` -> `{'content': [{'type': 'text', 'text': 'Successfully set environment variable \'{{"n"nam:\x17\x17\x17\x17\x17\x17\' in environment \'default\'.'}]}`. Two more inputs with NUL bytes gave the same kind of output.
- Hand-check hints: weak. Only `{{` was reflected, into a plain-text MCP result. The `<b>` payload and the stored echo through `get_environment_variables` are derived from the code, not from a logged run. The fuzz runs wrote junk variables into the server's `default` environment, which is expected for this tool. Same root cause as the other four postmancer drafts; consider one combined issue.
</details>
