# Missing output encoding in `get-component-docs`: unknown `componentName` is echoed verbatim, including HTML

**Repository:** `zhixiaoqiang/antd-components-mcp` · **Tool:** `get-component-docs` · **Tested commit:** `003ccf7`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get-component-docs` returns the documentation for an Ant Design component. When the name is not a known component, the reply repeats `componentName` twice, unchanged, so markup such as `<script>` in the argument comes back as-is. The reply is a plain text content block meant for the LLM, so this only matters if a client renders tool output as HTML or Markdown. The component lookup itself is an exact match against the bundled index, so the name is never used as a path.

## Details
`src/tools/get-component-docs.ts:14-24`:
```ts
    async ({ componentName }) => {
      const documentation = await getComponentDocumentation(componentName);
      return {
        content: [
          {
            type: "text",
            text: `${componentName} 组件的文档：
${documentation}
如有版本说明需要提醒用户需要使用某个版本及以上的版本`,
```
`src/utils/components.ts:51-56` puts the name into the "not found" message a second time:
```ts
export const getComponentDocumentation = async (componentName: string) => {
  const component = await findComponentByName(componentName);

  if (!component) {
    return ` "${componentName}" 组件文档不存在`;
  }
```
The schema is `{ componentName: z.string() }`, with no length or character limit.

## Steps to reproduce
1. Prerequisites: Node.js and pnpm. No credentials. The component data is bundled in `componentData/`.
2. Build and start the server (the README's `npx @jzone-mcp/antd-components-mcp` runs the published package; to test this commit, build it):
   ```bash
   git clone https://github.com/zhixiaoqiang/antd-components-mcp && cd antd-components-mcp
   git checkout 003ccf7
   pnpm install && pnpm build
   node dist/cli.js   # optional: the client script below starts it
   ```
3. From the repository root, call the tool with these arguments:
   ```json
   {"componentName": "Input<img src=x onerror=console.log('tofu-poc')>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/cli.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get-component-docs", {
                   "componentName": "Input<img src=x onerror=console.log('tofu-poc')>",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the `<img ...>` markup twice in the returned text, unescaped.

## Expected behavior
An unknown component name produces a fixed "not found" message, or the name is escaped before it is echoed.

## Actual behavior
The name is echoed twice. From the fuzzing run (input `{'componentName': 'Input<script>alert(1)</script>'}`):
```
Input<script>alert(1)</script> 组件的文档：
 "Input<script>alert(1)</script>" 组件文档不存在
如有版本说明需要提醒用户需要使用某个版本及以上的版本
```

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. The value is reflected only to the client that sent it. Risk exists only for MCP clients or chat UIs that render tool results as HTML (or Markdown with inline HTML) without sanitizing them. The text is mainly read by the model.

## Suggested fix
When the component is not found, return a fixed message without the input, or a list of close matches from the index. If the name must be echoed, restrict `componentName` in the schema, for example `z.string().max(64).regex(/^[A-Za-z][A-Za-z0-9.-]*$/)`, which accepts every name and directory name in `componentData/components-index.json` and rejects markup.

## Status on the default branch
Still present at `003ccf7` (2026-09-07). The tested commit is the current default branch head.

## Prior reports
- No issue or PR reports this. Searched all 4 issues and 53 pull requests (fetched 2026-10-01; 45 of the PRs are automated "Update extracted docs" PRs); none mentions `componentName` validation, escaping or XSS. The README / docs on the default branch have no security notes.
- #18 "Add MseeP.ai badge" (PR, closed 2025-06-24; its badge is on the README): third-party badge PR whose body reports an automated scan score of 100/100 with no findings listed; it does not mention this echo and is not a fix.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (tokens `<script`, `</script>`; `{{` on other inputs). `check_invalid_json` also fired (input-side heuristic).
- Campaigns and executions: `corpus-sbx` 2048 exec / 2048 success (60 s).
- Evidence (verbatim, trimmed): input `{'componentName': 'Input<script>alert(1)</script>'}`; output `Input<script>alert(1)</script> 组件的文档：\n "Input<script>alert(1)</script>" 组件文档不存在\n如有版本说明需要...`. Inputs `{{[` and `{{[G` were echoed the same way.
- Hand-check hints: weak. Real unescaped reflection of `<script>`, but into a plain `type: "text"` block consumed by the LLM, and the value comes from the same caller. No known renderer in scope. The `<img>` payload is my substitution; not run. All 73 entries in `componentData/components-index.json` (both `name` and `dirName`) match the suggested regex (checked with a JSON read of the data file). File together with the `list-component-examples` draft as one issue, if at all.
</details>
