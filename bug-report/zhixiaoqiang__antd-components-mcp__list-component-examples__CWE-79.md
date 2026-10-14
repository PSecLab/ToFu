# Missing output encoding in `list-component-examples`: unknown `componentName` is echoed verbatim, including HTML

**Repository:** `zhixiaoqiang/antd-components-mcp` · **Tool:** `list-component-examples` · **Tested commit:** `003ccf7`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`list-component-examples` returns code examples for an Ant Design component. The reply always starts with the caller's `componentName`, unchanged, so markup such as `<script>` in the argument comes back as-is when the name is unknown. The reply is a plain text content block meant for the LLM, so this only matters if a client renders tool output as HTML or Markdown. The component lookup itself is an exact match against the bundled index, so the name is never used as a path.

## Details
`src/tools/list-component-examples.ts:15-23`:
```ts
    async ({ componentName }) => {
      const componentExamples = await listComponentExamples(componentName);
  
      return {
        content: [
          {
            type: "text",
            text: `${componentName} 组件的代码示例文档：
${componentExamples || '暂无代码示例'}`,
```
`src/utils/components.ts:83-88` returns a fixed "component does not exist" string for unknown names, so the only echo is the prefix above:
```ts
export const listComponentExamples = async (componentName: string) => {
  const component = await findComponentByName(componentName);

  if (!component) {
    return "当前组件不存在";
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
   {"componentName": "<img src=x onerror=console.log('tofu-poc')>"}
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
               result = await session.call_tool("list-component-examples", {
                   "componentName": "<img src=x onerror=console.log('tofu-poc')>",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the `<img ...>` markup at the start of the returned text, unescaped.

## Expected behavior
An unknown component name produces a fixed "not found" message, or the name is escaped before it is echoed.

## Actual behavior
The name is echoed. From the fuzzing run (input `{'componentName': "<script>alert('xss')</script>"}`):
```
<script>alert('xss')</script> 组件的代码示例文档：
当前组件不存在
```

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. The value is reflected only to the client that sent it. Risk exists only for MCP clients or chat UIs that render tool results as HTML (or Markdown with inline HTML) without sanitizing them. The text is mainly read by the model.

## Suggested fix
Echo the canonical `component.name` from the index instead of the raw argument, and return a fixed message when the component is not found. Alternatively restrict `componentName` in the schema, for example `z.string().max(64).regex(/^[A-Za-z][A-Za-z0-9.-]*$/)`, which accepts every name and directory name in `componentData/components-index.json` and rejects markup.

## Status on the default branch
Still present at `003ccf7` (2026-09-07). The tested commit is the current default branch head.

## Prior reports
- No issue or PR reports this. Searched all 4 issues and 53 pull requests (fetched 2026-10-01; 45 of the PRs are automated "Update extracted docs" PRs); none mentions `componentName` validation, escaping or XSS. The README / docs on the default branch have no security notes.
- #13 "feat: Enhance listComponentExamples to prioritize remote fetching wit…" (PR, open 2025-05-22): changes `listComponentExamples` to fetch examples from the Ant Design GitHub repository with a local fallback; it does not touch the `${componentName}` prefix in the reply. Not a fix.
- #18 "Add MseeP.ai badge" (PR, closed 2025-06-24; its badge is on the README): third-party badge PR whose body reports an automated scan score of 100/100 with no findings listed; not a fix.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (tokens `<script`, `</script>`).
- Campaigns and executions: `corpus-sbx` 2048 exec / 2048 success (60 s).
- Evidence (verbatim, trimmed): input `{'componentName': "<script>alert('xss')</script>"}`; output `<script>alert('xss')</script> 组件的代码示例文档：\n当前组件不存在`.
- Hand-check hints: weak. Real unescaped reflection of `<script>`, but into a plain `type: "text"` block consumed by the LLM, and the value comes from the same caller. No known renderer in scope. The `<img>` payload is my substitution; not run. All 73 index entries (`name` and `dirName`) match the suggested regex (checked by reading the JSON data file). File together with the `get-component-docs` draft as one issue, if at all.
</details>
