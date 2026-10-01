# Missing output encoding in `project_architecture`: `features` is inserted raw (including HTML tags) into the returned prompt

**Repository:** `gdli6177/mcp-prompt-server` · **Tool:** `project_architecture` · **Tested commit:** `a27941f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`project_architecture` is built from `src/prompts/project_architecture.yaml`. It fills `{{project_type}}`, `{{technologies}}` and `{{features}}` in a text template and returns the result. Values go in with no encoding, so a `<script>` tag in `features` comes back unchanged. Each value is also used as a `String.prototype.replace` replacement string, so `$&`, `` $` `` and `$'` are expanded. Impact is low, because the output is a prompt for the model. It matters only if a client renders tool output as HTML or HTML-enabled Markdown.

## Details
All prompt tools share the handler at `src/index.js:96-127`. Substitution happens at `src/index.js:108-111`:

```js
// 替换所有 {{arg}} 格式的参数
for (const [key, value] of Object.entries(args)) {
  text = text.replace(new RegExp(`{{${key}}}`, 'g'), value);
}
```

The template is `src/prompts/project_architecture.yaml:20-22`. All three values land on plain text lines (`项目类型：`, `技术栈：`, `主要功能：`).

Three things are missing:
- No escaping of `<`, `>` and `&`.
- `value` is a replacement string, so `$$`, `$&`, `` $` `` and `$'` are interpreted.
- Arguments are substituted one pass at a time. A `project_type` value containing `{{features}}` is filled in by the `features` pass.

## Steps to reproduce
1. Prerequisites: Node.js. No environment variables or accounts are needed.
2. Install as the README describes:
   ```bash
   git clone https://github.com/gdli6177/mcp-prompt-server
   cd mcp-prompt-server && git checkout a27941f
   npm install
   ```
   The client below starts it with `node src/index.js`.
3. Call the tool:

   ```json
   {"project_type": "web", "technologies": "React", "features": "<b>tofu-poc</b> $&"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/mcp-prompt-server/src/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("project_architecture", {"project_type": "web", "technologies": "React", "features": "<b>tofu-poc</b> $&"})
               print(result)

   asyncio.run(main())
   ```
4. Look at the returned text. The `主要功能：` line contains `<b>tofu-poc</b>` verbatim, and `$&` has become `{{features}}`.

## Expected behavior
Values appear exactly as sent, with no `$` pattern expansion. If the output is meant to be rendered, HTML in values is escaped.

## Actual behavior
For the arguments above:

```
主要功能：<b>tofu-poc</b> {{features}}
```

From the fuzzing run, a `<script>` element in `features` was returned unchanged:

```
'请为以下项目设计一个合理的架构和目录结构：\n\n项目类型：Web应用\n技术栈：React\n主要功能：<script>while(true){}</script>\n\n请提供：...'
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content can steer that choice. The output goes back to the model and may be shown in the client UI. Whoever controls the argument can already write any text there. Markup only matters in clients that render tool output as HTML-enabled Markdown, and most MCP clients treat `text` content as plain text or sanitized Markdown. Low severity.

## Suggested fix
- Pass a replacer function so values are inserted literally: `text.replace(new RegExp(`{{${key}}}`, 'g'), () => value)`.
- Substitute all placeholders in one pass: `text = text.replace(/{{(\w+)}}/g, (m, k) => (k in args ? args[k] : m));`.
- If the output is rendered anywhere, escape `<`, `>` and `&` in values.

## Status on the default branch
Still present at `a27941f` (2025-07-30). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on `<script` / `</script>`. `check_invalid_json` also fired (it flags non-JSON input and is not relevant here).
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2560 successful, 60 s budget. Only one evidence row.
- Evidence (verbatim, trimmed):
  - input `{'project_type': 'Web应用', 'technologies': 'React', 'features': '<script>while(true){}</script>'}`
  - output `{'content': [{'type': 'text', 'text': '请为以下项目设计一个合理的架构和目录结构：\n\n项目类型：Web应用\n技术栈：React\n主要功能：<script>while(true){}</script>\n\n请提供：[...]'}]}`
- Hand-check hints: **weak**. This is the strongest-looking of the seven prompt-server items, because a real `<script>` element is reflected. But the output is a plain-text prompt for the model, and echoing the argument is the tool's purpose. A client would have to render tool output as raw HTML for this to matter, and I have no evidence that any client does. The fuzz payload was an infinite loop, so I swapped in `<b>tofu-poc</b>` for the PoC. The `$&` expansion was confirmed with a standalone Node 22 snippet that reimplements `src/index.js:108-111` (no repo code run). The PoC output line comes from that snippet.
- Same root cause as the six other prompt tools in this repo. One combined issue is probably better than seven.
</details>
