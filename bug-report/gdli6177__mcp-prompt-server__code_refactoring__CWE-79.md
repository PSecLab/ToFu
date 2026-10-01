# Missing output encoding in `code_refactoring`: `language` is inserted raw into the returned Markdown, and `$&` patterns are expanded

**Repository:** `gdli6177/mcp-prompt-server` · **Tool:** `code_refactoring` · **Tested commit:** `a27941f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`code_refactoring` is one of the tools the server builds from `src/prompts/*.yaml`. It fills `{{language}}`, `{{code}}` and `{{focus_areas}}` in a Markdown template and returns the text. Values go in with no encoding, so markup and Markdown fences in an argument pass through. Each value is also used as a `String.prototype.replace` replacement string, so `$&`, `` $` `` and `$'` inside it are expanded. Impact is low, because the output is a prompt for the model. But the text the model receives can differ from what the caller sent.

## Details
All prompt tools share the handler at `src/index.js:96-127`. Substitution happens at `src/index.js:108-111`:

```js
// 替换所有 {{arg}} 格式的参数
for (const [key, value] of Object.entries(args)) {
  text = text.replace(new RegExp(`{{${key}}}`, 'g'), value);
}
```

The template is `src/prompts/code_refactoring.yaml:18-26`. `language` appears in a sentence (line 18) and as the fence info string (line 20). `code` goes inside the fence (line 21). `focus_areas` sits between `{{#focus_areas}}` and `{{/focus_areas}}` (lines 24-26).

Three things are missing:
- Values are not escaped for Markdown/HTML.
- `value` is a replacement string, so `$$`, `$&`, `` $` `` and `$'` in it are interpreted.
- Arguments are substituted one pass at a time, so a value containing `{{code}}` gets filled in by a later pass.

The server also has no support for section tags, so `{{#focus_areas}}` and `{{/focus_areas}}` reach the output literally (visible in the fuzz output below).

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
   {"language": "<b>tofu-poc</b> $&", "code": "x", "focus_areas": ""}
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
               result = await session.call_tool("code_refactoring", {"language": "<b>tofu-poc</b> $&", "code": "x", "focus_areas": ""})
               print(result)

   asyncio.run(main())
   ```
4. Look at the returned text. `<b>tofu-poc</b>` is present verbatim, and `$&` has become `{{language}}`.

## Expected behavior
Values appear exactly as sent. No `$` pattern expansion and no re-substitution. If the output is rendered, markup is escaped or safely fenced.

## Actual behavior
The relevant lines for the arguments above:

````
请对以下<b>tofu-poc</b> {{language}}代码进行重构，以提高其质量和可维护性：
```<b>tofu-poc</b> {{language}}
````

From the fuzzing run, the `language` value was copied verbatim, and the unsupported section tags remained:

````
'请对以下{{{{{{{{{代码进行重构，以提高其质量和可维护性：\n\n```{{{{{{{{{\n\n```\n\n{{#focus_areas}}\n重点关注以下方面：\n{{/focus_areas}}\n\n请提供：...'
````

## Impact
The model chooses the arguments, and prompt injection in untrusted content can steer that choice. The output goes back to the model as a prompt and may be shown in the client UI. Whoever controls the argument can already write any text there, so the gain is small. Markup renders only in clients that render tool output as HTML-enabled Markdown. `$` patterns silently alter the prompt. Low severity.

## Suggested fix
- Pass a replacer function so values are inserted literally: `text.replace(new RegExp(`{{${key}}}`, 'g'), () => value)`.
- Do one substitution pass over all placeholders: `text = text.replace(/{{(\w+)}}/g, (m, k) => (k in args ? args[k] : m));`.
- Escape `<`, `>` and `&` in values if the output is rendered. Pick a fence longer than any backtick run in the value.
- Either implement `{{#name}}...{{/name}}` sections or remove them from the template.

## Status on the default branch
Still present at `a27941f` (2025-07-30). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on token `{{`.
- Campaigns and executions: `corpus-sbx`, 3584 executions, 3576 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'language': '{{{{{{{{{', 'code': '', 'focus_areas': ''}`
  - output `{'content': [{'type': 'text', 'text': '请对以下{{{{{{{{{代码进行重构，以提高其质量和可维护性：\n\n```{{{{{{{{{\n\n```\n\n{{#focus_areas}}\n重点关注以下方面：\n{{/focus_areas}}\n\n请提供：[...]'}]}`
- Hand-check hints: **weak**. Echoing the arguments into a prompt is what the tool is for. The output is plain-text MCP content for the model. `{{` is only template braces. The real defects are minor: no encoding, `$&`-pattern expansion, and second-order substitution. I confirmed these with a standalone Node 22 snippet that reimplements `src/index.js:108-111` (no repo code run). The PoC output lines come from that snippet, not from the live server.
- Same root cause as the six other prompt tools in this repo (`api_documentation`, `code_review`, `project_architecture`, `prompt_template_generator`, `test_case_generator`, `writing_assistant`). One combined issue is probably better than seven.
- The literal `{{#focus_areas}}` / `{{/focus_areas}}` in the output is a functional bug, not a security one.
</details>
