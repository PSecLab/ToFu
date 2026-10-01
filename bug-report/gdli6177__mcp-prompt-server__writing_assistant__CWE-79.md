# Missing output encoding in `writing_assistant`: `draft` can close the template's code fence and inject Markdown/HTML into the returned prompt

**Repository:** `gdli6177/mcp-prompt-server` · **Tool:** `writing_assistant` · **Tested commit:** `a27941f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`writing_assistant` is built from `src/prompts/writing_assistant.yaml`. It places the caller's `draft` inside a fenced code block of a Markdown template and returns the text. The value is inserted with no encoding, so a draft that contains a line of three backticks closes the fence. Whatever follows it then becomes live Markdown or HTML. The value is also used as a `String.prototype.replace` replacement string, so `$&`, `` $` `` and `$'` are expanded. Impact is low, because the output is a prompt for the model.

## Details
All prompt tools share the handler at `src/index.js:96-127`. Substitution happens at `src/index.js:108-111`:

```js
// 替换所有 {{arg}} 格式的参数
for (const [key, value] of Object.entries(args)) {
  text = text.replace(new RegExp(`{{${key}}}`, 'g'), value);
}
```

The template is `src/prompts/writing_assistant.yaml:59-70`:

````yaml
## 用户草稿

```
{{draft}}
```

## 目标平台
{{#if platform}}
{{platform}}
{{else}}
请先告诉我你希望将文章编辑成哪种平台的内容（公众号、小红书、推特等）
{{/if}}
````

Three things are missing:
- The fence around `draft` is fixed at three backticks, and backticks in the value are not escaped.
- `value` is a replacement string, so `$$`, `$&`, `` $` `` and `$'` are interpreted.
- Arguments are substituted one pass at a time. A `draft` value containing `{{platform}}` is filled in by the `platform` pass.

The server also has no support for Handlebars blocks. `{{#if platform}}`, `{{else}}` and `{{/if}}` reach the output literally (visible in the fuzz output below).

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

   ````json
   {"draft": "x\n```\n<b>tofu-poc</b> $&\n```", "platform": ""}
   ````

   ````python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/mcp-prompt-server/src/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("writing_assistant", {"draft": "x\n```\n<b>tofu-poc</b> $&\n```", "platform": ""})
               print(result)

   asyncio.run(main())
   ````
4. Look at the `## 用户草稿` section of the returned text. `<b>tofu-poc</b>` now sits outside any code fence, and `$&` has become `{{draft}}`.

## Expected behavior
The whole draft stays inside the code block, exactly as sent, with no `$` pattern expansion.

## Actual behavior
The `## 用户草稿` section for the arguments above:

````
## 用户草稿

```
x
```
<b>tofu-poc</b> {{draft}}
```
```
````

From the fuzzing run, the draft was copied verbatim, and the unsupported Handlebars blocks remained:

````
'...## 用户草稿\n\n```\n/XXXXXXXXXXXXXXXXX{{{\n```\n\n## 目标平台\n{{#if platform}}\n\n{{else}}\n请先告诉我你希望将文章编辑成哪种平台的内容（公众号、小红书、推特等）\n{{/if}}\n\n请根据以上信息，...'
````

## Impact
The model chooses the arguments, and prompt injection in untrusted content (for example, a draft pasted from the web) can steer that choice. The output goes back to the model and may be shown in the client UI. Breaking out of the fence lets draft text look like part of the instructions, not part of the quoted draft. That is a small prompt-structure issue. Markup renders only in clients that render tool output as HTML-enabled Markdown. Low severity.

## Suggested fix
- Pass a replacer function: `text.replace(new RegExp(`{{${key}}}`, 'g'), () => value)`.
- Substitute all placeholders in one pass: `text = text.replace(/{{(\w+)}}/g, (m, k) => (k in args ? args[k] : m));`.
- Build the fence around `draft` from a backtick run longer than the longest run inside the draft.
- Either implement `{{#if}}` / `{{else}}` / `{{/if}}` or remove them from the template.

## Status on the default branch
Still present at `a27941f` (2025-07-30). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on token `{{`.
- Campaigns and executions: `corpus-sbx`, 2048 executions, 2036 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'draft': '/XXXXXXXXXXXXXXXXX{{{', 'platform': ''}`
  - output `{'content': [{'type': 'text', 'text': '# 写作编辑助手\n\n[...]## 用户草稿\n\n```\n/XXXXXXXXXXXXXXXXX{{{\n```\n\n## 目标平台\n{{#if platform}}\n\n{{else}}\n[...]{{/if}}\n\n[...]'}]}`
- Hand-check hints: **weak**. The fuzz evidence only shows `{{` echoed inside a code fence, which is harmless. The fence breakout in the PoC is a real but minor prompt-structure issue that ToFu did not exercise. I derived it, together with the `$&` expansion, from a standalone Node 22 snippet that reimplements `src/index.js:108-111` and reads the YAML as text (no repo code run). The PoC output comes from that snippet, not from the live server.
- Same root cause as the six other prompt tools in this repo. One combined issue is probably better than seven.
- The literal `{{#if platform}}` blocks are a functional bug, not a security one.
</details>
