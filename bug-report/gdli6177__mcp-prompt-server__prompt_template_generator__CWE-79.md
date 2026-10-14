# Missing output encoding in `prompt_template_generator`: `prompt_name` is inserted raw into the returned prompt, and `$&` patterns are expanded

**Repository:** `gdli6177/mcp-prompt-server` · **Tool:** `prompt_template_generator` · **Tested commit:** `a27941f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`prompt_template_generator` is built from `src/prompts/prompt_template_generator.yaml`. It fills `{{prompt_name}}`, `{{task_type}}` and `{{prompt_description}}` in a text template and returns the result. Values go in with no encoding. Each value is also used as a `String.prototype.replace` replacement string, so `$&`, `` $` `` and `$'` are expanded instead of copied. Impact is low, because the output is a prompt for the model.

## Details
All prompt tools share the handler at `src/index.js:96-127`. Substitution happens at `src/index.js:108-111`:

```js
// 替换所有 {{arg}} 格式的参数
for (const [key, value] of Object.entries(args)) {
  text = text.replace(new RegExp(`{{${key}}}`, 'g'), value);
}
```

The template is `src/prompts/prompt_template_generator.yaml:18-20`. `prompt_name` is placed inside double quotes in a sentence (line 18). `task_type` (line 18) and `prompt_description` (line 20) are on plain text lines.

Three things are missing:
- No escaping of markup or quotes.
- `value` is a replacement string, so `$$`, `$&`, `` $` `` and `$'` are interpreted.
- Arguments are substituted one pass at a time. A `prompt_name` value containing `{{task_type}}` is filled in by a later pass.

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
   {"prompt_name": "<b>tofu-poc</b> $&", "prompt_description": "d", "task_type": "t"}
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
               result = await session.call_tool("prompt_template_generator", {"prompt_name": "<b>tofu-poc</b> $&", "prompt_description": "d", "task_type": "t"})
               print(result)

   asyncio.run(main())
   ```
4. Look at the first line of the returned text. `<b>tofu-poc</b>` is present verbatim, and `$&` has become `{{prompt_name}}`.

## Expected behavior
Values appear exactly as sent, with no `$` pattern expansion and no re-substitution. If the output is rendered, markup in values is escaped.

## Actual behavior
For the arguments above:

```
请为我生成一个名为"<b>tofu-poc</b> {{prompt_name}}"的新prompt模板，用于t任务。
```

From the fuzzing run, a `prompt_name` containing `${` was returned unchanged. In JavaScript, `${` is not a replacement pattern, so this particular input is a plain echo:

```
'请为我生成一个名为"a]pn${aa]pn"的新prompt模板，用于任务。\n\n该prompt的描述为：\n\n请提供：...'
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content can steer that choice. The output goes back to the model and may be shown in the client UI. Whoever controls the argument can already write any text there, so the gain is small. Markup matters only in clients that render tool output as HTML-enabled Markdown. `$` patterns silently alter the prompt. Low severity.

## Suggested fix
- Pass a replacer function: `text.replace(new RegExp(`{{${key}}}`, 'g'), () => value)`.
- Substitute all placeholders in one pass: `text = text.replace(/{{(\w+)}}/g, (m, k) => (k in args ? args[k] : m));`.
- If the output is rendered, escape `<`, `>` and `&` in values.

## Status on the default branch
Still present at `a27941f` (2025-07-30). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on token `${`. `check_invalid_json` also fired (not relevant here).
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2560 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'prompt_name': 'a]pn${aa]pn', 'prompt_description': '', 'task_type': ''}`
  - output `{'content': [{'type': 'text', 'text': '请为我生成一个名为"a]pn${aa]pn"的新prompt模板，用于任务。\n\n该prompt的描述为：\n\n请提供：[...]'}]}`
- Hand-check hints: **weak**, the weakest of the seven. The flagged token `${` has no meaning in this context: it is neither a JS replacement pattern nor rendered markup. I confirmed this with a standalone Node 22 snippet; `${` passed through literally. The only real defects are the shared ones: no encoding, `$&` expansion, second-order substitution. Those were confirmed with the same snippet, which reimplements `src/index.js:108-111` (no repo code run). The PoC output line comes from that snippet.
- Same root cause as the six other prompt tools in this repo. One combined issue is probably better than seven.
</details>
