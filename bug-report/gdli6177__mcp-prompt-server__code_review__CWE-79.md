# Missing output encoding in `code_review`: `language` and `code` are inserted raw into the returned Markdown, and `$&` patterns are expanded

**Repository:** `gdli6177/mcp-prompt-server` · **Tool:** `code_review` · **Tested commit:** `a27941f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`code_review` is built from `src/prompts/code_review.yaml`. It fills `{{language}}` and `{{code}}` in a Markdown template and returns the text. Values go in with no encoding: markup passes through, and a `code` value can close the code fence the template opens. Each value is also used as a `String.prototype.replace` replacement string, so `$&`, `` $` `` and `$'` are expanded. Impact is low, because the output is a prompt for the model. But the prompt text can differ from what the caller sent.

## Details
All prompt tools share the handler at `src/index.js:96-127`. Substitution happens at `src/index.js:108-111`:

```js
// 替换所有 {{arg}} 格式的参数
for (const [key, value] of Object.entries(args)) {
  text = text.replace(new RegExp(`{{${key}}}`, 'g'), value);
}
```

The template is `src/prompts/code_review.yaml:15-26`. `language` appears in a sentence (line 15) and as the fence info string (line 24). `code` goes inside the fence (line 25).

Three things are missing:
- No escaping for Markdown/HTML. A `code` value that contains a line of three backticks ends the fence early.
- `value` is used as a replacement string, so `$$`, `$&`, `` $` `` and `$'` in it are interpreted.
- Arguments are substituted one pass at a time. A `language` value containing `{{code}}` is filled in by the `code` pass.

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
   {"language": "<b>tofu-poc</b> $&", "code": "x"}
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
               result = await session.call_tool("code_review", {"language": "<b>tofu-poc</b> $&", "code": "x"})
               print(result)

   asyncio.run(main())
   ```
4. Look at the returned text. `<b>tofu-poc</b>` is present verbatim, and `$&` has become `{{language}}`.

## Expected behavior
Values appear exactly as sent. No `$` pattern expansion, no re-substitution, and no way for a value to close the template's code fence when the output is rendered.

## Actual behavior
The relevant lines for the arguments above:

````
请对以下<b>tofu-poc</b> {{language}}代码进行全面审查，包括但不限于：
```<b>tofu-poc</b> {{language}}
````

From the fuzzing run, `code: "{{"` and a `language` made of six U+107B7B characters were both copied verbatim:

````
'请对以下\U00107b7b[x6]代码进行全面审查，包括但不限于：\n1. 代码质量和可读性\n[...]\n\n代码：\n```\U00107b7b[x6]\n{{\n```\n\n请提供详细的分析和具体的改进建议。'
````

## Impact
The model chooses the arguments, and prompt injection in untrusted content (for example, a file under review) can steer that choice. The output goes back to the model and may be shown in the client UI. Whoever controls the argument can already write any text there, so the gain is small. Markup renders only in clients that render tool output as HTML-enabled Markdown. `$` patterns silently alter the prompt. Low severity.

## Suggested fix
- Pass a replacer function: `text.replace(new RegExp(`{{${key}}}`, 'g'), () => value)`.
- Substitute all placeholders in one pass: `text = text.replace(/{{(\w+)}}/g, (m, k) => (k in args ? args[k] : m));`.
- Build the fence for `code` from a backtick run longer than any run inside the value. Escape `<`, `>` and `&` in values that are placed outside fences if the output is rendered.

## Status on the default branch
Still present at `a27941f` (2025-07-30). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on token `{{` (it came from `code`).
- Campaigns and executions: `corpus-sbx`, 3072 executions, 3070 successful, 60 s budget. Only one evidence row.
- Evidence (verbatim, trimmed):
  - input `{'language': '\U00107b7b\U00107b7b\U00107b7b\U00107b7b\U00107b7b\U00107b7b', 'code': '{{'}`
  - output `{'content': [{'type': 'text', 'text': '请对以下\U00107b7b[x6]代码进行全面审查，[...]代码：\n```\U00107b7b[x6]\n{{\n```\n\n请提供详细的分析和具体的改进建议。'}]}`
- Hand-check hints: **weak**. The tool echoes its arguments into a prompt by design. The output is plain-text MCP content for the model. `{{` here is only template braces, placed inside a code fence. The real defects are minor: no encoding, `$&` expansion, second-order substitution. I confirmed these with a standalone Node 22 snippet that reimplements `src/index.js:108-111` (no repo code run). The PoC output lines come from that snippet.
- Same root cause as the six other prompt tools in this repo. One combined issue is probably better than seven.
</details>
