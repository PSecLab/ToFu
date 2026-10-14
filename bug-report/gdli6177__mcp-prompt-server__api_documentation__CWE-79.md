# Missing output encoding in `api_documentation`: `language` is inserted raw into the returned Markdown, and `$&` patterns are expanded

**Repository:** `gdli6177/mcp-prompt-server` · **Tool:** `api_documentation` · **Tested commit:** `a27941f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
The server turns each YAML file in `src/prompts/` into a tool. `api_documentation` fills `{{language}}`, `{{code}}` and `{{format}}` in a Markdown template and returns the text. Argument values go in unchanged: HTML-like markup and Markdown fences pass through. Each value is also used as the replacement string of `String.prototype.replace`, so sequences like `$&` and `` $` `` get expanded instead of copied. Impact is low, because the output is a prompt for the model. But the text the model receives can differ from what the caller sent, and a client that renders tool output as Markdown will render the markup.

## Details
The handler shared by all prompt tools is in `src/index.js:96-127`. The substitution loop is at `src/index.js:104-115`:

```js
for (const message of userMessages) {
  if (message.content && typeof message.content.text === 'string') {
    let text = message.content.text;

    // 替换所有 {{arg}} 格式的参数
    for (const [key, value] of Object.entries(args)) {
      text = text.replace(new RegExp(`{{${key}}}`, 'g'), value);
    }

    promptText += text + '\n\n';
  }
}
```

The template is `src/prompts/api_documentation.yaml:18-22`. `language` appears in a sentence (line 18) and as the info string of a fenced code block (line 20). `code` goes inside that fence (line 21).

There are three gaps:
- Values are not escaped for the Markdown/HTML context, so a value can contain markup or close the code fence.
- `value` is passed as a replacement string, so the JavaScript replacement patterns (`$$`, `$&`, `` $` ``, `$'`) inside it are interpreted.
- Each argument is substituted in a separate pass. A `language` value that contains `{{code}}` gets filled in by the next pass.

## Steps to reproduce
1. Prerequisites: Node.js. The server needs no environment variables or accounts.
2. Install and start the server as the README describes:
   ```bash
   git clone https://github.com/gdli6177/mcp-prompt-server
   cd mcp-prompt-server && git checkout a27941f
   npm install
   ```
   The client below starts it with `node src/index.js`.
3. Call the tool with these arguments:

   ```json
   {"language": "<b>tofu-poc</b> $&", "code": "x", "format": "markdown"}
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
               result = await session.call_tool("api_documentation", {"language": "<b>tofu-poc</b> $&", "code": "x", "format": "markdown"})
               print(result)

   asyncio.run(main())
   ```
4. Look at the returned text. `<b>tofu-poc</b>` is present verbatim, and `$&` has been replaced by the placeholder it matched (`{{language}}`).

## Expected behavior
Each argument value appears in the output exactly as sent. No `$` pattern expansion and no second substitution pass. If the output is meant to be rendered, markup in values is escaped or kept inside a fence it cannot close.

## Actual behavior
With the arguments above, the relevant lines of the returned text are:

````
请根据以下<b>tofu-poc</b> {{language}}代码生成详细的API文档，使用markdown格式：
```<b>tofu-poc</b> {{language}}
````

From the fuzzing run: a `language` value containing a newline was copied verbatim. The newline moved part of the value out of the fence info string and into the fence body:

````
'请根据以下 a\x08]\x13{{{{{{[...]\x0f \x11\nla代码生成详细的API文档，使用格式：\n\n``` a\x08]\x13{{{{{{[...]\x0f \x11\nla\n\n```\n\n文档应包括：...'
````

## Impact
In MCP the model chooses tool arguments, and prompt injection in untrusted content can steer that choice. The output goes back to the model as a prompt and may also be shown in the client UI. Whoever controls the argument can already put any text there, so the gain is small. Markup renders only if the client renders tool output as Markdown with inline HTML. `$` patterns change the prompt text silently. Low severity.

## Suggested fix
- Insert values literally by passing a replacer function: `text.replace(new RegExp(`{{${key}}}`, 'g'), () => value)`.
- Substitute all placeholders in one pass so inserted values are not scanned again: `text = text.replace(/{{(\w+)}}/g, (m, k) => (k in args ? args[k] : m));`.
- If tool output is meant to be rendered, escape `<`, `>` and `&` in values, and choose a code fence longer than any backtick run in the value.

## Status on the default branch
Still present at `a27941f` (2025-07-30). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired. The flagged token was `{{`.
- Campaigns and executions: `corpus-sbx`, 3072 executions, 3068 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'language': ' a\x08]\x13{{{{{{[...]{{{{\x0f \x11\nla', 'code': '', 'format': ''}`
  - output `{'content': [{'type': 'text', 'text': '请根据以下 a\x08]\x13{{{{[...]\x0f \x11\nla代码生成详细的API文档，使用格式：\n\n``` a\x08]\x13{{{{[...]\x0f \x11\nla\n\n```\n\n文档应包括：[...]'}]}`
- Hand-check hints: **weak**. The tool's whole purpose is to echo its arguments into a prompt. The output is a plain-text MCP `text` item meant for the model, not HTML. The `{{` that ToFu flagged is only template braces and means nothing to a renderer. The real defects are small: no Markdown/HTML encoding, `$&`-style replacement-pattern expansion, and second-order placeholder substitution. I confirmed the `$&` expansion, the second-order substitution, and that `${` passes through literally with a standalone Node 22 snippet. The snippet reimplements the loop at `src/index.js:108-111` and reads the YAML as text. No repo code was run, and I did not check this against the live server. The "Actual behavior" lines for the PoC payload come from that snippet.
- The same root cause (`src/index.js:108-111`) covers all seven prompt tools flagged in this repo: `api_documentation`, `code_refactoring`, `code_review`, `project_architecture`, `prompt_template_generator`, `test_case_generator`, `writing_assistant`. Consider filing one issue instead of seven.
- Side note: `src/index.js:59` and `:179` `console.log` to stdout on a stdio server. A client may log a parse warning for those lines. ToFu still got results.
</details>
