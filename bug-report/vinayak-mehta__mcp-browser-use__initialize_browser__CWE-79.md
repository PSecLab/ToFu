# Missing output encoding in `initialize_browser`: `task` is echoed verbatim into the returned prompt text

**Repository:** `vinayak-mehta/mcp-browser-use` · **Tool:** `initialize_browser` · **Tested commit:** `7fad668`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`initialize_browser` starts a browser session and returns the browser-use system prompt with the caller's `task` appended. The `task` string is inserted unchanged, so any markup in it, such as `<script>`, comes back as-is. The result is plain text meant for the LLM, so this only matters if a client renders tool output as HTML or Markdown. In most clients it is cosmetic.

## Details
`src/mcp_browser_use/server.py:60-67`:
```python
    browser_system_prompt = f"""
        {system_prompt.text()}
        Your ultimate task is: {task}.
        If you achieved your ultimate task, stop everything and use the done tool to complete the task.
        If not, continue as usual.
    """

    return browser_system_prompt
```
`task` is a free `str` parameter (`server.py:35`) with no length or character restriction. Nothing escapes it before it is placed in the returned text.

## Steps to reproduce
1. Prerequisites: Python 3.10+ (`requires-python`) and `uv`. Playwright's Chromium must be installed; on first start, `main()` (`server.py:489-496`) checks for it and tries to install it. No API keys.
2. Start the server from the tested commit (the README's `uvx mcp-browser-use` runs the published package):
   ```bash
   git clone https://github.com/vinayak-mehta/mcp-browser-use && cd mcp-browser-use
   git checkout 7fad668
   uv run mcp-browser-use   # optional: the client script below starts it
   ```
3. Call the tool with these arguments:
   ```json
   {"headless": true, "task": "<img src=x onerror=console.log('tofu-poc')>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["--directory", "/path/to/mcp-browser-use", "run", "mcp-browser-use"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("initialize_browser", {
                   "headless": True,
                   "task": "<img src=x onerror=console.log('tofu-poc')>",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe `Your ultimate task is: <img src=x onerror=console.log('tofu-poc')>.` near the end of the returned text.

## Expected behavior
If the task is echoed, it is escaped for the format the client will display, or the server documents that the returned text is raw and must not be rendered as HTML.

## Actual behavior
The task text is returned unchanged inside the prompt. ToFu's fuzzing run sent `{"headless": true, "task": "<script>alert('xss')</script>"}` and flagged `<script` and `</script>` in the output. The captured output in the log is truncated before the end of the prompt, so the excerpt there only shows the system prompt header:
```
        You are an AI agent designed to automate browser tasks. Your goal is to accomplish the ultimate task following the rules.
...
```

## Impact
Low. `task` is chosen by the LLM, and prompt injection from untrusted content can steer it, but the value is reflected only to the same client that sent it, in a text block that the model reads. Risk exists only for clients that render tool results as HTML (or Markdown with inline HTML) without sanitizing them.

## Suggested fix
Strip or escape `<` and `>` in `task` (for example `html.escape(task, quote=False)`) and cap its length before interpolating it. Alternatively, leave `task` out of the returned text, since the model that called the tool already has it.

## Status on the default branch
Still present at `7fad668` (2025-03-20). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 7 issues and 3 pull requests (fetched 2026-10-01) and the README on the default branch (the repository has no other docs). The issues cover terms of service, runtime errors, browser lifecycle and setup; the pull requests cover docs, an `execute_javascript` tool and a download path. None touches `initialize_browser`'s returned prompt or escaping of `task`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (tokens `<script`, `</script>`).
- Campaigns and executions: `corpus-sbx` 1 exec / 1 success (60 s).
- Evidence (verbatim, trimmed): input `{'headless': True, 'task': "<script>alert('xss')</script>"}`; output `'\n        You are an AI agent designed to automate browser tasks. ... Use maximum {max_actions} actions per sequence.\nCommon action sequ` (truncated by the logger before the `Your ultimate task is:` line).
- Hand-check hints: weak. The echo is confirmed by code (`server.py:62`), not by the logged output, which is cut off before the task appears; ToFu presumably matched the full output before truncation (not verified). The value goes back into an LLM-facing prompt, not into anything rendered. Only one execution. Probably not worth filing. A more relevant (but different) observation: the tool returns instruction text that tells the model how to act, which is a prompt-steering surface by design, not a CWE-79 issue.
</details>
