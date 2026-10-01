# Missing output encoding in `watch_topic`: `topic` is echoed and stored verbatim

**Repository:** `blazickjp/arxiv-mcp-server` · **Tool:** `watch_topic` · **Tested commit:** `42419c1`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`watch_topic` saves the caller's `topic` string to `watched_topics.json` and returns it unchanged inside a JSON result. Markup or template syntax in `topic` (for example `<b>` tags or `{{ }}`) comes back as-is. The result is JSON text, so this only matters if an MCP client or a downstream tool renders the tool result as HTML or Markdown. I rate it as a low-severity output-encoding note, not a confirmed XSS.

## Details
The handler strips the topic and stores it in the record that is both persisted and returned (`src/arxiv_mcp_server/tools/alerts.py:251-308`):

```python
        topic = (arguments.get("topic") or "").strip()
        ...
        record = {
            "topic": topic,
            ...
        }
        ...
        _save_watches(payload)
        ...
                text=json.dumps(
                    {
                        "status": "success",
                        "message": "Topic watch saved",
                        "topic": record,
                    },
```

`json.dumps` escapes quotes, backslashes and control characters, but not `<`, `>`, `&` or `{`. The stored value is later returned by `list_watches` and `check_alerts` as well.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No network access is needed for `watch_topic` itself.
2. Start the server at the tested commit, with a throwaway storage directory:
   `uvx --from git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38 arxiv-mcp-server --storage-path /tmp/tofu-arxiv`
3. Call the tool with `{"topic": "<b>tofu-poc</b>{{7*7}}", "categories": [], "max_results": 1}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=[
           "--from", "git+https://github.com/blazickjp/arxiv-mcp-server@42419c18376ef5559a38fa7f1895938ad2b84e38",
           "arxiv-mcp-server", "--storage-path", "/tmp/tofu-arxiv"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("watch_topic", {"topic": "<b>tofu-poc</b>{{7*7}}", "categories": [], "max_results": 1})
               print(result)

   asyncio.run(main())
   ```
4. The result text contains `"topic": "<b>tofu-poc</b>{{7*7}}"` unchanged, and the same string is in `/tmp/tofu-arxiv/watched_topics.json`. Remove the watch afterwards with `unwatch_topic` or delete `/tmp/tofu-arxiv`.

## Expected behavior
If tool results may be rendered, caller-supplied text should be encoded for that context, or the field should be documented as raw text.

## Actual behavior
From the fuzzing run:

```
{
  "status": "success",
  "message": "Topic watch saved",
  "topic": {
    "topic": "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
    ...
```

## Impact
`topic` is chosen by the LLM and can be steered by prompt injection. The value is reflected and also stored, so it reappears in later `list_watches`/`check_alerts` results. In a client that shows tool output as plain text or JSON there is no effect. In a client that renders tool output as HTML, the markup would be interpreted. I did not find such rendering in this repository. Low.

## Suggested fix
No change is strictly needed for a JSON API. If you want defense in depth, reject or strip `<`, `>` and control characters in `topic` (arXiv query syntax does not need them), or document that tool results carry raw caller text.

## Status on the default branch
Unchanged at `454397c` (2026-09-30). `alerts.py` is identical at the tested commit and HEAD.

## Prior reports
None found. Searched all 119 issues and 149 pull requests (fetched 2026-10-01) and the README / docs on the default branch. Issues #222 and #245 and PRs #224 and #250 touch `watch_topic`, but only its `categories` update semantics. The README and SECURITY.md treat paper text as untrusted but say nothing about encoding of caller-supplied `topic`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output` only; the reflected token was `{{`.
- Campaigns and executions: `corpus-sbx` 2,048 execs / 1,643 success (60 s); `repo24` 55,808 / 41,576 (4,200 s).
- Evidence (verbatim, trimmed): input `{'topic': '{{"top"', 'categories': [], 'max_results': 0}`, output `'{\n  "status": "success",\n  "message": "Topic watch saved",\n  "topic": {\n    "topic": "{{\\"top\\"", ...'`. The other two samples are runs of `{` with `\x7f` bytes (escaped by JSON as `\u007f`).
- Hand-check hints: weak. Only template braces `{{` echoed into JSON text; no HTML/Markdown rendering context in the server. A maintainer will likely call this working as intended. Consider not filing. The `<b>` payload in the draft is my substitution of the same shape to make the echo visible; it was not run.
</details>
