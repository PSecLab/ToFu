# Missing output encoding in `update-repository`: `owner` and `repo` are echoed raw into the error reply

**Repository:** `ddukbg/github-enterprise-mcp` · **Tool:** `update-repository` · **Tested commit:** `86c8752`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`update-repository` sends a PATCH for `owner/repo` to the GitHub API. When the API returns 404, the reply contains the raw request path, which includes the caller's `owner` and `repo` exactly as given. Neither field is validated or URL-encoded before it goes into the path. The reply is plain MCP text, so the echo is low severity.

## Details
`server/index.ts:1039-1099` (tested commit):

```ts
const repository = await context.repository.updateRepository(owner, repo, options);
...
} catch (error: any) {
  return { content: [{ type: "text", text: `Error updating repository: ${error.message}` }] };
}
```

The 404 message is built in `utils/client.ts:127-128` (`GitHub API resource not found: ${path}`), and the path comes from plain interpolation in `api/repos/repository.ts:73-75`:

```ts
return this.client.patch<GitHubRepository>(`repos/${owner}/${repo}`, options);
```

Both fields are only `z.string().min(1)`. So a `/` in `repo` also changes which API path receives the PATCH.

## Steps to reproduce
1. Prerequisites: Node.js 18+, Python 3. Use a local stub instead of a real GitHub instance, so nothing is changed. Save as `stub.py` and run `python3 stub.py`:

   ```python
   from http.server import BaseHTTPRequestHandler, HTTPServer

   class NotFound(BaseHTTPRequestHandler):
       def _reply(self):
           self.rfile.read(int(self.headers.get("Content-Length", 0)))
           self.send_response(404)
           self.send_header("Content-Type", "application/json")
           self.end_headers()
           self.wfile.write(b'{"message": "Not Found"}')
       do_GET = do_PATCH = do_DELETE = _reply

   HTTPServer(("127.0.0.1", 8099), NotFound).serve_forever()
   ```
2. Install and build as the README describes: `git clone https://github.com/ddukbg/github-enterprise-mcp.git && cd github-enterprise-mcp && npm install && npm run build`
3. Call the tool with:

   ```json
   {"owner": "<b>tofu-poc</b>", "repo": "none", "description": "tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["dist/index.js"],
           env={"GITHUB_ENTERPRISE_URL": "http://127.0.0.1:8099", "PATH": "/usr/bin:/bin:/usr/local/bin"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("update-repository",
                   {"owner": "<b>tofu-poc</b>", "repo": "none", "description": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `Error updating repository: GitHub API resource not found: repos/<b>tofu-poc</b>/none`.

## Expected behavior
`owner` and `repo` are checked against GitHub's naming rules before the request, and echoed values are encoded for the rendering context.

## Actual behavior
From the fuzzing run:

```
Error updating repository: GitHub API resource not found: repos/"own./e\x7f\x7f\x7f\x7ftc/,{{{{{{/{{{{{{{{...{{ "{2ower"
```

## Impact
The LLM chooses `owner` and `repo`, and prompt injection can steer it. The echoed text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. Low severity for the echo. Because the values are not encoded, the caller can also point the PATCH at a different API path under `repos/` (not tested).

## Suggested fix
Validate `owner` with `/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/` and `repo` with `/^[A-Za-z0-9._-]{1,100}$/`, and build the path with `encodeURIComponent(owner)` and `encodeURIComponent(repo)`.

## Status on the default branch
Still present at `86c8752` (2025-09-14). The tested commit is the current default branch head.

## Prior reports
- #5 "feat(cicd): Automate security scanning using CodeQL" (PR, closed 2025-04-08) and #14 "Potential fix for code scanning alert no. 6: Type confusion through parameter tampering" (PR, closed 2025-09-09): the only security PRs about the server's own code (the rest are dependency bumps, badges, docs, CI and features). #14 adds a type check on `sessionId` in the HTTP transport, not on `owner`/`repo` or tool replies. Any other CodeQL alerts live in the repository's Security tab, which is not in the fetched data. Neither fixes this.
- Documentation: README.md tool table lists `owner`: "Repository owner" and `repo`: "Repository name" for this tool, with no validation, encoding or untrusted-input note.
- No issue or PR reports unescaped output or unencoded API paths. Searched all 2 issues and 13 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: repo24-b 138240 exec / 70789 ok (4200 s); e2-0922 1536 / 1019 (300 s).
- Evidence (verbatim, trimmed):
  - `{'owner': '"own./e\x7f\x7f\x7f\x7ftc/,{{{{{{', 'repo': '{{{{...{{ "{2ower"', 'description': '', 'private': False, ...}` -> `Error updating repository: GitHub API resource not found: repos/"own./e\x7f\x7f\x7f\x7ftc/,{{{{{{/{{{{...{{ "{2ower"`
  - Same owner, `repo` with trailing `\x0f` bytes -> same shape.
  - Same owner prefix, CJK `repo` -> same shape.
- Hand-check hints: weak as XSS (only `{{` echoed into a plain-text reply; confirmed at `client.ts:127-128`, `index.ts:1093`). The `<b>` payload and the stub are my substitutions and were not run. Note that the first evidence `owner` contains `/` (`.../e...tc/,{{{`), which shows the path is not encoded. File together with `delete-repository` and `list-workflows` as one "validate and encode owner/repo" issue.
</details>
