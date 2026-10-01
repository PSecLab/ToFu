# Missing output encoding in `list-workflows`: `owner` and `repo` are echoed raw into the reply

**Repository:** `ddukbg/github-enterprise-mcp` · **Tool:** `list-workflows` · **Tested commit:** `86c8752`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`list-workflows` lists the GitHub Actions workflows of `owner/repo`. The caller's `owner` and `repo` strings are put unchanged into every reply: the success header, the "no workflows" message and the 404 error. They are also not validated or URL-encoded before they go into the API path. The reply is plain MCP text, so this is low severity.

## Details
`server/index.ts:1169-1236` (tested commit):

```ts
const response = await context.actions.listWorkflows(owner, repo, page, perPage);
if (!response.workflows || response.workflows.length === 0) {
  return { content: [{ type: "text", text: `No workflows found in repository '${owner}/${repo}'.` }] };
}
...
text: `Workflows in repository '${owner}/${repo}' (${response.total_count}):\n\n...`
...
text: `Error listing workflows: ${error.message}`
```

On a 404 the error message contains the raw request path (`utils/client.ts:127-128`, `GitHub API resource not found: ${path}`), and the path is plain interpolation (`api/actions/actions.ts:30-37`):

```ts
return this.client.get<GitHubWorkflowListResponse>(`repos/${owner}/${repo}/actions/workflows`, { ... });
```

Both fields are only `z.string().min(1)`.

## Steps to reproduce
1. Prerequisites: Node.js 18+, Python 3. Use a local stub instead of a real GitHub instance. Save as `stub.py` and run `python3 stub.py`:

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
   {"owner": "<b>tofu-poc</b>", "repo": "none"}
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
               result = await session.call_tool("list-workflows",
                   {"owner": "<b>tofu-poc</b>", "repo": "none"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `Error listing workflows: GitHub API resource not found: repos/<b>tofu-poc</b>/none/actions/workflows`.

## Expected behavior
`owner` and `repo` are checked against GitHub's naming rules before the request, and echoed values are encoded for the rendering context.

## Actual behavior
From the fuzzing run:

```
Error listing workflows: GitHub API resource not found: repos/{{/re\n\n\nre\n\n/actions/workflows
```

## Impact
The LLM chooses `owner` and `repo`, and prompt injection can steer it. The echoed text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. Low severity. This tool is read-only, so the unencoded path matters less here than in the write tools.

## Suggested fix
Validate `owner` with `/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/` and `repo` with `/^[A-Za-z0-9._-]{1,100}$/`, and build paths with `encodeURIComponent`. One shared helper in `api/` would cover every tool that takes `owner` and `repo`.

## Status on the default branch
Still present at `86c8752` (2025-09-14). The tested commit is the current default branch head.

## Prior reports
- #5 "feat(cicd): Automate security scanning using CodeQL" (PR, closed 2025-04-08) and #14 "Potential fix for code scanning alert no. 6: Type confusion through parameter tampering" (PR, closed 2025-09-09): the only security PRs about the server's own code (the rest are dependency bumps, badges, docs, CI and features). #14 adds a type check on `sessionId` in the HTTP transport, not on `owner`/`repo` or tool replies. Any other CodeQL alerts live in the repository's Security tab, which is not in the fetched data. Neither fixes this.
- Documentation: README.md tool table lists `owner`: "Repository owner" and `repo`: "Repository name" for this tool, with no validation, encoding or untrusted-input note.
- No issue or PR reports unescaped output or unencoded API paths. Searched all 2 issues and 13 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: repo24-b 224256 exec / 46718 ok (4200 s). Not seen in corpus-sbx or e2-0922.
- Evidence (verbatim, trimmed):
  - `{'owner': '{{', 'repo': 're\n\n\nre\n\n', 'page': 164497930, 'perPage': 164497956}` -> `Error listing workflows: GitHub API resource not found: repos/{{/re\n\n\nre\n\n/actions/workflows`
  - `{'owner': '{`\x16{{re', 'repo': 'ਊ츊', ...}` -> `... not found: repos/{`\x16{{re/ਊ츊/actions/workflows`
  - `{'owner': '筻഍഍ऍ∜‬┢', 'repo': '@#\r\x00\x16{{', ...}` -> echoed with CR and NUL.
- Hand-check hints: weak. Only `{{` was echoed into a plain-text reply (confirmed at `client.ts:127-128`, `index.ts:1209,1221,1230`). The `<b>` payload and the stub are my substitutions and were not run. Best filed together with `delete-repository` and `update-repository` as one "validate and encode owner/repo" issue.
</details>
