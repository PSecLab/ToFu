# Missing output encoding in `delete-repository`: `owner` and `repo` are echoed raw into the reply

**Repository:** `ddukbg/github-enterprise-mcp` · **Tool:** `delete-repository` · **Tested commit:** `86c8752`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`delete-repository` deletes `owner/repo` through the GitHub API. The caller's `owner` and `repo` strings are put unchanged into the reply text, on success and on a 404. They are also not checked against GitHub's name rules or URL-encoded. The reply is plain MCP text, so the echo itself is low severity.

## Details
`server/index.ts:1102-1166` (tested commit). The success and error replies:

```ts
await context.repository.deleteRepository(owner, repo);
return { content: [{ type: "text", text: `Successfully deleted repository: ${owner}/${repo}` }] };
...
} catch (error: any) {
  return { content: [{ type: "text", text: `Error deleting repository: ${error.message}` }] };
}
```

For a 404 the error message contains the raw request path (`utils/client.ts:127-128`):

```ts
} else if (status === 404) {
  errorMessage = `GitHub API resource not found: ${path}`;
```

and the path is built by plain interpolation (`api/repos/repository.ts:80-82`):

```ts
await this.client.delete(`repos/${owner}/${repo}`);
```

The schema only requires `z.string().min(1)` for both fields. There is no `encodeURIComponent` call anywhere in `api/`, `utils/` or `server/`. So the same values also choose the request path: a `/` in `repo` adds path segments to the DELETE request.

## Steps to reproduce
1. Prerequisites: Node.js 18+, Python 3. Use a local stub instead of a real GitHub instance, so nothing is deleted. Save this as `stub.py` and run `python3 stub.py`:

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
   {"owner": "<b>tofu-poc</b>", "repo": "none", "confirm": true}
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
               result = await session.call_tool("delete-repository",
                   {"owner": "<b>tofu-poc</b>", "repo": "none", "confirm": True})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Error deleting repository: GitHub API resource not found: repos/<b>tofu-poc</b>/none`.

## Expected behavior
`owner` and `repo` are checked against GitHub's naming rules before any request is sent, and anything echoed back is encoded for the rendering context.

## Actual behavior
The values are echoed raw. From the fuzzing run:

```
Error deleting repository: GitHub API resource not found: repos/{{{{{{{{{{\x7f"": "\\u0000","repo": "po","confirm"\x7f:tru/po
```

## Impact
The LLM chooses `owner` and `repo`, and prompt injection can steer it. The echoed text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. Low severity for the echo. The unencoded path is the more important part of the same root cause: for a destructive tool, the caller can direct the DELETE request at a different API path under `repos/` (not tested).

## Suggested fix
Validate the inputs: `owner: z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/)`, `repo: z.string().regex(/^[A-Za-z0-9._-]{1,100}$/)`. Build paths with `encodeURIComponent(owner)` and `encodeURIComponent(repo)` in `api/repos/repository.ts`. Apply the same change to the other tools that take `owner` and `repo`.

## Status on the default branch
Still present at `86c8752` (2025-09-14). The tested commit is the current default branch head.

## Prior reports
- #5 "feat(cicd): Automate security scanning using CodeQL" (PR, closed 2025-04-08) and #14 "Potential fix for code scanning alert no. 6: Type confusion through parameter tampering" (PR, closed 2025-09-09): the only security PRs about the server's own code (the rest are dependency bumps, badges, docs, CI and features). #14 adds a type check on `sessionId` in the HTTP transport, not on `owner`/`repo` or tool replies. Any other CodeQL alerts live in the repository's Security tab, which is not in the fetched data. Neither fixes this.
- Documentation: README.md tool table lists `owner`: "Repository owner", `repo`: "Repository name" and `confirm`: "Confirmation (must be true)" for this tool. The confirm flag is the only documented safeguard; nothing on validation, encoding or untrusted input.
- No issue or PR reports unescaped output or unencoded API paths. Searched all 2 issues and 13 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: repo24-b 184320 exec / 54286 ok and 256512 / 55280 (4200 s each). Not seen in corpus-sbx or e2-0922.
- Evidence (verbatim, trimmed):
  - `{'owner': '{{{{{{{{{{\x7f"": "\\u0000","repo": "po","confirm"\x7f:tru', 'repo': 'po', 'confirm': True}` -> `Error deleting repository: GitHub API resource not found: repos/{{{{{{{{{{\x7f"": "\\u0000","repo": "po","confirm"\x7f:tru/po`
  - `{'owner': '{', 'repo': '\r$$$$...${\r\r/\ra\x19\r$$$$.../\r;;;;...', 'confirm': True}` -> `... not found: repos/{/\r$$$$...` (note the `/` inside `repo` landed in the path)
  - Third input of the same shape as the first.
- Hand-check hints: weak as XSS (only `{{` / `${` echoed into a plain-text reply; echo confirmed at `client.ts:127-128` and `index.ts:1151,1160`). The `<b>` payload and the stub are my substitutions and were not run. The run got real 404s, so the fuzz host could reach some GitHub API endpoint; I could not tell which. The stronger finding is the unencoded `owner`/`repo` in the API path of a destructive tool (`repository.ts:80-82`): e.g. `repo: "x/collaborators/y"` would send `DELETE repos/<owner>/x/collaborators/y`. That is from code reading only, not tested, and should probably be its own issue (CWE-20 / CWE-74). Do not test it against a real GitHub account. Note: `index.ts` prints startup lines to stdout on the stdio transport; the Python client may log parse warnings for them.
</details>
