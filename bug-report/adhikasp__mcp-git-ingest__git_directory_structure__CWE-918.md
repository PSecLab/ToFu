# SSRF in `git_directory_structure`: `repo_url` is cloned with no restriction on the destination

**Repository:** `adhikasp/mcp-git-ingest` · **Tool:** `git_directory_structure` · **Tested commit:** `cd392d5`
**Weakness:** CWE-918 Server-Side Request Forgery

## Summary
`git_directory_structure` clones a caller-supplied `repo_url` and returns the directory tree. The URL is passed straight to `git clone` with no scheme allow-list and no check on the destination host. `git` will fetch `http(s)://`, `git://`, `ssh://` and `file://` targets, so the caller controls where the server connects. There is no restriction preventing a request to a host on the server's own network. Report so a maintainer can add a destination check.

## Details
`src/mcp_git_ingest/main.py:68-88` is the tool; it calls `clone_repo`, `src/mcp_git_ingest/main.py:20-44`:

```python
def clone_repo(repo_url: str) -> str:
    repo_hash = hashlib.sha256(repo_url.encode()).hexdigest()[:12]
    temp_dir = os.path.join(tempfile.gettempdir(), f"github_tools_{repo_hash}")
    ...
    os.makedirs(temp_dir, exist_ok=True)
    try:
        git.Repo.clone_from(repo_url, temp_dir)
        return temp_dir
```

`repo_url` reaches `git.Repo.clone_from` with no parsing, no scheme check and no host check. Nothing limits the clone to `github.com` or to public hosts, despite the tool's GitHub framing.

## Steps to reproduce
1. Prerequisites: Python 3.8+, `git` on PATH. No account needed.
2. Install and start as the README describes: `uvx --from git+https://github.com/adhikasp/mcp-git-ingest mcp-git-ingest`.
3. In another terminal, start a local listener the clone will hit:

   ```
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
4. Call the tool with a URL pointing at that listener:

   ```json
   {"repo_url": "http://127.0.0.1:8099/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx",
           args=["--from", "git+https://github.com/adhikasp/mcp-git-ingest", "mcp-git-ingest"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("git_directory_structure",
                   {"repo_url": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
5. What to observe: a `GET /tofu-poc/info/refs?service=git-upload-pack` request in the `http.server` log. That request proves the server connected to the caller-chosen address. The clone then fails (the listener is not a git server); reaching the listener is the point, not a successful clone.

## Expected behavior
The server restricts clone targets, for example to an allow-list of schemes (`https`) and hosts (`github.com`), and rejects anything else before calling `git`.

## Actual behavior
The URL is cloned as given. In the fuzzing run the inputs were an empty string and a null-byte string, which failed in `git` with the errors below, so the run does not by itself show a connection to another host; the missing restriction is visible in the code and in step 5.

```
Error: Failed to clone repository: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v --  /tmp/github_tools_e3b0c44298fc
  stderr: 'fatal: repository '' does not exist'
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. Because the clone destination is unrestricted, a caller can make the server open a connection to an address of their choosing, including hosts that are only reachable from the server itself and not from the caller. Whether any such host exists depends on where the server runs. The `file://` scheme also lets the clone target the local filesystem.

## Suggested fix
Parse `repo_url` and accept only an explicit scheme/host allow-list (for example `https` to `github.com`) before cloning. Reject `file://`, `ssh://` and `git://`, and reject hosts that resolve to private, loopback or link-local addresses. Pass `--` and a validated URL, and consider `GIT_ALLOW_PROTOCOL` to constrain git's own protocol handling.

## Status on the default branch
Still present at `cd392d5` (2025-01-26). This is the tested commit and the current default-branch head; `clone_repo` is unchanged.

## Prior reports
None found. Searched all 7 issues and 8 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The README only describes the server as reading "GitHub repository structure and important files"; it has no security notes and no setting that limits clone targets or file paths.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_resource_exhaustion`, `check_strict_url_security_contract`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: `corpus-sbx` 1,536/1,534 and `e2-0922` 1,024/1,015, 60 s each.
- Evidence (verbatim, trimmed): `{'repo_url': ''}` -> `Error: Failed to clone repository: ... fatal: repository '' does not exist`; `{'repo_url': '/etc/passwd\x00'}` -> `Error: Failed to clone repository: embedded null byte`. ToFu flags these as "validation bypass / silent bug" (sanitizer flagged, tool returned an error string instead of raising).
- Hand-check hints: real code gap, evidence weak. `git.Repo.clone_from(repo_url, ...)` with no scheme/host restriction is a textbook SSRF primitive; the evidence inputs were malformed and only produced git errors, so they do not themselves demonstrate an outbound connection. Step 5 (local listener) demonstrates reachability without touching any real internal service. Per coordinator instruction, repro uses only a locally started 127.0.0.1 listener; internal/metadata addresses are described in general terms in Impact only. `git_read_important_files` shares `clone_repo` and has the same SSRF gap plus a separate path-traversal gap (reported separately).
</details>
