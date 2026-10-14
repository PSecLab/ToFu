# Missing output encoding and validation in `update-connection-settings`: `url` is accepted as any string and echoed raw

**Repository:** `meilisearch/meilisearch-mcp` · **Tool:** `update-connection-settings` · **Tested commit:** `b764c9f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`update-connection-settings` replaces the Meilisearch URL and API key that every other tool uses. It accepts any string as `url`, rebuilds the client, and returns `Successfully updated connection settings to URL: <url>` with the value inserted unchanged. The reflected text itself has low impact. The more important part is the missing validation: there is no scheme or host check, and the value is also logged raw.

## Details
`src/meilisearch_mcp/server.py:95-103`:

```python
        @mcp.tool(name="update-connection-settings", annotations=WRITE)
        def update_connection_settings(
            url: Optional[str] = None, api_key: Optional[str] = None
        ) -> CallToolResult:
            """Update Meilisearch connection settings"""
            self.update_connection(url, api_key)
            return _result(
                f"Successfully updated connection settings to URL: {self.url}"
            )
```

`update_connection` (`src/meilisearch_mcp/server.py:71-82`) stores the value and builds a new `MeilisearchClient(self.url, self.api_key)` (`src/meilisearch_mcp/client.py:17-26`), with no check of scheme, host or characters. It then logs `logger.info(f"Updated Meilisearch connection settings: url={self.url}")` (`server.py:82`) to stderr (`server.py:423`). If `api_key` is omitted, the previous key is kept (`server.py:77-78`). So the existing key stays attached to whatever URL was just set.

## Steps to reproduce
1. Prerequisites: Python and `uv` (or `pip`). No running Meilisearch instance is needed for this tool, and no environment variables are needed.
2. Start the server as the README describes: `uvx -n meilisearch-mcp`. To test the tested commit, run `pip install -e .` in a checkout at `b764c9f`, then `meilisearch-mcp`.
3. Call the tool:

   ```json
   {"url": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["-n", "meilisearch-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("update-connection-settings", {"url": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is `Successfully updated connection settings to URL: <b>tofu-poc</b>`. The value was accepted as a URL and is echoed with the markup unchanged. A follow-up `get-connection-settings` call shows it is now the active URL.

## Expected behavior
The tool rejects values that are not `http://` or `https://` URLs with a host. It does not echo raw markup, and it neutralizes CR/LF before logging.

## Actual behavior
Any string is accepted and echoed. From the fuzzing run:

```
input:  {'url': '${urmmmm', 'api_key': 'mmmm'}
output: 'Successfully updated connection settings to URL: ${urmmmm'
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content (for example, a document being indexed) can steer them. The echoed URL is plain text, so the reflection alone is low severity. The missing validation matters more. A steered call can point the server at any host, and every later tool call (search, document reads, key management) then sends its requests there with the configured API key. That can leak the key and redirect data to a host the user did not choose.

## Suggested fix
- Parse `url` with `urllib.parse.urlsplit`. Require scheme `http` or `https` and a non-empty hostname, and reject control characters.
- Consider requiring the API key to be supplied again whenever the host changes, so an existing key is not silently reused for a new host. Optionally, support an operator-configured allowlist of hosts.
- Log the URL with `%r` (or strip `\r` and `\n`), and keep the echoed URL out of the success message, or return it in structured content only.

## Status on the default branch
Still present at `b764c9f` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
- #56 "Update README.md to add security clarification" (PR, closed 2025-11-24): body says "We aren't following MCP best practice - this is clarified in the PR". It adds README text, not code; it does not mention URL validation, the echoed URL, or the reused API key. The fetched data does not show whether it was merged, but the default-branch README carries the note quoted below.
- #7 "Add dynamic connection tooling" (PR, closed 2024-12-26): introduced the connection-switching tools; its body is an empty template and says nothing about validation.
- Documentation: README.md, "Security" section: "While you can add and update hosts and API keys directly in chat for convenience, this approach is primarily designed for development use cases" and "It does not follow best MCP security practices and should not be used in production environments without proper safeguards." (the maintainers document in-chat host switching as a known, development-only risk; the missing URL check and key reuse fall under this note, the raw echo of the URL does not).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: not fixed, but known. The README security note (apparently from PR #56) documents in-chat host and key changes as dev-only and outside MCP security practice, so expect a by-design answer on the URL part.
- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on `${`. Also fired: `check_strict_url_security_contract`, `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`, `check_url_alternative_ip_representations`, `check_introspection_log_injection`.
- Campaigns and executions: `corpus-sbx`, 3072 executions, 3068 successful, 60 s budget.
- Evidence (verbatim): input `{'url': '${urmmmm', 'api_key': 'mmmm'}` (also with `api_key` `'\x00\x10mm'` and `'\U000d1000'`), output `'Successfully updated connection settings to URL: ${urmmmm'`.
- Hand-check hints: **weak as CWE-79**. `${` echoed into a plain-text message is not XSS. The real content of this item is the missing URL validation plus the reuse of the existing API key (an SSRF / credential-forwarding concern, CWE-918). It probably deserves its own SSRF draft with a local `http.server` listener repro. I did not write one here because it is outside this item's class. I did not verify that the `meilisearch` Python client sends the key as an `Authorization: Bearer` header on every request; check that against the installed client before filing. The `server.py:82` log line is a minor CWE-117 issue (stderr only).
- Note: this tool is annotated `WRITE` (not destructive), so clients that auto-approve non-destructive tools may run it without asking.
</details>
