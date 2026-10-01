# `profile_papers`: loose host check on `profile_url` and unencoded ID in OpenAlex request URLs (no SSRF to the given URL)

**Repository:** `renyumeng1/mcp_scholar` · **Tool:** `profile_papers` · **Tested commit:** `5e12e93`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`profile_papers` takes a scholar profile URL, extracts an author ID from it and queries OpenAlex. Our fuzzer flagged it for SSRF, but the server never connects to the URL the caller passes: requests only go to the fixed hosts `api.openalex.org` and `scholar.google.com`. What remains is a hardening issue: the host check is a substring test, and the extracted ID is concatenated into the OpenAlex request URL without validation or encoding, so a caller can add path segments or query parameters to requests sent to OpenAlex.

## Details
`src/mcp_scholar/scholar.py:524-529` (`extract_profile_id_from_url`) checks the host with a substring test and keeps everything after `/authors/`:
```python
    if "openalex.org/authors/" in url:
        # 格式: https://openalex.org/authors/A[ID]
        parts = url.split("/authors/")
        if len(parts) > 1:
            author_id = parts[1].strip()
            return author_id  # 返回带A前缀的ID
```
The ORCID branch (`:532-540`) and the Google Scholar branch (`:543-547`, `re.search(r"user=([^&]+)", url)`) work the same way. Any URL containing these substrings is accepted, wherever it points.

`src/mcp_scholar/scholar.py:586-592` (`parse_profile`) then builds the request URL by string concatenation:
```python
        if not openalex_id.startswith("A"):
            openalex_id = f"A{openalex_id}"

        # 获取作者信息
        async with httpx.AsyncClient(timeout=15.0) as client:
            author_url = f"{OPENALEX_API}/authors/{openalex_id}{email_param}"
            author_response = await client.get(author_url)
```
`OPENALEX_API` is the constant `https://api.openalex.org` (`scholar.py:43`), so the host cannot change. Characters such as `?`, `&`, `#` and `/` in the ID do change the path and query of the request to OpenAlex. The Google Scholar branch passes its ID into `https://scholar.google.com/citations?user={google_id}` (`scholar.py:472`) in the same way.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No API key. Copy `.env.example` to `.env` in the repository root.
2. Start a local listener in a separate terminal:
   ```bash
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
   Start the server as the README describes (the client script below starts it for you):
   ```bash
   git clone https://github.com/renyumeng1/mcp_scholar && cd mcp_scholar
   git checkout 5e12e93
   cp .env.example .env
   uv --directory . run mcp-scholar
   ```
3. Call the tool with these arguments:
   ```json
   {"profile_url": "http://127.0.0.1:8099/tofu-poc", "count": 5, "sort_by": "relevance"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["--directory", "/path/to/mcp_scholar", "run", "mcp-scholar"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("profile_papers", {
                   "profile_url": "http://127.0.0.1:8099/tofu-poc", "count": 5, "sort_by": "relevance",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe that the listener logs no `GET /tofu-poc`. The tool returns an error because the URL contains none of the expected substrings.

## Expected behavior
Only URLs whose parsed hostname is one of the supported profile hosts are accepted. The extracted ID is validated against the expected format and encoded before it is placed in a request URL.

## Actual behavior
No request reaches the caller's URL. For every URL without the expected substrings the tool returns, as in the fuzzing run:
```
{"status": "error", "message": "\u65e0\u6cd5\u4eceURL\u4e2d\u63d0\u53d6\u5b66\u8005ID"}
```
("could not extract a scholar ID from the URL"). URLs that do contain the substrings are accepted no matter which host they name, and the ID from them is sent unencoded to OpenAlex, as shown in Details.

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. The caller cannot make the server contact a host of their choice through this tool, so the usual SSRF risk (reaching internal services from the server's network position) does not apply. The caller can only alter the path and query of requests that go to OpenAlex or Google Scholar anyway.

## Suggested fix
Parse the URL with `urllib.parse.urlsplit`, require `hostname` to be exactly `openalex.org`, `orcid.org` or `scholar.google.com`, and validate the extracted ID before use (OpenAlex author `^A\d+$`, ORCID `^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`, Google Scholar `user` as `^[A-Za-z0-9_-]+$`). Build request URLs with `urllib.parse.quote(openalex_id, safe="")`, or pass query values through `httpx`'s `params=` argument instead of concatenating strings.

## Status on the default branch
Still present at `5e12e93` (2025-03-22). The tested commit is the current default branch head.

## Prior reports
- No issue or PR reports the substring host check or the unencoded author ID. The repository has 0 issues and 1 pull request (fetched 2026-10-01); the README on the default branch has no security notes and only shows a `https://scholar.google.com/citations?user=xxxxxx` profile example.
- #1 "Fix OpenAlex URL construction bugs: DOI double-prefix, duplicate filter params, malformed mailto" (PR, open 2026-04-02): fixes the `?`/`&` prefix of `mailto` in `parse_profile`'s `papers_url`, the same string-built URL code; it does not validate or encode `openalex_id` or tighten `extract_profile_id_from_url`. Not a fix, and not merged.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf. Evidence calls fired `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`. Tool-level triggered set also includes `check_url_alternative_ip_representations` and `check_introspection_log_injection` (the `logger.info` at `server.py:393` logs the raw `profile_url`).
- Campaigns and executions: `corpus-sbx` 3584 exec / 3574 success (60 s); `e2-0922` 512 exec / 506 success (60 s).
- Evidence (verbatim, trimmed): input `{'profile_url': '', 'count': 0, 'sort_by': ''}`; output `'{"status": "error", "message": "\\u65e0\\u6cd5\\u4eceURL\\u4e2d\\u63d0\\u53d6\\u5b66\\u8005ID"}'`; analysis "Silent Bug Alert: Sanitizers [...] flagged this input as malicious, but the target tool executed successfully without raising any exception." The other two evidence inputs (a loopback URL and a `file:` URL) got the identical error response.
- Hand-check hints: weak, SSRF not confirmed. The alerts are input-side URL heuristics ("Silent Bug Alert"): ToFu judged the input string, and the tool returned "could not extract ID" without any request. Code reading confirms the host is the constant `https://api.openalex.org` (or `https://scholar.google.com`), so a classic SSRF is not possible here. Recommend not filing as SSRF. At most, file as a low-priority hardening note (substring host check, unencoded ID). Not run. Per the coordinator's update, the reproduction only uses a local listener, and there is no demo of the OpenAlex query manipulation because that would need a request to the public API. Side bug for the maintainer, if filed: the ORCID branch returns `orcid:<id>`, and `parse_profile` then prefixes `A` (`scholar.py:586-587`), producing `Aorcid:<id>`, so ORCID profile URLs probably never resolve.
</details>
