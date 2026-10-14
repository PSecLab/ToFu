# Log injection in `GetObject`: `bucket_name`/`key` logged unneutralized before validation

**Repository:** `aws-samples/sample-mcp-server-s3` · **Tool:** `GetObject` · **Tested commit:** `b215bed`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`GetObject` fetches an object from S3. Before any validation, it logs the caller-supplied `bucket_name` and `key` via the standard library logger. The values are not neutralized, so CR/LF characters in `bucket_name` or `key` are written into the log output and can forge or corrupt log lines.

## Details
The first statement in `get_object` logs the raw inputs (`src/s3_mcp_server/resources/s3_resource.py:127`):

```python
async def get_object(self, bucket_name: str, key: str, max_retries: int = 3) -> Dict[str, Any]:
    logger.info(f"s3_resource.get_object received bucket {bucket_name}, key {key}")
    if self.configured_buckets and bucket_name not in self.configured_buckets:
        raise ValueError(f"get_object failed! Bucket {bucket_name} not in configured bucket list")
```

The logger is the module logger writing at INFO/DEBUG to the root handler (`server.py:26`, `__init__.py:8`). The log call happens before the bucket-allowlist check, so even rejected buckets are logged with their raw (attacker-controlled) names.

## Steps to reproduce
1. Prerequisites: UV, Python 3.12+, AWS credentials, and `S3_BUCKETS` set to at least one bucket name. Logging is enabled by the package entry point (`logging.basicConfig(level=logging.DEBUG)`).
2. Start the server as the README describes:
   ```json
   { "command": "uvx", "args": ["s3-mcp-server"], "env": { "S3_BUCKETS": "mybucket", "AWS_REGION": "us-east-1" } }
   ```
3. Call the tool with CR/LF in `bucket_name`. Arguments as JSON:
   ```json
   {"bucket_name": "mybucket\r\nFAKE-LOG-ENTRY", "key": "x"}
   ```
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["s3-mcp-server"],
                                      env={"S3_BUCKETS": "mybucket", "AWS_REGION": "us-east-1"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("GetObject", {"bucket_name": "mybucket\r\nFAKE-LOG-ENTRY", "key": "x"})
               print(result)

   asyncio.run(main())
   ```
4. Inspect the server's log output. The `s3_resource.get_object received bucket ...` line contains the injected `\r\nFAKE-LOG-ENTRY`, appearing as a separate line.

## Expected behavior
Caller input written to logs should have CR/LF (and other control characters) stripped or escaped so it cannot forge log entries.

## Actual behavior
The raw value is logged. From the fuzz evidence (ToFu's runtime tracer captured the logged string):

```
Introspection Log Injection Alert (CWE-117): Unneutralized CRLF newline character detected in log output (logger:s3_mcp_server)!
Logged content: 's3_resource.get_object received bucket \r\r\r, key '.
```

## Impact
MCP tool arguments are LLM-controlled and steerable by prompt injection. An attacker who influences `bucket_name` or `key` can inject newlines into the server's logs, forging entries or splitting lines to hide activity or confuse log-based monitoring. Severity is moderate and depends on how logs are consumed.

## Suggested fix
Sanitize `bucket_name` and `key` before logging: strip or escape `\r` and `\n` (for example `value.replace("\r", "\\r").replace("\n", "\\n")`), or log via a formatter that escapes control characters. Validate the bucket against the allowlist before logging.

## Status on the default branch
Still present at `b215bed` (2025-12-09). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
- No issue or pull request covers this. Searched all 4 issues and 6 pull requests (fetched 2026-10-01).
- Documentation: CONTRIBUTING.md (linked from the README "Security" section): "If you discover a potential security issue in this project we ask that you notify AWS/Amazon Security via our vulnerability reporting page" and "Please do **not** create a public github issue." (nothing documents the logging behaviour; this is the repository's reporting policy, so this draft should go to AWS Security rather than to a public issue).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); triggered `check_introspection_log_injection` (runtime tracer observed the logged string). Campaigns: corpus-sbx (3072/3072), e2-0922 (1536/1536).
- Evidence (verbatim, trimmed): input `{'bucket_name': '\r\r\r', 'key': '', 'max_retries': ''}` → tracer logged `s3_resource.get_object received bucket \r\r\r, key `. The returned error `'<' not supported between instances of 'int' and 'str'` is a separate bug (empty `max_retries` string compared with int in the retry loop) and not the log-injection itself.
- Hand-check hints: REAL. `logger.info` on line 127 receives raw caller input before validation; CRLF confirmed in log output by the tracer. Note evidence shows `\r` only (CR), no LF — still a log-injection condition. Clean repro uses `\r\n`.
</details>
