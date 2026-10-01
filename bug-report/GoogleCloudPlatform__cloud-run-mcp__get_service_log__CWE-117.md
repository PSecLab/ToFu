# Log injection in `get_service_log`: CR/LF in `service`, `project` or `region` forges server log lines

**Repository:** `GoogleCloudPlatform/cloud-run-mcp` · **Tool:** `get_service_log` · **Tested commit:** `560558a`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_service_log` fetches Cloud Logging entries for a Cloud Run service. Before it queries the API, it writes the caller's `service`, `project` and `region` into a `console.log` template string with no neutralization. A value containing CR/LF starts a new line that looks like a separate server log entry. In stdio mode the line goes to stderr, which the MCP client usually saves to its log file. In HTTP mode (for example when the server itself runs on Cloud Run, as the README describes) it goes to stdout, which the platform ingests as log entries.

## Details
`lib/cloud-api/run.js:139-146`:

```js
    const filter = `resource.type="cloud_run_revision"
                    resource.labels.service_name="${serviceId}"
                    resource.labels.location="${location}"
                    severity>=${LOG_SEVERITY}`;

    console.log(
      `Fetching logs for Cloud Run service ${serviceId} in project ${projectId}, location ${location}...`
    );
```

The handler at `tools/register-tools.js:309-323` passes `project`, `region` and `service` straight from the tool arguments. The zod schema only requires strings (`tools/register-tools.js:295-306`). The log line runs before any network call: `getLoggingClient` (`lib/clients.js:236-245`, `:99-122`) only constructs a client. In stdio mode, `mcp-server.js:51-54` and `:63-64` redirect `console.log` to `console.error`. In HTTP mode, `console.log` writes to stdout. The error path at `lib/cloud-api/run.js:176-179` also logs `serviceId` raw.

## Steps to reproduce
1. Prerequisites: the Google Cloud SDK and Application Default Credentials (`gcloud auth login`, then `gcloud auth application-default login`), so that the server registers the real handler and not the credentials stub (`tools/register-tools.js:38-50`). Any project ID you can read works. The service does not need to exist.
2. Start the server as the README describes: `npx -y @google-cloud/cloud-run-mcp`. To test the tested commit, run `npm install` in a checkout at `560558a`, then `node mcp-server.js`.
3. Call the tool:

   ```json
   {"project": "<your-test-project>", "region": "europe-west1", "service": "tofu-poc\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "@google-cloud/cloud-run-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_service_log", {"project": "<your-test-project>", "region": "europe-west1", "service": "tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr, which the Python client forwards to your terminal by default. The single log call prints two lines, and the second one begins with the injected text:

   ```
   Fetching logs for Cloud Run service tofu-poc
   FAKE-LOG-ENTRY in project <your-test-project>, location europe-west1...
   ```

## Expected behavior
CR, LF and other control characters in tool arguments are escaped or rejected before they reach a log line. One call produces one log line.

## Actual behavior
By code reading, the argument is written into the log line unchanged (see the excerpt above). The fuzzing run did not reach this code. No GCP credentials were configured, so every logged call returned the credentials stub:

```
GCP credentials are not available. Please configure your environment using OAuth or `gcloud auth`.
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content can steer them. An attacker who controls them can add fake lines to the MCP server's log, either in the client's log file or in Cloud Logging for a hosted server. That can mislead whoever reads those logs during debugging or incident review. Low severity.

The same `service` and `region` values are also placed inside double quotes in the Cloud Logging filter (`lib/cloud-api/run.js:139-142`). A `"` in the value closes the quoted string and adds filter terms. The query can then return log entries other than the named Cloud Run service's, within whatever the credentials can read.

## Suggested fix
- Validate `project`, `region` and `service` in the zod schema against the GCP naming rules (lowercase letters, digits and hyphens). That fixes both the log line and the filter.
- Independently, log untrusted values with `JSON.stringify(value)`, or strip `\r` and `\n`, so a value cannot start a new line.

## Status on the default branch
Still present at `b3628fd` (2026-09-28). Between `560558a` and `b3628fd` only `.github/workflows/npm-publish.yml`, `package.json` and `package-lock.json` changed.

## Prior reports
- #212 "feat: add optional filtering parameters to get_service_log tool" (PR, open 2026-01-27) and #213 "[FEATURE]: add optional filtering parameters to get_service_log tool" (issue, open 2026-01-30): extend the same Cloud Logging filter with new parameters to save API quota. Neither body mentions escaping `service` / `region` or the `console.log` line, so they would not fix this.
- No issue or PR about log injection or filter quoting, among all 82 issues and 230 pull requests (fetched 2026-10-01).
- Documentation: SECURITY.md: "To report a security issue, please use g.co/vulnz" (Google's intake, not a public issue)

<details>
<summary>Internal notes (remove before filing)</summary>

- **Do not file as a public issue.** `SECURITY.md` asks for security reports through g.co/vulnz. That said, log injection is low severity, and Google may accept it as a normal bug.
- ToFu class / sanitizers: log-injection (CWE-117). Only `check_log_injection` fired.
- Campaigns and executions: `corpus-sbx` 2048 executions / 2040 successful; `e2-0922` 1536 / 1528; 60 s budget each.
- Evidence (verbatim, trimmed): inputs `{'project': 'my-gcp-project', 'region': 'europe-west1', 'service': 'myservice\nINJECTED_LOG_ENTRY'}`, `{..., 'service': 'myservice\r\n2024-01-01 00:00:00 ERROR: Sensitive info leaked'}` and `{'project': '\x00\x00[...]\r\x00', 'region': '', 'service': ''}`. Every output was ``GCP credentials are not available. Please configure your environment using OAuth or `gcloud auth`.``
- Hand-check hints: **real by code reading, low severity, and not demonstrated by the fuzz run**. ToFu only saw the `gcpTool` stub (`tools/register-tools.js:38-50`), so its alert proves nothing by itself. The sink at `lib/cloud-api/run.js:144-146` is unambiguous and runs before any API call. The expected stderr in step 4 is derived from the template string. I have not observed it, and it needs a credentialed run. The filter-quote issue at `run.js:139-142` (CWE-943-ish) is also from code reading only. `run.js:154` logs `JSON.stringify(options)`, which is escaped and safe.
</details>
