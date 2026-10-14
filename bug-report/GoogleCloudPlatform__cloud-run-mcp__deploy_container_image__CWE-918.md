# `deploy_container_image` accepts any `imageUrl` string without validation (reported as SSRF; no server-side fetch found)

**Repository:** `GoogleCloudPlatform/cloud-run-mcp` · **Tool:** `deploy_container_image` · **Tested commit:** `560558a`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`deploy_container_image` deploys a container image to Cloud Run. The only check on `imageUrl` is that it is a non-empty string. Any value is copied into the Cloud Run service spec. A fuzzer flagged this as SSRF. From reading the code, the MCP server itself never opens a connection to `imageUrl`, so there is no classic SSRF from the server host. The remaining point is input validation and default exposure: the service is created with invoker IAM disabled unless `SKIP_IAM_CHECK=false`, so any image the model is steered into deploying is publicly invokable.

## Details
Schema and the only check, `tools/register-tools.js:574-578` and `:589-593`:

```js
        imageUrl: z
          .string()
          .describe(
            'The URL of the container image to deploy (e.g. "gcr.io/cloudrun/hello")'
          ),
...
        if (typeof imageUrl !== 'string' || imageUrl.trim() === '') {
          throw new Error(
            'Container image URL must be specified and be a non-empty string.'
          );
        }
```

The value goes unchanged into the service spec at `lib/deployment/deployer.js:98-101` (`containers = [{ image: imgUrl }]`). The spec is sent to the Cloud Run Admin API. The service is made public at `lib/deployment/deployer.js:119-122` when `skipIamCheck` is true, and `mcp-server.js:71` sets `skipIamCheck = process.env.SKIP_IAM_CHECK !== 'false'`, which defaults to true. I found no `fetch` or HTTP client call on `imageUrl` in `lib/` or `tools/`. Google's infrastructure pulls the image, not the MCP host.

## Steps to reproduce
1. Prerequisites: a test GCP project with billing, the Google Cloud SDK, and Application Default Credentials (`gcloud auth login`, then `gcloud auth application-default login`). Without credentials every tool returns the stub message from `tools/register-tools.js:38-50`.
2. In a separate terminal, start a local listener: `python3 -m http.server 8099 --bind 127.0.0.1`. Then start the server as the README describes: `npx -y @google-cloud/cloud-run-mcp`. To test the tested commit, run `npm install` in a checkout at `560558a`, then `node mcp-server.js`.
3. Call the tool, passing the listener's URL as `imageUrl`:

   ```json
   {"project": "<your-test-project>", "region": "europe-west1", "service": "tofu-poc", "imageUrl": "http://127.0.0.1:8099/tofu-poc"}
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
               result = await session.call_tool("deploy_container_image", {"project": "<your-test-project>", "region": "europe-west1", "service": "tofu-poc", "imageUrl": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Check the `http.server` log. Based on code reading, it should show **no** `GET /tofu-poc`, because the MCP server never fetches `imageUrl`. If a GET does appear, that would be a real SSRF and would need a different report. Separately, note that the value reaches the Cloud Run Admin API with no local validation, so any error comes from the API. Delete the `tofu-poc` service afterwards if one was created.

## Expected behavior
The tool rejects strings that are not container image references (a URL scheme, whitespace, control characters) before calling the API. Ideally it also restricts registries or asks for confirmation before deploying a public service.

## Actual behavior
Any non-empty string is forwarded to the Cloud Run API. In the fuzzing run, no GCP credentials were configured, so the handler never executed. Every logged call returned the credentials stub:

```
GCP credentials are not available. Please configure your environment using OAuth or `gcloud auth`.
```

## Impact
The model chooses `imageUrl`. Prompt injection in untrusted content (a README, an issue, a web page) can steer it toward an attacker's image. That image then runs in the user's project and, with default settings, accepts unauthenticated requests. This is the tool working as designed with no guard rails, not a request from the MCP host to an address the caller picks. Low severity, and it depends on whether the client asks the user to confirm tool calls.

## Suggested fix
- Validate `imageUrl` against the image-reference grammar (`[registry[:port]/]repository[:tag][@digest]`, no scheme, no whitespace or control characters) in the zod schema.
- Optionally support an allowlist of registries through an environment variable.
- Consider defaulting `SKIP_IAM_CHECK` to `false`, or say in the tool description that the deployed service will be public.

## Status on the default branch
Still present at `b3628fd` (2026-09-28). Between `560558a` and `b3628fd` only `.github/workflows/npm-publish.yml`, `package.json` and `package-lock.json` changed.

## Prior reports
- #171 "Deployment fails when Org Policy prohibits public endpoints" (issue, closed 2026-03-16): a user notes the MCP server cannot deploy with `--no-allow-unauthenticated`; same public-by-default behaviour this report lists under Impact. Not about `imageUrl` and not a fix.
- #63 "return the info when we can't create a public service and create a private one." (issue, closed 2026-03-20): confirms the server tries a public service first and falls back to private; design context only.
- No issue or PR about validating `imageUrl`, among all 82 issues and 230 pull requests (fetched 2026-10-01).
- Documentation: README.md: "This is `true` by default which is a recommended way to make the service public." (the `SKIP_IAM_CHECK` default is documented, so the public-service part is by design; the missing `imageUrl` check is not documented)
- Documentation: SECURITY.md: "To report a security issue, please use g.co/vulnz" (Google's intake, not a public issue)

<details>
<summary>Internal notes (remove before filing)</summary>

- **Do not file as a public issue.** `SECURITY.md` asks for security reports through g.co/vulnz. If this is filed at all, it should go as a hardening suggestion, not as a security report.
- ToFu class / sanitizers: ssrf (CWE-918). `check_strict_url_security_contract`, `check_url_structure_and_parsing`, `check_url_hostname_canonicalization` and `check_url_ssrf_ip_ranges` fired.
- Campaigns and executions: `corpus-sbx` 2560 executions / 2556 successful; `e2-0922` 1536 / 1532; 60 s budget each.
- Evidence (verbatim, trimmed):
  - input `{'project': '', 'region': '', 'service': '', 'imageUrl': ''}`, output ``GCP credentials are not available. Please configure your environment using OAuth or `gcloud auth`.``
  - input `{'project': 'test-project', 'region': 'europe-west1', 'service': 'myservice', 'imageUrl': '/etc/passwd\x00'}`, same output.
- Hand-check hints: **weak, likely a false positive for SSRF**. All three evidence outputs are the `gcpTool` stub (`tools/register-tools.js:38-50`), so ToFu never reached the real handler. It ran without GCP credentials, so probably every call hit the stub. ToFu's "accepted" verdict is an artifact of that stub. With credentials, the empty `imageUrl` case would be rejected at `:589-593`. The server never fetches `imageUrl`. I did not verify the Cloud Run API's error text for a malformed image, so step 4 does not quote it. The only defensible content is "no format validation + public by default".
- The repro uses the local `http.server` listener from the updated SSRF instructions. The expected result is a negative (no GET), which I derived from code reading and did not observe. If the hand-checker sees no GET, that confirms this is not SSRF; drop the draft or re-file it as a hardening note.
</details>
