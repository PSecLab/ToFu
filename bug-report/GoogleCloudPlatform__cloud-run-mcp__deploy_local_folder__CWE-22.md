# No path restriction in `deploy_local_folder`: any readable file or directory is archived and uploaded to Cloud Storage

**Repository:** `GoogleCloudPlatform/cloud-run-mcp` · **Tool:** `deploy_local_folder` · **Tested commit:** `560558a`
**Weakness:** CWE-22 Path Traversal

## Summary
`deploy_local_folder` takes an absolute path, archives its content, uploads the archive to `gs://<project>-source-bucket`, and builds and deploys it to Cloud Run. The handler only checks that `folderPath` is a non-empty string. There is no allowed root such as the client's workspace, and single files are accepted as well as folders. Any file or directory readable by the server's user, including credential directories, can be uploaded to the caller-chosen project. With default settings, the resulting service accepts unauthenticated requests.

## Details
`tools/register-tools.js:400-404` rejects only empty strings. `deploy()` (`lib/deployment/deployer.js:510-613`) passes `[folderPath]` either to `deployWithZip` or to `deployWithBuild`. `deployWithBuild` (`lib/deployment/deployer.js:431-449`) creates the bucket, archives the files and uploads `source.zip` before Cloud Build runs. The archiving step is `lib/util/archive.js:86-96`:

```js
        const filePath = path.resolve(pathInput);
        if (!fs.existsSync(filePath)) {
          throw new Error(`File or directory not found: ${filePath}`);
        }

        const stats = fs.statSync(filePath);
        if (stats.isDirectory()) {
          archive.directory(filePath, false);
        } else {
          archive.file(filePath, { name: path.basename(filePath) });
        }
```

The path is resolved but never compared against any allowed directory. The zip-deploy branch copies the path in the same unchecked way (`lib/deployment/source-processor.js:47-55`). The service is created with `invokerIamDisabled = true` (`lib/deployment/deployer.js:119-122`) whenever `SKIP_IAM_CHECK` is not `false` (`mcp-server.js:71`).

## Steps to reproduce
1. Prerequisites: a test GCP project with billing, the Google Cloud SDK, and Application Default Credentials (`gcloud auth login`, then `gcloud auth application-default login`). Without credentials every tool returns the stub from `tools/register-tools.js:38-50`.
2. Start the server as the README describes: `npx -y @google-cloud/cloud-run-mcp`. To test the tested commit, run `npm install` in a checkout at `560558a`, then `node mcp-server.js`.
3. Call the tool with a single file outside any project folder. This uses `/etc/hostname` on Linux. On macOS, first run `echo tofu-poc > /tmp/tofu-poc.txt` and pass that path instead.

   ```json
   {"project": "<your-test-project>", "region": "europe-west1", "service": "tofu-poc", "folderPath": "/etc/hostname"}
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
               result = await session.call_tool("deploy_local_folder", {"project": "<your-test-project>", "region": "europe-west1", "service": "tofu-poc", "folderPath": "/etc/hostname"})
               print(result)

   asyncio.run(main())
   ```
4. The build is expected to fail, because there is no app to build. Then run `gcloud storage cp gs://<your-test-project>-source-bucket/source.zip . && unzip -l source.zip`. The archive contains `hostname`, the content of the host's `/etc/hostname`. Delete the object and any `tofu-poc` service afterwards.

## Expected behavior
The tool accepts only directories under an allowed root: the client's workspace roots, or a directory set by the operator. It rejects single files and paths outside that root.

## Actual behavior
Any existing path is archived and uploaded. In the fuzzing run, no GCP credentials were configured, so every logged call returned the credentials stub before the handler ran:

```
GCP credentials are not available. Please configure your environment using OAuth or `gcloud auth`.
```

## Impact
The model chooses `folderPath`, and prompt injection in untrusted content (a README, an issue, a web page) can steer it. A steered agent can upload files the user never meant to deploy, such as `~/.ssh` or `~/.config/gcloud`, to a bucket in the user's own project. It can also build them into a service that, by default, needs no authentication. The upload goes to the user's project, not directly to the attacker. Exposure to a third party needs a further step, such as the deployed service serving those files. Low to moderate severity.

## Suggested fix
- Resolve the path with `fs.realpathSync`, require a directory, and reject it unless it is inside an allowed root. Use the roots the MCP client advertises, or a configured `ALLOWED_DEPLOY_ROOTS` list.
- Refuse well-known credential locations (home directory itself, `~/.ssh`, `~/.config/gcloud`, `~/.aws`) even inside an allowed root.
- Consider defaulting `SKIP_IAM_CHECK` to `false`, or state in the tool description that the deployed service will be public.

## Status on the default branch
Still present at `b3628fd` (2026-09-28). Between `560558a` and `b3628fd` only `.github/workflows/npm-publish.yml`, `package.json` and `package-lock.json` changed.

## Prior reports
- #278 "fix: prevent shell injection in deployment file operations" (PR, closed 2026-08-18): reports that user-controlled file paths are interpolated into `exec('cp -R ...')` in `lib/deployment/source-processor.js`, the zip-deploy copy this report cites. It was closed without the change landing (the default branch still runs `exec` with `cp -R` at line 51), and it adds no allowed-root check, so it would not fix this.
- #171 "Deployment fails when Org Policy prohibits public endpoints" (issue, closed 2026-03-16): a user notes `deploy_local_folder` cannot deploy with `--no-allow-unauthenticated`; same public-by-default behaviour this report lists under Impact. Not about the path.
- No issue or PR about restricting `folderPath`, among all 82 issues and 230 pull requests (fetched 2026-10-01).
- Documentation: README.md: "only available when running locally" (footnote on `deploy-local-folder`; the tool is not offered by the remote server)
- Documentation: README.md: "This is `true` by default which is a recommended way to make the service public." (the `SKIP_IAM_CHECK` default is documented; no text limits which folders may be deployed)
- Documentation: SECURITY.md: "To report a security issue, please use g.co/vulnz" (Google's intake, not a public issue)

<details>
<summary>Internal notes (remove before filing)</summary>

- **Do not file as a public issue.** `SECURITY.md` asks for security reports through g.co/vulnz.
- ToFu class / sanitizers: path-traversal (CWE-22). Only `check_path_traversal` fired.
- Campaigns and executions: `corpus-sbx` 2048 executions / 2048 successful; `e2-0922` 1536 / 1536; 60 s budget each.
- Evidence (verbatim, trimmed): inputs `{'project': 'test-project', 'region': 'europe-west1', 'service': 'myservice', 'folderPath': '../../../../etc/passwd'}`, `{..., 'folderPath': '/etc/passwd\x00'}` and `{..., 'folderPath': '..\\..\\..\\..\\windows\\win.ini'}`. Every output was ``GCP credentials are not available. Please configure your environment using OAuth or `gcloud auth`.``
- Hand-check hints: **weak as reported, real-ish by design**. ToFu never reached the handler: every evidence output is the `gcpTool` stub (`tools/register-tools.js:38-50`), and its "Silent Bug" verdict comes from that stub. The tool is documented to take "an absolute folder path from the local filesystem", so there is no root to traverse out of. This is a missing allowlist, not a traversal. The single-file upload and the public-by-default service come from code reading. I did not run them. Step 4's object name `source.zip` comes from `lib/deployment/constants.js:19`.
- **Separate, possibly more serious finding (not reported here, verify before filing anything):** `lib/deployment/source-processor.js:51` runs ``execAsync(`cp -R "${file}/." "${tempDir}/"`)``, with `file` being the caller's `folderPath` and `tempDir` built from `path.basename(folderPath)`. Inside double quotes the shell still expands `$(...)`, backticks and `"`. That is a CWE-78 candidate on the zip-deploy branch (a Node or Python folder without a Dockerfile). The precondition is that `fs.stat` succeeds on the path, so the crafted directory name must exist, for example in a cloned repo. Not exercised by ToFu. If confirmed, it should go to g.co/vulnz as its own report.
- Side observation: `lib/util/archive.js:83-85` rewrites every path that starts with `/c` to `/mnt/c...` (a WSL hack). So on Linux, `/code/app` or `/config/x` becomes `/mnt/code/app` and fails. Functional bug.
</details>
