# Log injection via `featureName` from `start_feature_clarification`: CR/LF reaches `console.log` unneutralized in the legacy `src/index.ts` server

**Repository:** `crazyrabbitLTC/mcp-vibecoder` · **Tool:** `start_feature_clarification` · **Tested commit:** `5e218b0`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`start_feature_clarification` accepts any `featureName` of 2 to 100 characters and any `initialDescription`, including CR, LF and other control characters. In the built server (`build/mcp-server.js`) this tool does not log either value. The legacy `src/index.ts` server, which is still in the repository, stores the feature and later prints `feature.name` with `console.log` from `provide_clarification` with no neutralization, so a name containing `\r\n` writes a forged extra log line. That handler also logs `question` and `answer` raw, and `console.log` goes to stdout, which is the JSON-RPC channel in stdio mode.

## Details
Built server, `src/mcp-server.ts:297-317` at `5e218b0`: the schema is only `z.string().min(2).max(100)` and nothing is logged:

```ts
  "start_feature_clarification",
  {
    featureName: z.string().min(2).max(100),
    initialDescription: z.string().optional().default("")
  },
  async ({ featureName, initialDescription }) => {
    const feature = createFeatureObject(featureName, initialDescription);
    updateFeature(feature.id, feature);
```

Legacy server, `src/index.ts`: `start_feature_clarification` validates only length (`validateRequiredText`, `src/validators.ts:150-175`) and stores the feature (line 1088). `provide_clarification` then logs:

```ts
        console.log(`\n[CLARIFICATION] Received request for feature ${featureId}\n  Question: "${question.substring(0, 50)}..."\n  Answer: "${answer.substring(0, 50)}..."`);   // line 1106
        ...
        console.log(`[CLARIFICATION] Found feature: ${feature.name} with ${feature.clarificationResponses.length} existing responses`);   // line 1131
```

`src/index.ts` is excluded from `tsconfig.build.json`, so `npm run build` does not ship it. It is still the file a reader finds first, and anyone running it with a TypeScript runner gets this behavior.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No accounts are needed.
2. Install the server and run the legacy entry point (not part of `npm run build`):
   ```
   git clone https://github.com/crazyrabbitLTC/mcp-vibecoder.git
   cd mcp-vibecoder && git checkout 5e218b01c9bed9cc44c1c3c087faa559210bc1a7
   npm install
   npx tsx src/index.ts
   ```
3. Create a feature with a CR/LF in its name, then call `provide_clarification` on it:
   ```json
   {"featureName": "tofu-poc\r\nFAKE-LOG-ENTRY", "initialDescription": ""}
   ```

   ```python
   import asyncio
   import logging
   import re
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   logging.basicConfig(level=logging.ERROR)  # shows stdout lines that are not JSON-RPC

   async def main():
       server = StdioServerParameters(command="npx", args=["tsx", "src/index.ts"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "start_feature_clarification",
                   {"featureName": "tofu-poc\r\nFAKE-LOG-ENTRY", "initialDescription": ""},
               )
               print(result)
               feature_id = re.search(r"Feature ID: (\S+)", result.content[0].text).group(1)
               print(await session.call_tool(
                   "provide_clarification",
                   {"featureId": feature_id, "question": "q", "answer": "a"},
               ))

   asyncio.run(main())
   ```
4. What to observe: the server writes `[CLARIFICATION] Found feature: tofu-poc` and then a separate line starting with `FAKE-LOG-ENTRY with 0 existing responses`. Because this goes to stdout, the client reports these lines as messages it could not parse.

## Expected behavior
Values from tool arguments should be neutralized before logging, for example by escaping `\r` and `\n` or logging them through `JSON.stringify`, and logs should go to stderr in a stdio server. A feature name should not need control characters at all.

## Actual behavior
In the fuzzing run against `build/mcp-server.js`, names and descriptions with CR/LF and control bytes were accepted and the tool returned normally:

```
input:  {'featureName': 'LoggerTest', 'initialDescription': 'INFO: User created\nERROR: Sensitive data leak'}
output: Feature ID: feature-7zdds6nn

Let's clarify your feature request. What specific problem does this feature solve?
```

No log line was written by the built server for this tool. The unneutralized logging is in the legacy server described above.

## Impact
The LLM picks the tool arguments, and prompt injection can steer them. Where the legacy server is used, a crafted feature name, question or answer can forge log lines and confuse anyone reading the output. Because the logging uses stdout, it also corrupts the stdio protocol stream. For the built server the impact is limited to accepting control characters in a name that later appears in generated Markdown documents (`src/mcp-server.ts:153`, `:189`). Overall severity is low.

## Suggested fix
- Restrict `featureName` to a single line, for example `z.string().min(2).max(100).regex(/^[^\x00-\x1f\x7f]+$/)`, and strip or escape control characters in `initialDescription` before it is stored.
- In `src/index.ts`, switch `console.log` to `console.error` and neutralize interpolated values (`JSON.stringify(value)` or `value.replace(/[\r\n]/g, " ")`). If `src/index.ts` is no longer used, consider removing it so it is not mistaken for the server entry point.

## Status on the default branch
Still present at `5e218b0` (2025-03-22). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- Documentation: README.md configures clients with `"command": "/path/to/vibe-coder-mcp/build/mcp-server.js"`, and docs/mcp-sdk-improvements.md presents the `index.ts` switch-statement server as the "Before" version. Both support treating `src/index.ts` as a legacy entry point. Nothing documents logging behavior or input restrictions for `featureName`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, the only sanitizer that fired (silent-bug alert: input flagged, tool succeeded). The analysis contains no tracer observation of a log write.
- Campaigns and executions: corpus-sbx 2,560 exec / 2,071 ok (60 s); e2-0922 1,024 exec / 757 ok (60 s). The fuzz config (`eval/sandbox/configs/crazyrabbitLTC__mcp-vibecoder__start_feature_clarification.json`) runs `build/mcp-server.js`.
- Evidence (verbatim, trimmed): `{'featureName': 'LoggerTest', 'initialDescription': 'INFO: User created\nERROR: Sensitive data leak'}` -> `Feature ID: feature-7zdds6nn\n\nLet's clarify your feature request. What specific problem does this feature solve?`; also `{'featureName': '\x18\x01\x00\r\x00\x00\x00\x00\x02alD\x19s:" ', 'initialDescription': ''}` -> same shape.
- Hand-check hints: weak, likely a false positive for the fuzzed target. The built server has no log sink for this tool; the alert is input-only. The only CWE-117 sink I found is in the legacy `src/index.ts` (excluded from the build), and it is reached through a second tool (`provide_clarification`). The legacy repro was not run, and I did not check that `src/index.ts` runs cleanly under `tsx`. Probably not worth filing as a security issue. Side finding (functional bug, not security): in `src/mcp-server.ts:305-306` the new feature is passed to `updateFeature`, which returns early when the id is not already in `features` (`src/storage.ts:40-44`), so the built server never stores features created by this tool and follow-up calls should report "not found". Not run.
</details>
