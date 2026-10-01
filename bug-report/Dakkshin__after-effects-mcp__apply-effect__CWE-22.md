# Unrestricted file path in `apply-effect`: `presetPath` can name any local file, and its existence is reported back

**Repository:** `Dakkshin/after-effects-mcp` · **Tool:** `apply-effect` · **Tested commit:** `88d5fbf`
**Weakness:** CWE-22 Path Traversal

## Summary
`apply-effect` queues a command for the After Effects bridge panel to add an effect, or apply a preset, to a layer. `presetPath` is forwarded unchanged and the panel opens it with `new File(presetPath)` and `layer.applyPreset()`. There is no directory restriction and no `.ffx` check. Any path the After Effects process can read is accepted, and the result tells the caller whether that file exists.

## Details
The MCP server only validates that `presetPath` is a string, then writes it into the command file. `src/index.ts:640-655` (tested commit):

```ts
server.tool(
  "apply-effect",
  "Apply an effect to a layer in After Effects",
  {
    ...
    presetPath: z.string().optional().describe("Optional path to an effect preset file (.ffx)."),
    ...
  },
  async (parameters) => {
      writeCommandFile("applyEffect", parameters);
```

The bridge panel uses it as is. `src/scripts/mcp-bridge-auto.jsx:900-908`:

```js
        if (presetPath) {
            var presetFile = new File(presetPath);
            if (!presetFile.exists) {
                throw new Error("Effect preset file not found: " + presetPath);
            }
            layer.applyPreset(presetFile);
```

The same code is in `src/scripts/applyEffect.jsx:34-41`. Relative paths resolve against After Effects' current folder, and `../` and absolute paths are accepted. The error text separates "does not exist" from "exists but failed to apply", which gives a file-existence oracle.

## Steps to reproduce
1. Prerequisites: Adobe After Effects (macOS or Windows) with a project open that has composition 1 containing layer 1. Node.js 18+. Create a harmless file: `echo tofu-poc > /tmp/tofu-poc.txt`.
2. Install, build and install the panel as the README describes: `git clone https://github.com/Dakkshin/after-effects-mcp && cd after-effects-mcp && npm install && npm run build && npm run install-bridge`, then in After Effects open Window > `mcp-bridge-auto.jsx`.
3. Call the tool once with an existing non-preset file and once with a missing file, reading the result after each:

   ```json
   {"compIndex": 1, "layerIndex": 1, "presetPath": "/tmp/tofu-poc.txt"}
   ```
   ```json
   {"compIndex": 1, "layerIndex": 1, "presetPath": "/tmp/tofu-missing.ffx"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for p in ["/tmp/tofu-poc.txt", "/tmp/tofu-missing.ffx"]:
                   await session.call_tool("apply-effect", {"compIndex": 1, "layerIndex": 1, "presetPath": p})
                   await asyncio.sleep(5)
                   result = await session.call_tool("get-results", {})
                   print(p, result)

   asyncio.run(main())
   ```
4. Observe: for the missing file, `get-results` returns `Effect preset file not found: /tmp/tofu-missing.ffx`. For `/tmp/tofu-poc.txt`, the existence check passes and After Effects tries to apply a `.txt` file as a preset, so the result shows an `applyPreset` error instead.

## Expected behavior
`presetPath` is accepted only if it ends in `.ffx` and resolves inside an allowed presets folder (for example After Effects' `Presets` folder or a configured directory). Other paths get the same generic error whether or not they exist.

## Actual behavior
Any path is queued. In the fuzzing run, `../../../../etc/passwd` was accepted and queued:

```
input:  {'compIndex': 1, 'layerIndex': 1, 'effectName': '../../../../etc/passwd', 'effectMatchName': 'ADBE Gaussian Blur 2', 'effectCategory': 'Blur & Sharpen', 'presetPath': '../../../../etc/passwd', 'effectSettings': {}}
output: Command to apply effect to layer 1 in composition 1 has been queued.
        Use the "get-results" tool after a few seconds to check for confirmation.
```

(After Effects was not running in the fuzzing environment, so the panel never processed it.)

## Impact
The LLM chooses `presetPath`, and prompt injection in content the agent reads can steer it. An attacker learns whether given files exist on the user's machine, and can make After Effects load any `.ffx` file at a path the attacker can predict, for example one dropped in the Downloads folder. File contents are not returned. This needs After Effects running with the bridge panel open, so the severity is low.

## Suggested fix
In the MCP server, before `writeCommandFile`:
- Reject `presetPath` values that do not end in `.ffx`.
- Resolve the path (`fs.realpathSync`) and require it to be inside an allowed presets directory.
- Return one generic error for refused and missing files.

Keep the `presetFile.exists` check in the panel as a second line of defense.

## Status on the default branch
Still present at `88d5fbf` (2026-04-01). The tested commit is the current default branch head.

## Prior reports
- #42 "Add footage import, trimmed placement and Time Remap tools" (PR, open 2026-09-28): its new `importFootage` "rejects relative, UNC and drive-relative paths". That check is for the new tool only and does not touch `presetPath`. Does not fix this.
- #38 "fix: 6 bridge/scripting bugs found via live AE testing" (PR, open 2026-08-21): fixes effect matchNames in `applyEffectTemplate` and the effects help text; nothing about `presetPath`. Does not fix this.
- Documentation: README.md does not mention `apply-effect` or `presetPath` and has no security or untrusted-input note.
- No issue reports this. Searched all 11 issues and 31 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` only (input-pattern "silent bug" alert).
- Campaigns and executions: corpus-sbx 2048 exec / 1705 ok; e2-0922 2048 exec / 1274 ok (60 s budgets).
- Evidence (verbatim, trimmed): the single call in "Actual behavior"; the output is the fixed "has been queued" message.
- Hand-check hints: weak. The node server never touches `presetPath`; it only writes it into `~/Documents/ae-mcp-bridge/ae_command.json`. The file access happens in After Effects (`mcp-bridge-auto.jsx:902-908`), confirmed in source but not run: no After Effects in the fuzzing environment. The parameter is documented as "path to an effect preset file (.ffx)" with no folder, so there is no intended directory being escaped. Real effect is an existence oracle plus loading of arbitrary `.ffx` files. I did not verify the exact After Effects error text for a non-preset file. `effectName` in the evidence is irrelevant (used with `addProperty`, no file access).
</details>
