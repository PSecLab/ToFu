# Missing output escaping in `generate-double-tap-code`: `elementId` is pasted unescaped into the generated JavaScript and Java string literals

**Repository:** `AppiumTestDistribution/mcp-appium-gestures` · **Tool:** `generate-double-tap-code` · **Tested commit:** `6bd1aa2`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generate-double-tap-code` returns a WebdriverIO or Java snippet for a double tap. When `useElement` is true, the caller's `elementId` is inserted with a template literal straight into a quoted string in the generated code. A quote character in `elementId` closes the string, and whatever follows becomes code in the snippet. The snippet is meant to be pasted into a test suite and run, so the missing escaping lets caller text turn into statements.

## Details
`src/tools/generate-double-tap-code.js:33-41` and `:80` at `6bd1aa2`:

```js
      if (language === 'javascript') {
        if (useElement) {
          code = `// For WebdriverIO v9+
const element = $('~${elementId}');
await element.doubleClick();

// For WebdriverIO below v9
// Using the Gestures helper class
const element = $('~${elementId}');
...
          code = `WebElement element = driver.findElement(AppiumBy.accessibilityId("${elementId}"));
```

`elementId` is `z.string().optional()` (line 13) with no character restrictions. It is not escaped for a single-quoted JavaScript string or a double-quoted Java string. The numeric arguments are safe because zod forces them to numbers.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No accounts or devices are needed; the tool only builds a string.
2. Install and start the server:
   ```
   git clone https://github.com/AppiumTestDistribution/mcp-appium-gestures.git
   cd mcp-appium-gestures && git checkout 6bd1aa2642ba7b0905d313d11f378333c4fc5b09
   npm install
   node src/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"language": "javascript", "useElement": true, "elementId": "tofu-poc'); console.log('FAKE-INJECTED-LINE", "pauseDuration": 200}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {
       "language": "javascript",
       "useElement": True,
       "elementId": "tofu-poc'); console.log('FAKE-INJECTED-LINE",
       "pauseDuration": 200,
   }

   async def main():
       server = StdioServerParameters(command="node", args=["src/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generate-double-tap-code", ARGS)
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the generated snippet contains `const element = $('~tofu-poc'); console.log('FAKE-INJECTED-LINE');` twice. The `console.log` call is now a separate statement in the code the user would paste.

## Expected behavior
`elementId` should be emitted as a correctly escaped string literal for the target language, for example with `JSON.stringify(elementId)` for both JavaScript and Java, or rejected if it contains quotes, backslashes or line breaks.

## Actual behavior
The value is copied verbatim into the literal. In the fuzzing run the double quotes in `elementId` were echoed raw:

```
const element = $('~{{"lan"olangu"gu');
await element.doubleClick();
```

The run used `language: "javascript"`, where `"` is harmless inside a single-quoted string. A `'` (JavaScript) or `"` (Java) closes the string.

## Impact
The LLM picks the tool arguments, and prompt injection can steer them. An element name taken from untrusted content, such as an app's UI text or a test plan, could carry a quote and extra code. The user then pastes a snippet that runs more than a gesture. Code review would usually catch this, so the impact is low to moderate. In clients that render tool output as Markdown or HTML, unescaped markup in `elementId` is also echoed, which is lower risk.

## Suggested fix
Emit `elementId` with a language-appropriate escaper instead of raw interpolation. `JSON.stringify(elementId)` produces a valid double-quoted literal for both JavaScript and Java, so `$(${JSON.stringify('~' + elementId)})` and `accessibilityId(${JSON.stringify(elementId)})` would work. Alternatively, reject `elementId` values that contain `'`, `"`, `\`, `` ` `` or line breaks. The same pattern is in `generate-tap-code`, `generate-long-press-code` and `generate-scroll-code`.

## Status on the default branch
Still present at `6bd1aa2` (2025-07-17). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issue and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 3,072 exec / 2,600 ok (60 s).
- Evidence (verbatim, trimmed): input `{'language': 'javascript', 'useElement': True, 'elementId': '{{"lan"olangu"gu', 'x': 0.0, 'y': 0.0, 'pauseDuration': 0.0}` -> `// For WebdriverIO v9+\nconst element = $('~{{"lan"olangu"gu');\nawait element.doubleClick(); ...`. Two more inputs of the same shape (one with 33 NUL bytes) were echoed the same way.
- Hand-check hints: real, but not as XSS. As XSS it is weak (only `{{` flagged, plain-text MCP content); the actual defect is string-literal breakout in generated code (closer to CWE-94/CWE-116). The logged run never used a `'` in JavaScript mode, so the breakout repro is derived from the template at lines 36 and 41, not from a run. `src/index.js:12` prints to stdout with `console.log` before the stdio transport starts, so a client may log a JSON parse warning at startup; the fuzz harness worked regardless. Consider one issue for all four generators.
</details>
