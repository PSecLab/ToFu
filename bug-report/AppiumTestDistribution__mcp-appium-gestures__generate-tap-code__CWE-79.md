# Missing output escaping in `generate-tap-code`: `elementId` is pasted unescaped into the generated JavaScript and Java string literals

**Repository:** `AppiumTestDistribution/mcp-appium-gestures` · **Tool:** `generate-tap-code` · **Tested commit:** `6bd1aa2`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generate-tap-code` returns a WebdriverIO or Java snippet for a tap. With `useElement: true`, the caller's `elementId` goes raw into a quoted string inside the generated code. A `'` (JavaScript) or `"` (Java) in `elementId` closes that string, and the rest of the value becomes code in the snippet. This is the tool shown in the README example, and its output is meant to be pasted into a test suite.

## Details
`src/tools/generate-tap-code.js:32-40` and `:62` at `6bd1aa2`:

```js
      if (language === 'javascript') {
        if (useElement) {
          code = `// For WebdriverIO v9+
const element = $('~${elementId}');
// It will automatically scroll to the element if it's not already in the viewport
await element.tap();

// For WebdriverIO below v9
await $('~${elementId}').click();`;
        ...
          code = `// Using W3C Actions API (recommended)
WebElement element = driver.findElement(AppiumBy.accessibilityId("${elementId}"));
```

`elementId` is `z.string().optional()` (line 13). It is not escaped for a single-quoted JavaScript string or a double-quoted Java string. `x` and `y` are numbers, so they are safe.

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
   {"language": "javascript", "useElement": true, "elementId": "tofu-poc'); console.log('FAKE-INJECTED-LINE"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {
       "language": "javascript",
       "useElement": True,
       "elementId": "tofu-poc'); console.log('FAKE-INJECTED-LINE",
   }

   async def main():
       server = StdioServerParameters(command="node", args=["src/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generate-tap-code", ARGS)
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the snippet contains `const element = $('~tofu-poc'); console.log('FAKE-INJECTED-LINE');` and `await $('~tofu-poc'); console.log('FAKE-INJECTED-LINE').click();`. The `console.log` call is now a separate statement in the generated code.

## Expected behavior
`elementId` should be emitted as an escaped string literal for the target language, for example with `JSON.stringify(elementId)`, or rejected when it contains quotes, backslashes or line breaks.

## Actual behavior
The value is copied verbatim. From the fuzzing run:

```
const element = $('~{{`+');
...
await $('~{{`+').click();
```

The logged inputs did not contain a `'`, so they did not close the JavaScript string. They show that the value is inserted with no escaping.

## Impact
The LLM picks the tool arguments, and prompt injection can steer them, for example via element names copied from an app's UI text or a test plan. A crafted `elementId` adds statements to code the user is about to paste and run. Review would usually catch this, so the impact is low to moderate. Clients that render tool output as Markdown or HTML would also show unescaped markup from `elementId`, which is lower risk.

## Suggested fix
Emit `elementId` through an escaper instead of raw interpolation. `JSON.stringify` gives a valid literal in both JavaScript and Java: `$(${JSON.stringify('~' + elementId)})` and `accessibilityId(${JSON.stringify(elementId)})`. Alternatively, restrict `elementId` with a zod regex that excludes `'`, `"`, `\`, `` ` `` and line breaks. `generate-double-tap-code`, `generate-long-press-code` and `generate-scroll-code` share the pattern.

## Status on the default branch
Still present at `6bd1aa2` (2025-07-17). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issue and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 3,072 exec / 2,492 ok (60 s).
- Evidence (verbatim, trimmed): input `{'language': 'javascript', 'useElement': True, 'elementId': '{{`+', 'x': 0.0, 'y': 0.0}` -> `// For WebdriverIO v9+\nconst element = $('~{{`+');\n...\nawait $('~{{`+').click();`. Two more logged inputs were long runs of `{` followed by `"j `, echoed the same way.
- Hand-check hints: real, but not as XSS. ToFu only flagged `{{` in plain-text content and no logged input closed the string; the breakout repro is derived from the template at lines 35 and 40, not from a run. The defect is string-literal injection in generated code (closer to CWE-94/CWE-116), low to moderate severity. Consider one issue for all four generators.
</details>
