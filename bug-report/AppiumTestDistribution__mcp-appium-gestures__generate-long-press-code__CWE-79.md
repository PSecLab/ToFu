# Missing output escaping in `generate-long-press-code`: `elementId` breaks out of the string literal in the generated Java and JavaScript

**Repository:** `AppiumTestDistribution/mcp-appium-gestures` · **Tool:** `generate-long-press-code` · **Tested commit:** `6bd1aa2`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generate-long-press-code` returns a WebdriverIO or Java snippet for a long press. When `useElement` is true, the caller's `elementId` is interpolated raw into a quoted string in the generated code. A `"` (Java) or `'` (JavaScript) in `elementId` ends the string early, and the rest of the value becomes code. The fuzzing run produced a Java snippet where this already happened. Users paste these snippets into test suites and run them.

## Details
`src/tools/generate-long-press-code.js:33-54` at `6bd1aa2`:

```js
      if (language === 'javascript') {
        if (useElement) {
          code = `// For WebdriverIO v9+
const element = $('~${elementId}');
await element.longPress({ duration: ${duration} });

// For WebdriverIO below v9
await $('~${elementId}').touchAction('longPress');`;
        ...
      } else if (language === 'java') {
        if (useElement) {
          code = `// Using W3C Actions API (recommended)
WebElement element = driver.findElement(AppiumBy.accessibilityId("${elementId}"));
```

`elementId` is `z.string().optional()` (line 13) and is never escaped for either language. `duration`, `x` and `y` are numbers, so they are safe.

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
   {"language": "java", "useElement": true, "elementId": "tofu-poc\")); System.out.println((\"FAKE-INJECTED-LINE", "duration": 2000}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {
       "language": "java",
       "useElement": True,
       "elementId": 'tofu-poc")); System.out.println(("FAKE-INJECTED-LINE',
       "duration": 2000,
   }

   async def main():
       server = StdioServerParameters(command="node", args=["src/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generate-long-press-code", ARGS)
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the first line of the snippet is `WebElement element = driver.findElement(AppiumBy.accessibilityId("tofu-poc")); System.out.println(("FAKE-INJECTED-LINE"));`. That is valid Java with an extra statement. With `language: "javascript"` and `elementId: "tofu-poc'); console.log('FAKE-INJECTED-LINE"` the JavaScript variant breaks out the same way.

## Expected behavior
`elementId` should be emitted as a correctly escaped string literal, for example via `JSON.stringify(elementId)`, which is valid in both JavaScript and Java. Or the tool should reject values containing quotes, backslashes or line breaks.

## Actual behavior
The value is copied verbatim. From the fuzzing run (Java, trimmed), the `"` in the input closed the Java string:

```
WebElement element = driver.findElement(AppiumBy.accessibilityId("\x00{{"language": "javascript", "useElement": false, "elem": 1"));
```

## Impact
The LLM picks the tool arguments, and prompt injection can steer them, for example through element names copied from an app's UI or a test plan. A crafted `elementId` adds statements to code the user is about to paste and run in their test environment. Review would usually catch it, so the impact is low to moderate. Clients that render tool output as Markdown or HTML would also show unescaped markup from `elementId`, which is lower risk.

## Suggested fix
Replace raw interpolation of `elementId` with an escaped literal. `JSON.stringify` works for both targets: `$(${JSON.stringify('~' + elementId)})` and `accessibilityId(${JSON.stringify(elementId)})`. Alternatively, restrict `elementId` with a zod regex that excludes `'`, `"`, `\`, `` ` `` and line breaks. `generate-tap-code`, `generate-double-tap-code` and `generate-scroll-code` share the pattern.

## Status on the default branch
Still present at `6bd1aa2` (2025-07-17). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issue and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 3,072 exec / 2,645 ok (60 s).
- Evidence (verbatim, trimmed): input `{'language': 'java', 'useElement': True, 'elementId': '\x00{{"language": "javascript", "useElement": false, "elem": 1', 'x': 0.0, 'y': 0.0, 'duration': 0.0}` -> `WebElement element = driver.findElement(AppiumBy.accessibilityId("\x00{{"language": "javascript", "useElement": false, "elem": 1"));`. Also logged: JS mode with `elementId: '"l&: {{'` -> `const element = $('~"l&: {{');`.
- Hand-check hints: real, but not as XSS. ToFu only flagged `{{` in plain-text content; the defect that matters is string-literal breakout in generated code (closer to CWE-94/CWE-116), and the Java evidence line shows the breakout in a logged run. The `System.out.println` payload is derived from the template at line 54 and was not run. Consider one issue for all four generators.
</details>
