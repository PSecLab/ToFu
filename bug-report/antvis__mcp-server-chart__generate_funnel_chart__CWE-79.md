# Missing output encoding in `generate_funnel_chart`: `title` markup is echoed raw into `_meta.spec`

**Repository:** `antvis/mcp-server-chart` · **Tool:** `generate_funnel_chart` · **Tested commit:** `e2a8fb7`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`generate_funnel_chart` sends the chart arguments to the rendering service and returns the image URL plus `_meta.spec`, a copy of the arguments that the tool says "can be rendered using AntV GPT-Vis chart components". `title`, the `category` strings in `data`, and `style.backgroundColor` are free text and are copied into `_meta.spec` unchanged, including HTML such as `<script>`. If a client renders the spec with a component that does not escape these fields, the markup runs in that client's page.

## Details
The spec is built from the raw arguments in `src/utils/callTool.ts:93-107` at `e2a8fb7`:

```ts
    const url = await generateChartUrl(chartType, args);
    ...
    return {
      content: [{ type: "text", text: url }],
      _meta: {
        description:
          "The content returned by MCP is the remote image URL of the visualization chart, which can be rendered using Markdown or HTML image tags. The _meta.spec content corresponds to the chart's configuration and spec, which can be rendered using AntV GPT-Vis chart components.",
        spec: { type: chartType, ...args },
      },
    };
```

The Zod schema is checked first (`callTool.ts:67-79`), but `src/charts/base.ts:45-49` defines `TitleSchema` as `z.string()` and `base.ts:10-13` defines `BackgroundColorSchema` as `z.string().optional()` with no color format. `src/charts/funnel.ts:18-39` uses both, and `category` is `z.string()` (`funnel.ts:13-16`). Nothing in `src/` escapes or restricts these values before they are returned. The image URL in `content` comes from the rendering service and is not affected.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and npm. Network access to the default rendering service (`https://antv-studio.alipay.com/api/gpt-vis`), or a self-hosted GPT-Vis-SSR set through `VIS_REQUEST_SERVER`. No accounts.
2. Install and build as the README describes:

   ```bash
   git clone https://github.com/antvis/mcp-server-chart.git
   cd mcp-server-chart && git checkout e2a8fb7
   npm install && npm run build
   ```
3. Call the tool from the repository root with:

   ```json
   {"data": [{"category": "visit", "value": 50000}, {"category": "order", "value": 20000}], "title": "<b>tofu-poc</b>"}
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
               result = await session.call_tool("generate_funnel_chart", {
                   "data": [{"category": "visit", "value": 50000}, {"category": "order", "value": 20000}],
                   "title": "<b>tofu-poc</b>",
               })
               print(result.meta)

   asyncio.run(main())
   ```
4. Observe: `_meta.spec.title` is `<b>tofu-poc</b>`, unchanged.

## Expected behavior
Free-text fields such as `title` are either HTML-escaped in `_meta.spec` or documented as untrusted text that renderers must escape. `style.backgroundColor` is validated as a color.

## Actual behavior
The markup is returned verbatim. From the fuzzing run:

```
input:  {"data": [{"category": "浏览网站", "value": 50000}], "style": {"backgroundColor": "#fff", ...}, ..., "title": "<script>alert('xss')</script>"}
output: {"_meta": {..., "spec": {"type": "funnel", ..., "title": "<script>alert('xss')</script>"}},
         "content": [{"type": "text", "text": "https://mdn.alipayobjects.com/one_clip/afts/img/.../original"}]}
```

## Impact
In MCP the LLM fills `title` and `data`, and prompt injection from untrusted content (for example a page or file whose numbers the user asks to chart) can put markup in them. Whether this leads to script execution depends on the client that renders `_meta.spec`. I have not confirmed that GPT-Vis or any specific client renders `title` as HTML. If one does, the markup runs in the chat UI's origin. The PNG in `content` is not affected. Treat this as hardening, not a confirmed XSS.

## Suggested fix
- Return the parsed Zod result (`result.data`) in `_meta.spec` instead of the raw `args`.
- Either HTML-escape free-text fields in `_meta.spec` or state in `_meta.description` that `spec` contains untrusted text, and make sure GPT-Vis components render `title` and labels with text APIs (not `innerHTML`).
- Validate `style.backgroundColor` and `style.palette` with a color regex in `src/charts/base.ts`.

## Status on the default branch
Still present at `e2a8fb7` (2026-08-27). The default branch head is the tested commit.

## Prior reports
- #279 "Security Advisory: Prompt Injection Risk via External Data Sources in Chart Generation" (issue, closed 2026-05-02): says attacker-controlled titles, labels and data values from external sources pass through the chart tools, and asks for sanitizing and length limits on text fields. Its concern is prompt injection into the model, not markup in `_meta.spec`. Nothing in `src/` at `e2a8fb7` sanitizes these fields, so it does not fix this.
- #296 "docs: add security advisory note about prompt injection risks" (PR, closed 2026-04-29): would have added a README "Security Considerations" section for #279 (validate and sanitize external data). Not merged: the README at `e2a8fb7` has no such section.
- #297 "fix(callTool): address bot review comments on PR #296" (PR, closed 2026-04-29): would have put `sortedArgs` instead of `args` in `_meta.spec`. Not merged (`src/utils/callTool.ts:106` still spreads `args`), and it would not escape anything.
- #197 "vulnerability in  mcp-server-chart" (issue, closed 2025-09-16) and #198 "fix: mcp inspector xss" (PR, closed 2025-09-16): an XSS in the `@modelcontextprotocol/inspector` dev dependency, handled through a Dependabot alert (`package.json` now pins `^0.16.6`). Different code; does not touch `_meta.spec`.
- #300 "Private security disclosure route? (pub_antv@antgroup.com bounced)" (issue, closed 2026-08-21): an undisclosed finding in the default Docker deployment, not this one. It notes there is no `SECURITY.md` and private vulnerability reporting was disabled, which matters for how to file.
- Documentation: README.md has no security section, and the default branch has no `SECURITY.md` or `docs/`. Nothing documents `_meta.spec` as unescaped.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output`. Also listed for this tool: `check_introspection_type_confusion`, `check_unexpected_crash` (not used here).
- Campaigns and executions: recover-pc, 1 exec / 0 ok (60 s). The logged call returned a normal image URL, so "0 ok" looks like a ToFu counting artifact; not checked.
- Evidence (verbatim, trimmed): input `{'data': [{'category': '浏览网站', 'value': 50000}], 'style': {'backgroundColor': '#fff', 'palette': ['#ff0000'], 'texture': 'default'}, 'theme': 'default', 'width': 600, 'height': 400, 'title': "<script>alert('xss')</script>"}` -> output `_meta.spec.title` = `"<script>alert('xss')</script>"`; `content[0].text` is an `mdn.alipayobjects.com` PNG URL.
- Hand-check hints: weak. The echo is by design (`_meta.spec` is a copy of the caller's config), it is structured JSON, and the caller chose the markup. The logged payload was only in `title`; `backgroundColor` is unvalidated here too but was not exercised. I did not check GPT-Vis or any client renderer, so XSS is unconfirmed. Same root cause as the other chart tools; file one combined issue. Repro not executed; it sends the harmless payload to AntV's public rendering service.
</details>
