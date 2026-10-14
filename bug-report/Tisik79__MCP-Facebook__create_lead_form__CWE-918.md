# Missing URL validation in `create_lead_form`: `privacy_policy.url` and `follow_up_action_url` are forwarded unchecked

**Repository:** `Tisik79/MCP-Facebook` · **Tool:** `create_lead_form` · **Tested commit:** `2ebfbc9`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`create_lead_form` creates a Meta instant (lead) form on a page. It accepts `privacy_policy.url` and `follow_up_action_url` and passes them to the Graph API without checking the scheme or host, so values such as `file:///etc/passwd` or empty strings are accepted. The MCP server itself never fetches these URLs: the only outbound request goes to `graph.facebook.com`. This is a low-severity input-validation gap, not a server-side request forgery in this process.

## Details
`src/tools/leadform-tools.ts:51-73` (tested commit):

```ts
if (!args.name) throw new Error('Chybí povinný parametr: name.');
if (!args.privacyPolicy?.url) {
  throw new Error('Chybí privacy_policy.url – ...');
}
const { id: pageId, token } = resolvePage(args.pageId);
...
body.append('privacy_policy', JSON.stringify(args.privacyPolicy));
...
if (args.followUpActionUrl) body.append('follow_up_action_url', args.followUpActionUrl);

const endpoint = `https://graph.facebook.com/${GRAPH_VERSION}/${pageId}/leadgen_forms`;
const res = await fetch(endpoint, { method: 'POST', body });
```

The only check on `privacy_policy.url` is that it is non-empty. There is no check that it is an `http(s)` URL. `follow_up_action_url` is not checked at all. The tool schema in `src/index.ts:796-822` declares both as plain `z.string()`.

A related point: the caller-supplied `page_id` is interpolated into the Graph API path without encoding. The host stays `graph.facebook.com`, but characters such as `/`, `?` or `#` in `page_id` change which Graph endpoint receives the POST with the active token.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python 3 for a local listener. To reach the Graph API call you need a connected page (run `node dist/index.js login`, or set `FACEBOOK_PAGE_ID` and `FACEBOOK_PAGE_ACCESS_TOKEN`). Without a page the tool stops at `resolvePage` after it has already accepted the URLs.
2. Install and build as the README describes:
   `git clone https://github.com/Tisik79/MCP-Facebook.git && cd MCP-Facebook && npm install && npm run build`
   In a second terminal start a local listener: `python3 -m http.server 8099 --bind 127.0.0.1`
3. Call the tool with the listener URL in both URL fields:

   ```json
   {"name": "UrlCheck", "privacy_policy": {"url": "http://127.0.0.1:8099/tofu-poc", "link_text": "Privacy"}, "locale": "CS_CZ", "follow_up_action_url": "http://127.0.0.1:8099/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_lead_form", {
                   "name": "UrlCheck",
                   "privacy_policy": {"url": "http://127.0.0.1:8099/tofu-poc", "link_text": "Privacy"},
                   "locale": "CS_CZ",
                   "follow_up_action_url": "http://127.0.0.1:8099/tofu-poc",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the listener log. Per the code, no `GET /tofu-poc` should arrive: the server does not request the URL, it only places it in the POST body sent to `graph.facebook.com`. Observe also that the tool does not reject the value. The same holds for a non-HTTP value such as `file:///etc/hostname`, which the fuzzer used.

## Expected behavior
The tool rejects `privacy_policy.url` and `follow_up_action_url` unless they are absolute `https://` (or `http://`) URLs with a non-empty host, before contacting the Graph API.

## Actual behavior
The URL passes validation. In the fuzzing run, without a connected page, the tool got past the URL check and failed only at page resolution:

```
Chyba: Chyba při vytváření lead formuláře: Není k dispozici žádná Facebook stránka. ...
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. Here the effect is limited: the server forwards the URL to Meta and never requests it itself, so it cannot be used to reach other services from the server's network. The practical risk is a lead form created with a bogus or attacker-chosen privacy or follow-up link, if Meta accepts it.

## Suggested fix
- Parse `privacy_policy.url` and `follow_up_action_url` with `new URL()` and accept only `https:` (optionally `http:`) with a non-empty hostname.
- Validate `page_id` as a numeric Graph ID (for example `/^\d+$/`) or `encodeURIComponent` it before building the endpoint path.

## Status on the default branch
Still present at `2ebfbc9` (2026-07-06). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918); triggered `check_strict_url_security_contract`, `check_invalid_json`.
- Campaigns and executions: corpus-sbx 2560 exec / 2554 ok; e2-0922 1536 exec / 1526 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - input `{'name': 'FileAccessTest', 'privacy_policy': {'url': 'file:///etc/passwd', 'link_text': '...'}, 'page_id': '', 'locale': 'CS_CZ', 'questions': [], 'context_card': '', 'thank_you_page': '', 'follow_up_action_url': ''}` -> `Chyba: ... Není k dispozici žádná Facebook stránka...`
  - All three alerts report `Input: ''`: the sanitizer evaluated an empty URL argument (most likely the empty `follow_up_action_url`), not the `file://` value.
  - First evidence call failed with `Chybí povinný parametr: name.`, which is a rejection; the sanitizer's `is_input_rejected` did not recognise the Czech error text.
- Hand-check hints: weak, likely a false positive for SSRF. The server never fetches the caller URL; the only fetch goes to `https://graph.facebook.com/<ver>/<page_id>/leadgen_forms`. The alert fired on an empty string and on Czech-language rejections. What remains is missing URL validation plus unencoded `page_id` in the Graph path (host fixed). Consider not filing, or filing as a low-priority hardening note. Not verified against a live Meta account.
</details>
