# CWE-295 -- (taxonomy extension) (1 findings: 1 Tier-A, 0 Tier-B)

vanilla-claude-sonnet-5 static audit, 2026-09-21. Grounded per Phase 2 (verify_findings.py). Static reading only, no execution.

| repo | tool | tier | cwe | file:line | param -> sink | why |
|---|---|---|---|---|---|---|
| yokingma/one-search-mcp | `one_scrape` | A | CWE-295 | `src/schemas.ts:82` | skipTlsVerification (boolean, declared directly in ScrapeToolInputSchema, no server-side override) -> src/index.ts:182 ignoreHttpsErrors:skipTlsVerification -> src/libs/agent-browser/index.ts:59 browser.launch({ignoreHTTPSErrors}) -> node_modules/agent-browser/dist/browser.js:905/929/934 newContext({ignoreHTTPSErrors: options.ignoreHTTPSErrors ?? false}), Playwright's documented mechanism for disabling TLS cert validation on a browser context | every hop from the declared schema field to Playwright's real certificate-validation-disabling context option was traced and confirmed with no gate at all, letting any caller silently defeat TLS validation for whatever host is scraped, enabling undetected MITM/content-spoofing; CWE-295 is not in ... |
