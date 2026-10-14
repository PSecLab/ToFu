# CWE-352 -- (taxonomy extension) (1 findings: 1 Tier-A, 0 Tier-B)

vanilla-claude-sonnet-5 static audit, 2026-09-21. Grounded per Phase 2 (verify_findings.py). Static reading only, no execution.

| repo | tool | tier | cwe | file:line | param -> sink | why |
|---|---|---|---|---|---|---|
| cline/linear-mcp | `linear_auth_callback` | A | CWE-352 | `src/auth.ts:72` | code -> LinearAuth.handleCallback() exchanges the caller-supplied `code` for a token via fetch(OAUTH_TOKEN_URL) with no state/CSRF check anywhere in the flow | getAuthorizationUrl() (auth.ts:65) generates a random `state` via generateState() and embeds it in the authorize URL, but that value is never stored on the LinearAuth instance and is never compared to anything. handleCallback(code) (auth.ts:72-120) and the linear_auth_callback tool schema/handler... |
