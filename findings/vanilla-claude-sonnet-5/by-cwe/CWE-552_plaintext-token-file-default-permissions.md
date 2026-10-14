# CWE-552 -- Files or Directories Accessible to External Parties (1 findings: 0 Tier-A, 1 Tier-B)

vanilla-claude-sonnet-5 static audit, 2026-09-21. Grounded per Phase 2 (verify_findings.py). Static reading only, no execution.

| repo | tool | tier | cwe | file:line | param -> sink | why |
|---|---|---|---|---|---|---|
| Tisik79/MCP-Facebook | `set_facebook_token` | B | CWE-552 | `src/auth-manager.ts:40` | token -> caller-supplied long-lived Facebook user/page access tokens are written in plaintext to tokens.json next to the install directory with default OS file permissions (no explicit chmod) | The token argument the caller hands to set_facebook_token, plus page/ad-account tokens fetched from it, are persisted unencrypted via a bare fs.writeFileSync with no mode argument, so on a shared/multi-user host other local accounts may be able to read long-lived Facebook credentials depending on... |
