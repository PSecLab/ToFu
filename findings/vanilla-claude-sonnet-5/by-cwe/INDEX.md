# vanilla-claude-sonnet-5 -- findings by CWE (2026-09-21)

748 grounded flag rows (474 Tier-A, 274 Tier-B) across 24 CWE classes.

| CWE | title | count | file |
|---|---|---|---|
| CWE-22 | Path Traversal | 217 | [CWE-22_faiss-version-dir-traversal.md](CWE-22_faiss-version-dir-traversal.md) |
| CWE-918 | Server-Side Request Forgery (SSRF) | 150 | [CWE-918_ssrf-dns-rebinding-toctou.md](CWE-918_ssrf-dns-rebinding-toctou.md) |
| CWE-73 | External Control of File Name or Path | 81 | [CWE-73_arbitrary-file-write-scriptpath.md](CWE-73_arbitrary-file-write-scriptpath.md) |
| CWE-89 | SQL Injection | 73 | [CWE-89_wiql-injection-via-unescaped-project-team-filter.md](CWE-89_wiql-injection-via-unescaped-project-team-filter.md) |
| CWE-78 | OS Command Injection | 60 | [CWE-78_blockedcommands-guard-not-applied.md](CWE-78_blockedcommands-guard-not-applied.md) |
| CWE-88 | Argument Injection | 41 | [CWE-88_blockedcommands-quoting-bypass.md](CWE-88_blockedcommands-quoting-bypass.md) |
| CWE-94 | Code Injection | 39 | [CWE-94_jxa-argv-string-breakout-code-injection.md](CWE-94_jxa-argv-string-breakout-code-injection.md) |
| CWE-200 | Information Exposure | 16 | [CWE-200_partial-secret-redaction.md](CWE-200_partial-secret-redaction.md) |
| CWE-377 | Insecure Temporary File | 15 | [CWE-377_insecure-temp-values-file.md](CWE-377_insecure-temp-values-file.md) |
| CWE-400 | Uncontrolled Resource Consumption | 11 | [CWE-400_unbounded-threadpool-max-workers.md](CWE-400_unbounded-threadpool-max-workers.md) |
| CWE-862 | Missing Authorization | 9 | [CWE-862_unscoped-process-kill.md](CWE-862_unscoped-process-kill.md) |
| CWE-1333 | Inefficient Regular Expression Complexity (ReDoS) | 7 | [CWE-1333_redos-user-supplied-regex-pattern.md](CWE-1333_redos-user-supplied-regex-pattern.md) |
| CWE-532 | Insertion of Sensitive Information into Log File | 5 | [CWE-532_nested-credential-logged.md](CWE-532_nested-credential-logged.md) |
| CWE-598 | (extension) | 5 | [CWE-598_api-key-in-url-query-string.md](CWE-598_api-key-in-url-query-string.md) |
| CWE-502 | Deserialization of Untrusted Data | 3 | [CWE-502_unvalidated-model-path-config-injection.md](CWE-502_unvalidated-model-path-config-injection.md) |
| CWE-798 | Use of Hard-coded Credentials | 3 | [CWE-798_hardcoded-shared-oauth-app-secret.md](CWE-798_hardcoded-shared-oauth-app-secret.md) |
| CWE-95 | Eval Injection | 3 | [CWE-95_jsonpath-script-expression-eval.md](CWE-95_jsonpath-script-expression-eval.md) |
| CWE-23 | Relative Path Traversal | 2 | [CWE-23_path-traversal-arbitrary-overwrite.md](CWE-23_path-traversal-arbitrary-overwrite.md) |
| CWE-306 | Missing Authentication for Critical Function | 2 | [CWE-306_blind-message-signing.md](CWE-306_blind-message-signing.md) |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | 2 | [CWE-829_unverified-remote-prompt-injection.md](CWE-829_unverified-remote-prompt-injection.md) |
| CWE-295 | (extension) | 1 | [CWE-295_caller-controlled-tls-verification-bypass.md](CWE-295_caller-controlled-tls-verification-bypass.md) |
| CWE-352 | (extension) | 1 | [CWE-352_oauth-state-not-validated.md](CWE-352_oauth-state-not-validated.md) |
| CWE-552 | Files or Directories Accessible to External Parties | 1 | [CWE-552_plaintext-token-file-default-permissions.md](CWE-552_plaintext-token-file-default-permissions.md) |
| CWE-915 | (extension) | 1 | [CWE-915_json-path-prototype-pollution.md](CWE-915_json-path-prototype-pollution.md) |
