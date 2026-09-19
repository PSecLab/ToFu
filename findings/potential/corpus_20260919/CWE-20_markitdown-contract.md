# CWE-20 — Improper Input Validation (1 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-19.** Each row is a ToFu oracle hit: an adversarial input tripped `markitdown-contract` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| dazeb/markdown-downloader | `download_markdown` | node | 0.000 | 3d4394b34b | check_strict_markitdown_security_contract | dazeb__markdown-downloader__download_markdown.log |
