# All-sanitizers arm: true/false-positive census (2026-09-28)

Census, not a sample: every one of the 928 bugs the All-sanitizers arm (`abl-allsan`, 251-repo
set, 1,672 tools) reported was labelled. Regenerate the numbers:
`python3 findings/ablation_20260928/allsan_labels/aggregate.py` -> `allsan_label_summary.json`.

## Method
- Evidence per bug: up to 3 triggering calls from the run log (input, tool output, ToFu's
  analysis, sanitizers that fired) — `extract_allsan.py` -> `allsan_evidence.json`.
- Source: each of the 185 repositories checked out at the exact fuzzed commit, read only
  (`repos_commits.txt`).
- Rubric: identical to the 2026-09-27 precision study (`../../labels_20260927/RUBRIC.md`), plus
  the All-sanitizers notes in `INSTRUCTIONS.md` (CR/LF must come from the caller's argument; an
  input sanitizer firing is not evidence the argument reached a sink).
- Labels: TP (real, security-relevant), TP-low (real but low impact, or the tool's documented
  purpose), FP, UNCLEAR. `basis: code-only` = the alert itself was incidental but the code shows
  the same weakness for the flagged argument.
- Labelled by 24 LLM agents (one per repository group, same rubric), coordinator spot-checks:
  kukapay/crypto-indicators-mcp (77 FP: brace-only echoes in plain-text errors; arguments never
  logged) and prathammanocha/wordpress-mcp-server (SSRF TP: caller `siteUrl` dialed by axios,
  src/index.ts:178; run log shows the connection to 127.0.0.1:8080). 0 UNCLEAR.

## Results

| | reports | TP | TP-low | FP | precision strict | precision lenient |
|---|---|---|---|---|---|---|
| All-sanitizers, all reports | 928 | 42 | 140 | 746 | 4.5% | 19.6% |
| … on tools Full ToFu also flagged | 393 | 29 | 100 | 264 | 7.4% | 32.8% |
| … on tools Full ToFu did not flag | 535 | 13 | 40 | 482 | 2.4% | 9.9% |

Strict = TP / reports; lenient = (TP + TP-low) / reports. 28 of the 42 TP are code-only; 14 rest
on the alert itself.

By class (strict / lenient): log injection 492 reports, 3.7% / 14.0%; reflected XSS 187,
5.3% / 13.4%; path traversal 148, 4.1% / 50.7%; SSRF 58, 12.1% / 12.1%; command injection 38,
2.6% / 13.2%; data exfiltration 4, 0 / 0; insecure temp file 1, 0 / 100%.

### What Full ToFu misses (its false negatives relative to All-sanitizers)
Real bugs All-sanitizers found on tools Full ToFu reported nothing for:
- **strict: 13** (6 alert-grounded, 7 code-only), in 5 repositories:
  - SSRF 5 — prathammanocha/wordpress-mcp-server (delete-user, get-clicks, get-user,
    remove-referrer-spam, update-user). Alert-grounded. Root cause: for this JavaScript server the
    LLM selected the runtime SSRF tracer, which does not exist for out-of-process JS targets, and
    not the input-side URL sanitizer that fired here.
  - log injection 7 — sunriseapps/imagesorcery-mcp (5, code-only), movibe/memory-bank-mcp
    log_decision (alert-grounded), dragon1086/kospi-kosdaq-stock-server (code-only).
  - reflected XSS 1 — CheMiguel23/MemoryMesh add_skills (code-only).
- **lenient: 53** (log injection 41, SSRF 5, path traversal 4, XSS 2, command injection 1;
  38 JavaScript, 15 Python).
- class level: 9 more TP/TP-low where Full ToFu flagged the tool but with a different class.

### The cost of enabling everything
On the 535 tools only All-sanitizers flagged, 482 reports (90.1%) are false positives: about
37 false reports per additional strict real bug (482 / 13), or 9 per additional lenient one.

## Caveats
- Labels come from code + run evidence, never from re-executing targets.
- The 129 configs added for the 266-repo set are not in this census yet (All-sanitizers arm
  still running on them when this was written).
- Full ToFu's own 408 reports are not labelled in this census; its precision is not stated here.
