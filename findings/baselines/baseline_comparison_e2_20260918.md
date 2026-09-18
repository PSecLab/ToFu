# Baseline comparison — set_e2 corpus scale — ToFu vs CodeQL (Cisco pending) — 2026-09-18

Scale point beyond host-39: the whole executable pool (`set_e2`, the 482 repos
that cloned+installed+exposed tools). Supersedes the host-39 tables for corpus
scale; host-39 stays the 4-tool apples-to-apples micro-comparison.

## ⚠ Read this before the numbers
- **The ToFu run is INCOMPLETE.** It fuzzed **196 / 482** repos, then a fuzzed
  target (`m-ahmed-elbeskeri/UltimateCoderMCP::tool_delete_path`) deleted the
  harness working tree mid-run (item 91, cwd=ROOT). The other 286 repos never
  ran. Results for the 196 are intact and backed up; the rest await the
  item-91 fix + re-run. Treat every ToFu number here as **196-repo partial**.
- **CodeQL is complete** (static, no execution → unaffected): 480/482 analyzed.
- **Cisco YARA is pending**: a FRESH scanner clone (newer HEAD) regressed and
  throws `UnboundLocalError: os` on every target that fails to start (0/8 on
  set_e2). Root-caused as a version regression -- run_cisco_scanner.py now pins
  the known-good v4.8.4 (16e684d8bd8f, the 2026-09-11 baseline build) in setup.
  Re-run after `--setup` re-pins + rebuilds the venv. Column open until then.
- Units differ (unchanged): ToFu = oracle silent-bug **candidates** (adversarial
  input tripped a sanitizer AND the tool returned success), auto-triaged, NOT
  hand-verified, mandatory layer not subtracted (CLAUDE.md §2). CodeQL = static
  security-extended rule matches, unconfirmed. Never a single ranked score.

## Apples-to-apples: the 196 repos ToFu actually covered
| tool | repos flagged | findings | scope |
|---|---|---|---|
| **ToFu** | **102** | 459 finding-configs (candidates) | 196/196 covered |
| CodeQL (restricted to those 196) | 71 | 370 rule-matches | 194/196 analyzed |
| Cisco YARA | — | — | scanner erroring (pending) |

**Repo-level overlap on the 196:** both **37**, **ToFu-only 65**, CodeQL-only 34.
→ ToFu flags more repos (102 vs 71) and has ~2× the unique repos (65 vs 34).

## For reference — full scope (different denominators, NOT apples-to-apples)
| tool | repos flagged | findings | analyzed |
|---|---|---|---|
| ToFu | 102 | 459 finding-configs | 196 repos (partial) |
| CodeQL | 154 | 1037 rule-matches | 480 repos |

CodeQL's extra reach (154 vs 102) is mostly the 286 repos ToFu never ran +
static-only classes; not evidence ToFu missed them (it never fuzzed them).

## ToolFuzz — separate axis (correctness, NOT security)
ToolFuzz (prior work) ran on the VM: **56 repos covered, 2030 correctness
discrepancies across 43 repos** (0 runtime failures; its own summarizer labels
these "behaviour observations, not security findings"). It measures whether a
tool behaves as its *description* says — a different question than ToFu/CodeQL/
Cisco ask — so it is NOT merged into the security table. Overlap with ToFu's 196:
only **11 repos**. Reported as a complementary correctness baseline, its own unit.

| tool | axis | count | repos | scope |
|---|---|---|---|---|
| ToolFuzz | correctness/description-conformance | 2030 discrepancies | 43 | 56 covered |

## ToFu candidates by class (harvest, 450 across the 196 — findings/potential/corpus_20260917/)
security-relevant: log-injection 76, insecure-temp-file 72, ssrf 52,
path-traversal 47, os-command-injection 5, hardcoded-credentials 1
(+ the destructive UltimateCoderMCP arbitrary-delete, filed separately).
lower-signal: type-confusion 115, improper-input-validation 37,
resource-exhaustion 21, uncaught-exception 5, fd-leak 7, unclassified 11.

## CodeQL top rules (full scope)
js/file-access-to-http 241, js/file-system-race 120, js/insecure-temporary-file 97,
py/clear-text-logging-sensitive-data 94, js/log-injection 84, js/http-to-file-access 50,
js/incomplete-sanitization 37, py/incomplete-url-substring-sanitization 30,
js/clear-text-logging 24, js/insecure-randomness 21, js/indirect-command-line-injection 20.

## Read
- On identical repos, ToFu and CodeQL are **complementary, not redundant**: only
  37 of ToFu's 102 finding-repos overlap CodeQL; 65 are ToFu-only (runtime
  silent-bugs static did not flag), 34 are CodeQL-only (static classes ToFu did
  not confirm at runtime, e.g. clear-text-logging, file-system-race, weak PRNG).
- ToFu's SSRF (52) and log-injection (76) partly overlap CodeQL's URL/log rules;
  path-traversal (47) and command/exec are largely ToFu-unique at runtime.
- Numbers are candidates/flags, not confirmed counts. Confirmation + FP triage +
  mandatory-layer subtraction still owed before any published figure.

## To finish this comparison
1. Land item 91 (cwd isolation), rebuild .venv, regenerate configs, re-run the
   286 missing repos (196 cached → cheap) → full 482 ToFu column.
2. Fix/patch the Cisco scanner startup-failure path → Cisco YARA column.
3. Triage a sample of ToFu candidates + CodeQL flags for a defensible FP rate.
