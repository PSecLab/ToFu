# Baseline comparison — full set_e2 corpus — 6 tools — 2026-09-19

> **UPDATE 2026-09-22 (see rerun_results_20260922.md):** after the reachability
> re-run + 2 new oracles, ToFu totals are now **627 candidates / 299 high-conf /
> 157 repos** (was 600/281/148); new reflected-xss class = 21 (18 hi). vanilla-
> claude-sonnet-5 also completed the full corpus (484 repos, 214 flagged) — it is
> now a 4th full-corpus tool. Figures below are the 09-19 snapshot; use the update
> for the headline.


Supersedes baseline_comparison_e2_20260918.md. All indices snapshotted in
findings/baselines/*_20260919.jsonl (+ vanilla-claude-sonnet-5/). ToFu run
complete: 6,153 configs, 481 repos, 5,551 ok (90%), 0 crashes.

## ⚠ Coverage is NOT uniform — only 3 tools cover the full corpus
| tool | repos covered | flagged repos | findings | axis | full corpus? |
|---|---|---|---|---|---|
| **ToFu** | 481 | 148 (sec-class) / 207 (any hit) | 600 candidates, 281 high-conf | runtime silent-bug | ✅ |
| CodeQL security-extended | 482 | 154 | 1,037 rule-matches | static SAST | ✅ |
| Cisco MCP Scanner (YARA) | 484 | 50 | 125 metadata hits | static metadata | ✅ |
| ToolFuzz | 59 | 43 | 2,030 discrepancies | correctness (diff axis) | ❌ partial |
| Viper-MCP | 38 | 5 | 12 (node-only) | static taint, 3 classes | ❌ partial |
| vanilla-claude-sonnet-5 | 75 | 53 | 240 flagged tools | LLM code-read | ❌ partial |

Units differ per tool — never a single ranked score. ToFu = oracle silent-bug
candidates (unconfirmed, mandatory layer not subtracted). CodeQL/Cisco = static
flags. ToolFuzz = description-conformance (a different question). Viper = taint on
3 classes only. vanilla-claude = an LLM's read verdict.

## Cross-tool comparison is only valid on the intersection
ToFu/CodeQL/Cisco all cover ~482 → their overlap numbers are apples-to-apples
(see below). ToolFuzz(59)/Viper(38)/vanilla(75) ran *different, smaller* subsets;
their columns are indicative only until extended to the full corpus.

### ToFu vs CodeQL vs Cisco (full corpus, repo-level)
- ToFu flagged 148 sec-class repos; CodeQL 154; Cisco 50.
- ToFu∩CodeQL and ToFu∩Cisco are largely disjoint (per the 0918 doc: ~37 and ~14
  overlap) — the three are complementary, not redundant.
- Where they disagree: see tofu_miss_analysis_20260919.md — of 87 repos others
  flagged but ToFu didn't, ~63% are ToFu reachability/coverage gaps, ~22% true
  runtime-oracle blind spots, ~15% Cisco static-capability flags.

## Coverage gaps + how to complete the 6-way
| tool | have | missing | how to run the rest (on the VM) |
|---|---|---|---|
| ToolFuzz | 59 | ~425 | `python3 eval/run_toolfuzz.py` (reads all prepared.jsonl, resumable, skips done). Expect ToolFuzz-internal errors (StructuredTool sync, recursion). EXECUTES tools → VM only. |
| Viper-MCP | 38 | ~446 | `python3 eval/run_viper.py --skip-codeql` — **node-only** (pyql exits 2 on python, item 95); models only cmd-inj / SSRF / path-traversal. |
| vanilla-claude-s5 | 75 | ~409 | rebuild shards for all ready repos (`findings/vanilla-claude-sonnet-5/_scripts/build_shards.py`) then re-run the Sonnet-5 verdict prompt over `shards/*.json` → `shards/out/*.jsonl`. |

## vanilla-claude-sonnet-5 (new baseline)
Sonnet-5 read each tool's code (repo + tool + code hints per shard) and returned a
per-tool verdict. 75 repos, 2,486 tools: **2,246 clear, 240 flag** across 53 repos.
An LLM-code-audit baseline (no execution, no taint) — complementary to ToFu's
runtime evidence; its 240 flags are unverified LLM judgments (verdict="flag").

## Notes
- Viper's python column is an analysis error, not a clean result (pyql exit 2,
  item 95) — report Viper node-only unless item 95 is fixed.
- ToFu 148 vs 207: 148 = security-exploitable classes (path-trav/ssrf/log-inj/
  cmd-inj/temp-file/creds, triage_findings.py); 207 = any finding_hits incl.
  robustness + mandatory-layer noise. Use 148 (or 281 high-conf configs) for the
  headline; 207 only for the miss-set arithmetic.
