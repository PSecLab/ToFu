# ToFu — consolidated results + comparisons (source of truth for the paper)

Last updated 2026-09-26. Every number traces to committed indices in
findings/baselines/*.jsonl and the docs cited per section. This is the single
headline reference; the dated docs hold the detail.

## 1. Dataset funnel
| stage | count | source |
|---|---|---|
| MCPCorpus records | 13,875 | lin2025mcpcorpus, mcpso_servers_cleaned.json |
| after filter (GitHub repo, ≥10 stars, not archived, not client) | 2,501 | |
| dedup by repository | 2,222 | |
| Python + Node only (excl. Go 154, Rust 41, Java 34, C# 19, PHP 17, …) | 1,847 | 808 py + 1,039 node |
| static extraction succeeded | 1,778 | 69 failed: 52 deleted/private, 13 clone err, 4 timeout |
| **tool-exposing (≥1 tool)** | **1,404** | 597 py + 807 node, **24,194 tools** |
| set_e2 prepared + ready (fuzzable) | **482** | prepared.jsonl status=ready |
| runnable + tool invoked + fuzzable | **408** | |
| **cleanly executable (tool returned success ≥1 input)** | **249** | the honest reachable denominator |

Framing: 482→249 drop is repo-side (creds/backends/runtime errors), not ToFu —
static tools "work" only because they never execute.

## 1a. CONSOLIDATED current candidates (2026-09-26, all sandboxed runs, deduped)
Union of the three campaigns by distinct (repo, tool, class), all under bubblewrap,
current oracles, no confidence tier. **Candidates, unconfirmed** (hand-verified
precision owed).

- **498 candidates across 143 repos / 497 tools.**
- By class: reflected-xss 222, path-traversal 101, log-injection 85, ssrf 76,
  insecure-temp-file 6, os-command-injection 4, data-exfiltration 4.
- **By fuzz budget** (from each bug's first-appearance time on the stitched tool
  clock, not just which run saw it): **483 within 60 s**, **15 genuinely required
  >60 s** (111 s up to 4,202 s; e.g. ddukbg/github-enterprise-mcp::list-workflows).
  Of the 29 that show only in the 24 h runs, 14 first appeared <=60 s (60 s-reachable;
  missing from the 60 s sweep only because those exact configs were unsafe-skipped or
  outside the reachable set) and 15 first appeared >60 s (the real long-budget wins).
  So the 24 h budget adds 15 candidates over 60 s. (An earlier "~1 from budget" figure
  compared against the pre-sandbox 09-22 corpus, which lacked the reflected-xss tracer;
  15 is the current-oracle number. Most bugs still surface within 60 s -- efficiency
  holds -- but the long budget is not zero.)

### Internal provenance only -- NOT paper narrative (paper reports the final method + number, not our phases)
The pre-sandbox 09-22 run reported 627. The change to the current numbers is:
- **Scope/definition.** The sandboxed sweep counts candidates only on tools that
  RETURNED SUCCESS >=1 (the reachable denominator). 09-22 also counted 249 candidates
  on tools that executed but errored on every input (n_exec>0, n_exec_success=0); a
  tracer still fired -- often legitimately (e.g. 129 SSRF = the introspection tracer
  caught the outbound dial to an internal host before the connection failed). These
  are NOT junk; the sandboxed count simply excludes them, so it is CONSERVATIVE.
  Decision owed: keep the success>=1 gate (current 498) or also credit
  introspection-observed hits on tools that only error.
- **FP removal.** insecure-temp-file went 142 -> 6 corpus-wide: the unsandboxed run
  shared one /tmp across 5 concurrent configs, so a config flagged temp files другие
  configs left. The private-/tmp sandbox removes these harness artefacts.
- On the identical 1,481 reachable configs, sandboxed vs 09-22: 370 -> 413.
- The paper should state only the final result (498 candidates / 143 repos, sandboxed,
  on tools driven to success), not this delta.

## 1b. Sandboxed re-runs (2026-09-26) — READ THESE FOR THE CURRENT NUMBERS
Three campaigns after the sandbox + the two new tracers (reflected-xss, exfil) landed.
All under bubblewrap; no confidence tier (item 17: success rate = reachability only).
Each has its own report with per-repo tables + regen scripts; candidates unconfirmed.

- **Reachable corpus, sandboxed** (`findings/corpus_sbx_20260926/REPORT.md`, arm
  gpt41-corpus-sbx): the 1,481 reachable configs (250 repos) on current oracles.
  **413 candidates / 123 repos** (reflected-xss 189, path-trav 94, log-inj 73, ssrf 48,
  cmd-inj 4, exfil 4, temp-file 1). vs the 09-22 run on the same configs: +183 new
  (175 from the new tracers), −140 gone — of which **77 insecure-temp-file were
  shared-/tmp false positives** the private-/tmp sandbox removes (class 78→1).
- **24h deep budget** (`findings/repo24_20260926/REPORT.md`, RQ4): 34 repos, 129
  candidates; only 1 attributable to budget alone (rest are oracle-extension); bugs
  surface early (116/157 first-appearances within 60 s). Long budget ≈ saturation.
- **Recovery of dead repos** (`findings/recover_pc_20260926/REPORT.md`): the 231 repos
  with 0 reachable tools in 09-22, re-prepared on the PC's open egress. 21 repos / 58
  tools recovered to success; 56 net-new candidates (9 from new tracers). Confirms the
  482→249 drop is creds/backends, with a minority of schema-gated seed misses.

**For the eval writer:** the corpus-scale headline is now the sandboxed sweep (413 on
the reachable set) plus these three reports. The 627 below is the pre-sandbox 09-22
number (kept for provenance/comparison, includes the temp-file FPs now known to be
shared-/tmp artefacts).

## 2. ToFu headline (full set_e2, 2026-09-22, post re-run)
- 481 repos fuzzed, **5,551/6,153 configs ok (90%)**, 0 crashes (after item-91 cwd
  + $TMUX isolation + 16-repo unsafe-skip).
- **627 real-vuln candidates / 157 repos.** (A former "299 high-confidence (succ≥0.5)" tier is withdrawn: tool-level exec-success rate is reachability, not evidence about a given alert (the oracle already requires per-input success), so it is no longer used to tier or filter candidates. Quality = hand-verified precision, owed.)
- By security class (any-succ): log-injection 135, ssrf 199, insecure-temp-file 142,
  path-traversal 121, reflected-xss 21, os-command-injection 7, hardcoded-creds 2.
- The auto-triage classifier (eval/triage_findings.py) filters oracle hits →
  security-exploitable classes, dedups by (repo,tool,class), tiers by success rate.
  UNCONFIRMED candidates (mandatory layer not subtracted; FP pass owed).

## 3. Confirmed / hand-verified exploits
14 hand-verified across the host-39 set (tab:identified_issues in the paper):
local file access, path traversal (HAR/ZIP), arbitrary write, DoS/crash, log
injection, missing-auth, fail-open init, temp-file leak, deprecated-API. These
are the confirmed subset; the 627 are the corpus-scale candidate set.

## 4. Baseline comparison (full set_e2) — units differ, NOT one leaderboard
| tool | repos covered | repos flagged | findings | axis | full corpus? |
|---|---|---|---|---|---|
| **ToFu** | 481 | **157** | 627 candidates | runtime silent-bug | ✅ |
| CodeQL sec-extended | 482 | 154 | 1,037 | static SAST | ✅ |
| Cisco MCP Scanner (YARA) | 484 | 50 | 125 | static metadata | ✅ |
| vanilla-claude-sonnet-5 | 484 | 214 | 891 flagged tools | LLM code-audit (unverified) | ✅ |
| ToolFuzz (H2H re-run, 2026-09-25) | 31 of H2H-45 (298 tools) | 8 tools genuine crash | 51 tools runtime (own def.), 8 crash; correctness 35 by formula → **0** genuine (all were tool errors) | tool-doc robustness/correctness (diff axis) | ❌ H2H only |
| Viper-MCP | 38 | 5 | 12 | static taint, 3 classes (node-only) | ❌ partial |

Overlap (full): ToFu∩CodeQL 37, ToFu∩Cisco 14, vanilla∩ToFu 107 (100 ToFu-only /
107 vanilla-only, 47 vanilla-exclusive). Complementary, not redundant.
ToFu flags the 2nd-most repos (157), behind only the unverified LLM audit (214),
ahead of CodeQL (154) — and ToFu's are runtime-evidence-gated.

## 5. Head-to-head (45 ToFu-flagged repos, all tools same set)
ToFu 45/579 · CodeQL 11/111 · Viper 23-of-35/45 · Cisco 3/13. **16 ToFu-exclusive.**
(ToFu-selected → demonstrates unique catches, not blanket superiority.)
Per-repo breakdown of all 45 (every tool, incl. ToolFuzz+vanilla columns):
head_to_head_per_repo_20260922.md — after security-class triage: ToFu 30/45 repos,
12 ToFu-exclusive vs all 3 static comparators (the 16 above is the looser raw-hit
measure). Coverage-vs-time for the 8 recovered re-run repos:
coverage_rerun_20260922.png (coverage keeps climbing past the 60s budget).

## 6. Miss-analysis (repos others flagged, ToFu didn't; post-rerun 76, was 87)
Of the 87 original: **~63% reachability/coverage-fixable** (item-94 in-process
discovery = biggest lever; JS startup hangs; schema/cred/format input gates — only
6.2% of miss-configs reached a live tool call) · **~22% true runtime-oracle blind
spots** · **~15% Cisco static-capability flags**. Re-run recovered **11/27** of a
hard subset (7 via the new reflected-xss oracle, 4 via 5× budget) — empirical
backing for the "fixable" majority.

## 7. Oracle inventory + construction (defend in paper)
**21 sink tracers** (== 21 sink families in the corpus scan) + ~30 evidence
channels; **73 registered sanitizers** (75 check_ defined; 10 BASE_MANDATORY
always-on + 63 LLM/evidence-selected). Each maps to a CWE; derived from the MCP
tool threat surface + observed sink families + prior-work coverage; 2 newest
(check_introspection_exfil CWE-201, check_reflected_output CWE-79/116) were
miss-analysis-driven.

## 8. Deliberate scope (blind spots — report as design boundary, not weakness)
No runtime oracle for: CORS-permissive (static config, no runtime event),
regexp/sanitization correctness (latent, no event + unknown intended contract),
TOCTOU file-system-race (needs concurrency; ToFu is single-input). These are
static-analysis territory (CodeQL complements). prototype-pollution/ReDoS/XXE
DO have oracles → those misses are reachability, not absence.

## Docs (findings/baselines/)
baseline_comparison_full_20260919.md, tofu_miss_analysis_20260919.md,
head_to_head_results_20260921.md, head_to_head_per_repo_20260922.md (+ .json),
rerun_results_20260922.md, coverage_rerun_20260922.png (+ .json + plot_cov_rerun.py),
REAL_vulns_20260919.md, head_to_head_shortlist_20260920.md; index snapshots *_2026091{9}/22.jsonl;
harvest findings/potential/corpus_20260919/. Paper-notes: ToFu_src/nazmul.todo items 10–11.
