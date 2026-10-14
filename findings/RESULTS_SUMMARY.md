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

## 1a. CONSOLIDATED bug count (2026-09-26, all sandboxed campaigns, deduped)  [HEADLINE]
> **PAPER HEADLINE = 508 bugs · 147 repos · 507 tools (Ananto's decision, 2026-09-27).**
> The 648 below minus the 140 SSRF bugs that rest only on `check_introspection_ssrf` (host not
> taken from the input: the server dialling its own default backend, item 20). Strict rule: an SSRF
> counts only when the contacted host came from the fuzzed input. 60 s: 493 (97%), >60 s: 15.
> Classes: reflected-xss 222, log-inj 122, path-trav 106, ssrf 42, temp-file 6, cmd-inj 5, exfil 4,
> creds 1. Regenerate: backend_dial set in findings/baselines/h2h_tofu_vs_viper_20260926.py.
> Baseline overlaps at 508 (ToFu-only/both/baseline-only): CodeQL 85/61/91, Cisco 128/18/30,
> Sonnet-5 72/75/137. The 14 host-set issues (§3) are dropped from the paper.

Union of every sandboxed campaign, distinct (repo, tool, class); budget = each bug's
earliest fuzz budget. Regenerate: `python3 findings/union_20260926/analyze_union.py`
(full report: findings/union_20260926/REPORT.md). insecure-temp-file shared-/tmp
artefacts excluded (private-/tmp sandbox removes them).

- **648 bugs · 154 repos · 647 tools.**
- By budget: **633 at 60 s/tool**, **15 required >60 s** (24 h deep run; first-appearance
  111 s–4,202 s). ~98% surface within 60 s.
- By class: reflected-xss 222, ssrf 182, log-injection 122, path-traversal 106,
  temp-file 6, os-command-injection 5, data-exfiltration 4, hardcoded-creds 1.
- Built from: 469 (60 s sandboxed reachable + recovered dead repos) + 150 net-new
  introspection-observed on tools that executed-but-errored (09-22, 60 s; SSRF dial /
  file read etc. fire legitimately; temp-file FPs excluded) + 29 from the 24 h deep run
  (14 were 60 s-reachable, 15 needed >60 s).
- Detection: outcome-divergence (sanitizer-flagged input accepted) or introspection
  (tracer observed the dangerous op: SSRF dial, /etc/passwd read, temp-file write).

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
| Cisco MCP Scanner (yara+llm+behavioral, c273, 2026-09-29) | 273 (266 ok) | 46 (yara 29, llm 14, behavioral 11) | 84 yara / 16 llm tools; behavioral 40 VULN + 30 THREAT tools (53 rows in 1 repo; 55% of checks inconclusive on gpt-4.1-mini) | static metadata + LLM + source behavioral | H2H-273 — `findings/cisco_c273_20260929/REPORT.md` |
| vanilla-claude-sonnet-5 | 484 | 214 | 891 flagged tools | LLM code-audit (unverified) | ✅ |
| ToolFuzz (H2H-273, 2026-09-28) | 266 = H2H-273 minus 7 unsafe; 1,516 / 1,585 executed tools (258 repos) | runtime 200 tools / 77 repos · correctness 114 tools / 52 repos · either 237 / 92 | runtime 200 erroneous / 517 tested prompts; correctness 342 erroneous / 3,441 prompts (not hand-checked; ToolFuzz's own FDR 46%) | tool-documentation failures (diff axis) | H2H-273 dynamic set |
| ~~ToolFuzz (H2H-45 re-run, 2026-09-25)~~ superseded by H2H-273 | 31 of H2H-45 (298 tools) | 8 tools genuine crash | | | |
| Viper-MCP (c251, 2026-09-28) | 266 = H2H-273 minus 7 unsafe (259 ok) | 48 static · 118 runtime sink · **11 confirmed** | 340 static taint flows; 11 distinct hit-judge-confirmed chains (4 on repos where ToFu reports 0) | CodeQL taint + LLM runtime agent, 3 classes | H2H-273 dynamic set |
| ~~Viper-MCP (H2H-45 re-run, 2026-09-26)~~ superseded by c251 | 45 | 11 static · 9 sink · 2 confirmed | | | |

Overlap (full): ToFu∩CodeQL 37, ToFu∩Cisco 14, vanilla∩ToFu 107 (100 ToFu-only /
107 vanilla-only, 47 vanilla-exclusive). Complementary, not redundant.
ToFu flags the 2nd-most repos (157), behind only the unverified LLM audit (214),
ahead of CodeQL (154) — and ToFu's are runtime-evidence-gated.

## 5. Head-to-head (45 ToFu-flagged repos, all tools same set)
> **Viper on the H2H-273 set (2026-09-28): `findings/viper_c251_20260928/REPORT.md`** (per-repo: `per_repo.json`).
> 266 repos (273 minus 7 unsafe), 259 ok, hook proven on all: Viper static 48, sink 118, confirmed 11;
> ToFu (508 on the 266) 139 repos / 493 bugs; Viper-confirmed where ToFu reports 0: 4 (code/command-exec tools).
> The H2H-45 figures below are superseded.
>
> **ToolFuzz on the H2H-273 set (2026-09-28): `findings/toolfuzz_h2h273_20260928/REPORT.md`** (paper brief `PAPER_NOTES.md`).
> Reported only in ToolFuzz's own units (verified with its `tool_stats.py`): runtime failures 200 tools / 77 repos
> (200 erroneous of 517 tested prompts); correctness failures 114 tools / 52 repos (342 erroneous of 3,441 prompts,
> not hand-checked). On the same 1,516 tools: both 62, ToolFuzz-only 175, ToFu-only 366.
> Report ToolFuzz's own 46% correctness FDR next to any ToolFuzz correctness figure.

ToFu 45/579 · CodeQL 11/111 · Viper 11/45 static (2 confirmed) · Cisco 3/13. **16 ToFu-exclusive.**
> **2026-09-26, at the 648 headline:** `baselines/h2h_tofu_vs_viper_20260926.md` (regen script alongside):
> ToFu 33/45 repos, 266 bugs (142 excl. backend-dial SSRF, item 20); Viper static 11, sink 9, confirmed 2
> (both ToFu-flagged, same class); 15 ToFu-exclusive vs CodeQL+Cisco+Viper. ToFu's 0 on mcp-gsc /
> bilibili / (obsidian 8 tools) is a sandboxed-sweep runner failure recorded ok=True, not a miss.
> **CORRECTION 2026-09-26 (recounted from Viper's own outputs) — the Viper figure above is not a finding count.**
> It counted `oracle.json` lines incl. the `hook_init` marker (hook loaded = 1). Viper's real results on all 45
> H2H repos: **confirmed 2** (memory-bank-mcp path traversal; paper-search), **runtime sink hits 9**,
> **static taint flows 11**. See `baselines/viper_h2h_corrected_20260926.md`. §4 Viper row updated.
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
