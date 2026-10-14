# Head-to-head (H2H) results + holistic review — 2026-09-21

> **NOTE 2026-09-26:** the "high-confidence (succ≥0.5)" tier used below is withdrawn — tool-level exec-success rate is reachability, not evidence about a given alert (the oracle already requires per-input success), so it is no longer used to tier or filter candidates. Candidate totals below are unaffected; see findings/RESULTS_SUMMARY.md.


The **H2H** subset = 45 repos ToFu flagged (all classes), stratified by bug-count
(15 hi / 15 mid / 15 lo), chosen to be ToFu-dominant vs CodeQL/Cisco. Viper +
Cisco(YARA+LLM) were then run on the *same* repos. This measures **what ToFu
catches that the baselines miss** — it is deliberately ToFu-selected, so it is
NOT a blanket "ToFu wins" claim (the reverse — repos ToFu missed — is in
tofu_miss_analysis_20260919.md).

## Coverage on H2H
Cisco YARA+LLM: 44/45 (1 repo errored). Viper: 35/35 node repos.

## All-way, repo-level (on the 45)
| tool | repos flagged | total findings | unit |
|---|---|---|---|
| **ToFu** | **45 / 45** (by construction) | **579** | runtime silent-bug candidates |
| CodeQL | 11 / 45 | 111 | static SAST rule matches |
| Cisco YARA+LLM | 3 / 45 | 13 | metadata YARA/LLM flags |
| Viper | 23 / 35 node | 45 | taint-to-sink oracle hits |

**16 of 45 repos are ToFu-EXCLUSIVE** — no other tool flags them at all
(meilisearch, alaturqua/mcp-trino, neka-nat/freecad, vinayak-mehta/mcp-browser-use,
aminforou/mcp-gsc, rishijatia/fantasy-pl, sworddut/mcp-ffmpeg-helper, graphlit,
the memory-bank servers, …).

## Where the baselines DID reach (honest)
- `taylorwilsdon/google_workspace_mcp` — ToFu 105, **CodeQL 59**, Cisco 5: CodeQL's 59 are static classes (clear-text-logging etc.), largely disjoint from ToFu's runtime hits.
- `tisik79/MCP-Facebook` — ToFu 18, **CodeQL 28** (CodeQL found MORE here — a static-class-dense repo), Viper 0.
- `Antonytm/mcp-sitecore-server` — ToFu 86, CodeQL 4, Cisco 7, Viper 0.
- Viper was surprisingly active (23/35), but its taint-hits **don't track ToFu's count** (matlab-mcp ToFu 1 / Viper 5; bilibili ToFu 1 / Viper 3) — a different methodology + unit, and its hits are unverified taint-oracle events, not confirmed vulns.
- Cisco YARA+LLM is very sparse on this set (3/45) — metadata signatures rarely match these runtime bugs.

**Units differ — this is not a single leaderboard.** Each "finding" is a different
object (silent-bug candidate vs static match vs metadata flag vs taint hit).

## Holistic review of the whole evaluation

**Scale.** Full set_e2 corpus: 481 repos fuzzed by ToFu (5,551/6,153 configs ok,
90%, 0 crashes after the item-91/TMUX/unsafe-skip fixes). ToFu produced **600
real-vuln candidates (281 high-confidence) across 148 repos**.

**Coverage (only 3 of 6 tools cover the full corpus):** ToFu 481, CodeQL 482,
Cisco 484; ToolFuzz 59, Viper 38, vanilla-claude-s5 75 (partial — extend via the
commands in baseline_comparison_full_20260919.md).

**Complementarity, not redundancy.** On the full corpus ToFu∩CodeQL and ToFu∩Cisco
are largely disjoint; on H2H, 16/45 repos are ToFu-exclusive and CodeQL/Cisco reach
only 11/3. ToFu's runtime silent-bug oracle finds a large class of bugs static SAST
+ metadata scanners do not.

**Where ToFu misses (tofu_miss_analysis).** Of 87 repos others flagged but ToFu
didn't: ~63% reachability/coverage gaps ToFu could fix (item-94 in-process
discovery — biggest lever; JS startup hangs; schema/credential/format input
gates — only 6% of miss configs reached a successful tool call); ~22% true
runtime-oracle blind spots (TOCTOU race, XSS, CORS, prototype pollution, regexp/
sanitization correctness, dataflow exfil — classes with no runtime *event* to
observe, or needing a render/concurrency context ToFu lacks); ~15% Cisco static
capability flags. ToFu already *has* oracles for prototype-pollution/ReDoS/XXE —
those misses are reachability, not oracle absence. The one genuinely addable
oracle is a file-read→network-send correlation tracer (exfil).

**Bottom line.** ToFu's value is runtime confirmation of a bug class the other
tools structurally can't reach; its misses are majority-fixable infrastructure
(dominated by the item-94 discovery gap), with an irreducible ~35–40% blind spot
in static-only classes. The other tools remain complementary: CodeQL for
static-only classes (races, clear-text-logging, regexp), Cisco for capability
signatures, Viper for 3-class taint (node), vanilla-claude for LLM code-audit.

## Caveats (binding)
- ToFu findings are UNCONFIRMED oracle candidates; mandatory-sanitizer layer not
  subtracted (CLAUDE.md §2). Hand-verification + FP triage still owed.
- H2H is ToFu-selected → shows ToFu's unique catches, not overall superiority.
- Viper hits are taint-oracle events (unverified); Viper is node-only (pyql broken,
  item 95). ToolFuzz/Viper/vanilla-claude ran partial subsets — cross-tool totals
  are only apples-to-apples on the intersection.
