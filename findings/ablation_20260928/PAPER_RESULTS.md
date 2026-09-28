# Ablation study — paper-ready results (for the writing agent)

Every number below is recomputed by `python3 findings/ablation_20260928/paper_numbers.py`
from the committed indices `runs.abl-*.jsonl` in this directory (output: `paper_numbers.json`).
LaTeX tables: `tables.tex`. Write the paper as "we did X, the result is Y"; the section
"Internal provenance" at the bottom is NOT paper material.

## 1. Setup (what to say in the methodology)

- **Targets.** The 251 MCP server repositories on which ToFu executed at least one tool call
  successfully in the main 60 s evaluation; all 1,672 tools (configs) of those repositories.
  Every arm runs on exactly this set.
- **Budget and platform.** 60 s of fuzzing per tool, 12 parallel workers, one Linux host
  (16 threads, 32 GB), every target inside a bubblewrap filesystem sandbox.
- **Holding the other stage fixed.** LLM output (gpt-4.1, temperature 0, fixed seed) is recorded
  once and replayed. When one LLM stage is removed, the other stage receives exactly the LLM
  output of the full configuration, so each difference is attributable to the removed stage.
  No arm made a live LLM call.
- **Bug counting.** Same rule as the main results: one bug per (repository, tool), classed by the
  most severe security-relevant sanitizer that fired.
- **Arms.**
  | arm | LLM seeds | LLM sanitizer selection | notes |
  |---|---|---|---|
  | Full ToFu | yes | yes | |
  | No LLM seeds | deterministic seeds | yes | |
  | No LLM selection | yes | 10 always-on sanitizers only | |
  | No LLM | deterministic seeds | 10 always-on sanitizers only | zero LLM cost |
  | No seeds | none (empty corpus) | yes | plain coverage-guided fuzzing over the tool schema |
  | All sanitizers | yes | all 73 sanitizers enabled | "why not enable everything?" |
- **Deterministic seed generator** (used by "No LLM seeds" and "No LLM"; describe it in the
  design/implementation section). From the tool's JSON schema, with no LLM:
  1. a valid default per field (first enum member, `1`, `true`, `[]`, `{}`, `"test"`);
  2. per field, one seed per boundary value: every enum member plus one out-of-enum value;
     numbers `0, -1, 2^31-1, -2^31, ±1e308, null`; both booleans; malformed arrays
     (`[]`, `[null]`, mixed types) and objects (empty, nested three levels);
  3. per string field, 5 adversarial payloads from a curated seed bank (6 categories, 52 payloads:
     path traversal 10, SQL injection 10, SSRF URLs 10, XSS/markdown 10, wildcards 7, XML bombs 5).
     The category comes from the selected sanitizers; if none maps, from keywords in the field
     name/description (`url`, `path`, `query`, …);
  4. type-confusion seeds (wrong JSON type per field) and the all-defaults seed; duplicates removed.
  The LLM seed stage adapts payloads from the same seed bank to the tool, so "No LLM seeds"
  isolates the LLM's adaptation, not access to attack payloads.
- **"No seeds".** libFuzzer starts from an empty corpus; raw bytes are decoded into
  schema-conforming arguments, so the tool still receives well-typed calls.
- **Oracle ablations** are computed from the Full ToFu run's logs (no extra run). ToFu reports a
  bug when a sanitizer flags the input AND the tool returns success, OR when the runtime tracer
  observes the dangerous operation. We recompute the bug set with (a) tracers only, (b) the
  tracer removed (sanitizer + success only), (c) the success requirement removed (every
  sanitizer fire counts; failed executions included). The tracer exists only for Python targets
  (in-process); JavaScript targets run out of process, so tracers-only is 0 for JS **by
  construction** — say so in the table, do not present it as a finding.

## 2. Results

### Table A — LLM stages (2×2) and seeds

| arm | tools executed | bugs | repos | Δ vs full | tools shared / new / lost vs full |
|---|---|---|---|---|---|
| Full ToFu | 1,450 | **408** | 130 | — | — |
| No LLM seeds | 1,328 | 369 | 124 | −39 (−10%) | 321 / 48 / 87 |
| No LLM selection | 1,455 | 303 | 98 | −105 (−26%) | 259 / 44 / 149 |
| No LLM (both off) | 1,321 | 286 | 96 | −122 (−30%) | 239 / 47 / 169 |
| No seeds | 1,209 | 223 | 89 | −185 (−45%) | 195 / 28 / 213 |

"Tools executed" = tools with ≥1 successful call (of 1,672). Median throughput is 44.6–46.3
executions/s in every arm.

### Table B — bugs by class

| class | Full | No LLM seeds | No LLM selection | No LLM | No seeds | All sanitizers |
|---|---|---|---|---|---|---|
| path traversal | 95 | 85 | 0 | 0 | 1 | 148 |
| SSRF | 24 | 27 | 4 | 0 | 27 | 58 |
| OS command injection | 4 | 2 | 0 | 0 | 2 | 38 |
| reflected XSS | 200 | 189 | 230 | 226 | 117 | 187 |
| log injection | 80 | 63 | 64 | 56 | 73 | 492 |
| data exfiltration | 4 | 2 | 4 | 2 | 1 | 4 |
| insecure temp file | 1 | 1 | 1 | 2 | 2 | 1 |
| **total** | **408** | **369** | **303** | **286** | **223** | **928** |

### Table C — All sanitizers enabled

| | Full ToFu (LLM selection) | All 73 sanitizers |
|---|---|---|
| tools executed | 1,450 | 1,456 |
| median executions/s | 45.7 | 45.9 |
| reported bugs | 408 | 928 |
| tools shared / new / lost | — | 393 / 535 / 15 |

**Labelled (census of all 928 reports; `allsan_labels/REPORT.md`).**

| All-sanitizers reports | n | real (strict) | real (lenient) | false positives |
|---|---|---|---|---|
| all | 928 | 42 (4.5%) | 182 (19.6%) | 746 |
| on tools Full ToFu also flagged | 393 | 29 (7.4%) | 129 (32.8%) | 264 |
| on tools Full ToFu did not flag | 535 | 13 (2.4%) | 53 (9.9%) | 482 (90.1%) |

Strict = TP; lenient = TP + TP-low (real but low impact or the tool's documented purpose).
**Full ToFu's false negatives** relative to All-sanitizers: 13 real bugs (strict; 53 lenient) on
tools Full ToFu did not flag, in 5 repositories. The largest group, 5 SSRF bugs in one
WordPress server, traces to a selection gap: for a JavaScript target the LLM chose the runtime
SSRF tracer, which only exists for Python targets, instead of the input-side URL sanitizer.
Enabling every sanitizer buys those 13 at the cost of 482 false reports (~37 per real bug).

### Table D — oracle ablation (from the Full ToFu run)

| oracle | bugs | Python | JavaScript | tools shared / new / lost vs full |
|---|---|---|---|---|
| Full: sanitizer ∧ (success ∨ tracer) | 408 | 154 | 254 | — |
| Tracers only | 85 | 85 | 0 † | 85 / 0 / 323 |
| No tracer (sanitizer ∧ success) | 347 | 93 | 254 | 347 / 0 / 61 |
| No success requirement | 408 | 118 | 290 | 357 / 51 / 51 |

† No tracer exists for JavaScript targets; 0 by construction.

## 3. Claims the data supports

1. **The LLM is not all of ToFu.** With both LLM stages removed (zero LLM cost), ToFu still
   reports 286 bugs, 70% of the full system (Table A).
2. **LLM seeds buy reach.** Without them, 122 fewer tools execute successfully even once
   (1,450 → 1,328; 64 Python, 58 JavaScript) and 39 fewer bugs are found.
3. **LLM sanitizer selection buys bug classes, not volume.** Without selection, path traversal
   drops 95 → 0, SSRF 24 → 4 and command injection 4 → 0 (Table B). The bugs that remain are
   almost entirely reflected XSS and log injection, whose checks run on every call regardless
   of selection.
4. **Seeds matter more than either LLM stage alone.** An empty corpus loses 45% of the bugs and
   241 executing tools. With LLM selection kept in both, the deterministic seeds recover 146 of
   those 185 bugs without an LLM (No LLM seeds: 369 vs No seeds: 223).
5. **The runtime tracer contributes bugs no outcome check sees.** Removing it loses 61 bugs, all
   Python (Table D).
6. **Selection is about precision, not speed.** Enabling all 73 sanitizers leaves throughput
   unchanged (45.9 vs 45.7 exec/s), so do NOT argue that selection saves time. It more than
   doubles the reports (928 vs 408), but 90% of the additional reports are false positives: 13 real
   bugs (strict) for 482 false reports (Table C).
7. **Selection has a measurable miss.** Full ToFu misses 13 real bugs that All-sanitizers finds;
   5 are one server's SSRF, missed because the LLM chose a Python-only tracer for a JavaScript
   target. State this as a limitation / future work (language-aware selection).

## 4. Caveats to state

- One run per arm. Run-to-run variation is being measured with two additional Full ToFu runs;
  until then, report the −10% of "No LLM seeds" as indicative (the per-tool churn is visible
  in the shared/new/lost columns).
- Labelling (Table C) is by LLM agents applying a fixed rubric to run evidence + source at the
  fuzzed commit, with coordinator spot-checks; say so in the methodology.
- Counts are reported bugs under the same rule as the main evaluation; precision applies to
  every arm equally.

## Internal provenance (not paper material)

- PSU PC, 2026-09-28 04:28–~17:50, tmux `ablation`, `eval/run_ablation.sh`; health checks
  `eval/ablation_check.py` (switches recorded per row, cache hits, 0 live LLM calls).
- Commits: abl-full rows 1–217 at be2529b, all later rows at f608f20. The only runner change
  between them (a92dc8a, All-sanitizers crash fix) is unreachable in every other arm
  (`abl_commit_boundary.txt`, nazmul.todo items 25/28).
- Replay cache `eval/state/llm_cache_ablation` (PC): 1,672 entries, never written during the campaign.
