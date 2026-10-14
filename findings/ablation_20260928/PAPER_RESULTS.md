# Ablation study — paper-ready results (for the writing agent)

Every number below is recomputed by `python3 findings/ablation_20260928/paper_numbers.py`
(stage + oracle tables, output `paper_numbers.json`), `repeat_numbers.py` (Full ToFu repeats,
Table E, output `repeat_numbers.json`) and
`python3 findings/ablation_20260928/allsan_labels/aggregate.py` (Table C, output
`allsan_labels/allsan_label_summary.json`) from the committed indices in this directory.
LaTeX tables: `tables.tex`. Write the paper as "we did X, the result is Y"; the section
"Internal provenance" at the bottom is NOT paper material.

## 1. Setup (what to say in the methodology)

- **Targets.** The 273-repository head-to-head set. As for every dynamic tool in the comparison
  (ToFu, Viper, ToolFuzz), the 7 host-control servers (shell/terminal, tmux, Frida, device and
  desktop control) are not executed, leaving **266 MCP servers and all 1,801 of their tools**.
  Every arm runs on exactly this set.
- **Budget and platform.** 60 s of fuzzing per tool, 12 parallel workers, one Linux host
  (16 threads, 32 GB), every target inside a bubblewrap filesystem sandbox.
- **Holding the other stage fixed.** LLM output (gpt-4.1, temperature 0, fixed seed) is recorded
  once and replayed. When one LLM stage is removed, the other stage receives exactly the LLM
  output of the full configuration, so each difference is attributable to the removed stage.
  Only the full configuration may call the LLM (it did for 5 tools with no recorded seeds); no
  ablated arm made a live LLM call.
- **Bug counting.** Same rule as the main results: one bug per (server, tool), classed by the
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
  sanitizer fire counts; failed executions included). The runtime tracer exists only for Python
  targets (in-process); JavaScript targets run out of process, so tracers-only is ~0 for JS **by
  construction** (the single JS row is a credential-pattern check on the tool's output, not a
  runtime observation) — say so in the table, do not present it as a finding.
- **Labelling the All-sanitizers reports (Table C).** Every report (census, 960) was labelled
  TP / TP-low / FP from its run evidence (triggering input, tool output, sanitizer analysis) and
  the server's source at the fuzzed commit, never by re-running targets. Rubric per class (e.g.
  log injection needs CR/LF from the caller's argument to reach a logger; path traversal needs the
  argument to reach a file operation without containment). TP-low = real but low impact, or the
  tool's documented purpose. Labelling was LLM-assisted with a fixed rubric and author
  spot-checks; state this.

## 2. Results

### Table A — LLM stages (2×2) and seeds

| arm | tools executed | bugs | servers | Δ vs full mean | tools shared / new / lost vs full run 1 |
|---|---|---|---|---|---|
| Full ToFu (3 runs) | 1,502 (1,495–1,507) | **430 ± 5** (427–436) | 136 † | — | — |
| No LLM seeds | 1,371 | 396 | 129 | −34 (−8%) | 345 / 51 / 91 |
| No LLM selection | 1,501 | 311 | 103 | −119 (−28%) | 266 / 45 / 170 |
| No LLM (both off) | 1,369 | 293 | 100 | −137 (−32%) | 245 / 48 / 191 |
| No seeds | 1,258 | 244 | 93 | −186 (−43%) | 213 / 31 / 223 |

"Tools executed" = tools with ≥1 successful call (of 1,801). Full ToFu = mean ± SD over three
independent runs (range in parentheses); every other arm is one run. Median throughput is
43.1–46.1 executions/s in every arm. † servers and the shared/new/lost columns, and Tables B–D,
use Full run 1 (436 bugs) as the reference.

### Table B — bugs by class

| class | Full | No LLM seeds | No LLM selection | No LLM | No seeds | All sanitizers |
|---|---|---|---|---|---|---|
| path traversal | 100 | 91 | 0 | 0 | 1 | 169 |
| SSRF | 38 | 43 | 4 | 0 | 42 | 58 |
| OS command injection | 4 | 2 | 0 | 0 | 2 | 38 |
| reflected XSS | 207 | 194 | 237 | 233 | 122 | 193 |
| log injection | 80 | 63 | 64 | 56 | 73 | 496 |
| data exfiltration | 4 | 2 | 4 | 2 | 1 | 4 |
| insecure temp file | 2 | 1 | 1 | 2 | 2 | 1 |
| hard-coded credentials | 1 | 0 | 1 | 0 | 1 | 1 |
| **total** | **436** | **396** | **311** | **293** | **244** | **960** |

### Table C — All sanitizers enabled (every report labelled)

| | Full ToFu (LLM selection) | All 73 sanitizers |
|---|---|---|
| tools executed | 1,507 | 1,512 |
| median executions/s | 43.1 | 43.5 |
| reported bugs | 436 | 960 |

| All-sanitizers reports | n | real (strict) | real (lenient) | false positives |
|---|---|---|---|---|
| all | 960 | 47 (4.9%) | 188 (19.6%) | 772 |
| on tools Full ToFu also flagged | 421 | 34 (8.1%) | 135 (32.1%) | 286 |
| **on tools Full ToFu did not flag** | **539** | **13 (2.4%)** | **53 (9.8%)** | **486 (90.2%)** |

Strict = TP; lenient = TP + TP-low.
**Full ToFu's false negatives** relative to All-sanitizers: 13 real bugs (strict; 53 lenient) on
tools Full ToFu did not flag, in 5 servers: SSRF 5 (one WordPress server), log injection 7,
reflected XSS 1. The SSRF group traces to a selection gap: for a JavaScript target the LLM chose
the runtime SSRF tracer, which only exists for Python targets, instead of the input-side URL
sanitizer. Enabling every sanitizer buys those 13 at the cost of 486 false reports (~37 per real bug).

### Table E — run-to-run variation of Full ToFu (three independent 60 s runs)

| | run 1 | run 2 | run 3 | mean ± SD |
|---|---|---|---|---|
| bugs | 436 | 428 | 427 | 430.3 ± 4.9 |
| tools executed | 1,507 | 1,503 | 1,495 | 1,501.7 |
| path traversal / SSRF / reflected XSS / log injection | 100 / 38 / 207 / 80 | 102 / 40 / 196 / 81 | 100 / 46 / 189 / 83 | |

Bugs found by all three runs: 342; by exactly two: 100; by only one: 65; by any: 507. Pairwise
Jaccard overlap of the bug sets: 0.75–0.81. The total is stable (±1%), which bug-tool pairs are
found varies: a single 60 s run is a sample of what the fuzzer can reach. Every ablation arm lies
outside the Full ToFu range (427–436); the smallest effect, No LLM seeds (396), is 34 bugs
(~7 SD) below the Full mean.

### Table D — oracle ablation (from the Full ToFu run)

| oracle | bugs | Python | JavaScript | tools shared / new / lost vs full |
|---|---|---|---|---|
| Full: sanitizer ∧ (success ∨ tracer) | 436 | 169 | 267 | — |
| Tracers only | 87 | 86 | 1 † | 87 / 0 / 349 |
| No tracer (sanitizer ∧ success) | 373 | 107 | 266 | 373 / 0 / 63 |
| No success requirement | 450 | 132 | 318 | 383 / 67 / 53 |

† No runtime tracer exists for out-of-process JavaScript targets; the single row is a
credential-pattern check on the tool's output.

## 3. Claims the data supports

1. **The LLM is not all of ToFu.** With both LLM stages removed (zero LLM cost), ToFu still
   reports 293 bugs, 68% of the full system (mean of three Full runs; Table A).
2. **LLM seeds buy reach.** Without them, 136 fewer tools execute successfully even once
   (1,507 → 1,371; 64 Python, 72 JavaScript) and 40 fewer bugs are found.
3. **LLM sanitizer selection buys bug classes, not volume.** Without selection, path traversal
   drops 100 → 0, SSRF 38 → 4 and command injection 4 → 0 (Table B). The bugs that remain are
   almost entirely reflected XSS and log injection, whose checks run on every call regardless
   of selection.
4. **Seeds matter more than either LLM stage alone.** An empty corpus loses 44% of the bugs and
   249 executing tools. With LLM selection kept in both, the deterministic seeds recover 152 of
   those 192 bugs without an LLM (No LLM seeds: 396 vs No seeds: 244).
5. **The runtime tracer contributes bugs no outcome check sees.** Removing it loses 63 bugs,
   62 of them Python (Table D).
6. **Selection is about precision, not speed.** Enabling all 73 sanitizers leaves throughput
   unchanged (43.5 vs 43.1 exec/s), so do NOT argue that selection saves time. It more than
   doubles the reports (960 vs 436), but 90% of the additional reports are false positives:
   13 real bugs (strict) for 486 false reports (Table C).
7. **Selection has a measurable miss.** Full ToFu misses 13 real bugs that All-sanitizers finds;
   5 are one server's SSRF, missed because the LLM chose a Python-only tracer for a JavaScript
   target. State this as a limitation / future work (language-aware selection).

## 4. Caveats to state

- **Why Full ToFu is 436 here, not the 508 headline.** The ablation's Full ToFu is ONE fresh 60 s
  run and is compared only against the other ablation arms (same code, budget, host). The 508
  headline is the deduplicated union of all campaigns (60 s sweeps, 24 h deep runs, and bugs
  observed on errored calls in an earlier sweep); 492 of the 508 lie on these 266 servers. Of
  those 492, this single run re-finds 363 tools and adds 73 new ones (436 = 492 − 129 + 73). The
  129 not re-found: 48 only from the earlier sweep's errored-call observations, 18 only from the
  24 h runs, 63 from 60 s sweeps that this run did not reproduce (run-to-run variation). Say:
  "Full ToFu in the ablation is a single fresh 60 s run; the headline aggregates all campaigns."
  (Recompute: `python3 findings/ablation_20260928/headline_vs_ablation.py`.)

- Full ToFu was run three times (Table E); the other arms once each. Every arm's difference from
  Full is far outside Full's own run-to-run range, so the conclusions do not depend on one run.
  Per-bug identity varies between runs (Jaccard 0.75–0.81), so compare totals and classes, not
  individual bugs, across arms.
- Counts in Tables A, B, D are reported bugs under the same rule as the main evaluation. Only
  the All-sanitizers reports are labelled (Table C); Full ToFu's own 436 are not labelled here.

## Internal provenance (not paper material)

- PSU PC, 2026-09-28, tmux `ablation`, `eval/run_ablation.sh`; health checks
  `eval/ablation_check.py` (switches recorded per row, cache hits, 0 live LLM calls in ablated arms).
- Scope history: first run on the 251 repos / 1,672 tools; extended the same day with the 15
  repos / 129 tools that complete the 266 dynamic set (same code, commit e310654, no `src/`
  change since f608f20). Earlier 251-only numbers live in `ablation_report_20260928.md`.
- Commits: abl-full rows 1–217 at be2529b, later rows f608f20 / e310654. The only runner change
  (a92dc8a, All-sanitizers crash fix) is unreachable in every other arm (`abl_commit_boundary.txt`).
- Full repeats: `eval/run_full_repeats.sh`, 2026-09-28 ~21:30 to 2026-09-29 02:59, commit c821e98 (no runner
  change since e310654), indices runs.abl-r2-full / runs.abl-r3-full, 0 live LLM calls, log
  `full_repeats.log`; numbers `repeat_numbers.py` -> `repeat_numbers.json`.
- newtype-01/obsidian-mcp deleted its own target directory while being fuzzed (inside the
  sandbox; nothing outside it was touched), so it could not start in nollm/noseeds/allsan. It was
  re-prepared before each of those three arms and its 11 tools re-run; the failed rows are kept
  in `quarantine-abl-*-obsidian-wiped.jsonl`.
- ToolFuzz shards from another session ran on the same PC until 04:29–04:43, overlapping the
  first ~15 min of abl-full (LLM-bound, low CPU).
- Replay cache `eval/state/llm_cache_ablation` (PC): 1,801 entries.
