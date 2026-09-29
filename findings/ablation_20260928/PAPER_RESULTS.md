# Ablation study — paper-ready results (for the writing agent)

Every number below is recomputed by `python3 findings/ablation_20260928/paper_numbers.py`
(stage + oracle tables, output `paper_numbers.json`) and
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

| arm | tools executed | bugs | servers | Δ vs full | tools shared / new / lost vs full |
|---|---|---|---|---|---|
| Full ToFu | 1,507 | **436** | 136 | — | — |
| No LLM seeds | 1,371 | 396 | 129 | −40 (−9%) | 345 / 51 / 91 |
| No LLM selection | 1,501 | 311 | 103 | −125 (−29%) | 266 / 45 / 170 |
| No LLM (both off) | 1,369 | 293 | 100 | −143 (−33%) | 245 / 48 / 191 |
| No seeds | 1,258 | 244 | 93 | −192 (−44%) | 213 / 31 / 223 |

"Tools executed" = tools with ≥1 successful call (of 1,801). Median throughput is 43.1–46.1
executions/s in every arm.

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
   reports 293 bugs, 67% of the full system (Table A).
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

- One run per arm. Run-to-run variation is being measured with two additional Full ToFu runs;
  until then, report the −9% of "No LLM seeds" as indicative (the per-tool churn is visible in
  the shared/new/lost columns).
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
- newtype-01/obsidian-mcp deleted its own target directory while being fuzzed (inside the
  sandbox; nothing outside it was touched), so it could not start in nollm/noseeds/allsan. It was
  re-prepared before each of those three arms and its 11 tools re-run; the failed rows are kept
  in `quarantine-abl-*-obsidian-wiped.jsonl`.
- ToolFuzz shards from another session ran on the same PC until 04:29–04:43, overlapping the
  first ~15 min of abl-full (LLM-bound, low CPU).
- Replay cache `eval/state/llm_cache_ablation` (PC): 1,801 entries.
