# ToFu ablation — 2026-09-28 (PSU PC, 12 workers, 60 s/tool, bwrap)

Scope: the 251 repos that executed in the 60 s sandboxed headline runs (230 corpus-sbx + 21
recover-pc), all 1,672 of their configs, every arm. LLM calls: 0 live (replay cache
`llm_cache_ablation`, read-only after `full`). Commits: abl-full rows 1-217 at be2529b, rest of
the campaign at f608f20 (only runner diff = a92dc8a, unreachable outside `allsan`;
abl_commit_boundary.txt). Regenerate the tables: `python3 eval/ablation_report.py --state findings/ablation_20260928`.
Full tables: ablation_report_20260928.md. One run per arm (no repeats yet).

## Stage ablations (bugs = distinct (repo, tool, class), headline rule)

| arm | removed | tools executed (py / js) | bugs | tool-level vs full: shared / new / lost |
|---|---|---|---|---|
| full | — | 1,450 (506 / 944) | **408** | — |
| nollmseeds | LLM seeds -> fallback seeds | 1,328 (442 / 886) | 369 | 321 / 48 / 87 |
| mandatory | LLM selection -> 10 mandatory | 1,455 (509 / 946) | 303 | 259 / 44 / 149 |
| nollm | both LLM stages | 1,321 (443 / 878) | 286 | 239 / 47 / 169 |
| noseeds | all seeds (empty corpus) | 1,209 (424 / 785) | 223 | 195 / 28 / 213 |
| allsan | LLM selection -> all 73 | 1,456 (508 / 948) | 928 (raw) | 393 / 535 / 15 |

Median exec/s is 44.6-46.3 in every arm, allsan included (45.9 vs 45.7).

Class mix (full -> mandatory -> nollm): path-traversal 95 -> 0 -> 0; ssrf 24 -> 4 -> 0;
reflected-xss 200 -> 230 -> 226; log-injection 80 -> 64 -> 56. The no-selection arms keep only
the classes whose checks run evidence-gated regardless of selection (reflected-output, log
tracers). allsan: log-injection 492, path-traversal 148, cmd-injection 38, ssrf 58.

## Oracle ablations (from the full arm's logs)

| oracle | bugs | py | js | tool-level vs full: shared / new / lost |
|---|---|---|---|---|
| full: sanitizer AND (success OR tracer) | 408 | 154 | 254 | — |
| tracers-only | 85 | 85 | 0 (JS has no tracer: 0 by construction, not a result) | 85 / 0 / 323 |
| outcome-only (tracer off) | 347 | 93 | 254 | 347 / 0 / 61 |
| sanitizers-only (no success gate) | 408 | 118 | 290 | 357 / 51 / 51 |

Shadow (ungated) lines in 310 of 1,672 full-arm configs.

## Caveats
- One run per arm; fuzzing is stochastic. The run-to-run churn of `full` itself is not measured
  yet, so small deltas (e.g. nollmseeds -41) are not yet separable from noise.
- allsan's extra 535 tools are raw candidates; precision must be labelled before they count.
- Precision (nazmul.todo item 23) applies to every arm; reflected-xss / log-injection dominate
  the no-selection arms.
