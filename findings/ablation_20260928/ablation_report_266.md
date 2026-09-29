# ToFu ablation (1801 configs)

## Stage ablations (each arm = its own run)

| arm | what is removed | configs run | executed | median exec/s | bugs | repos | py | js | shared / only-here / lost vs full |
|---|---|---|---|---|---|---|---|---|---|
| full | full ToFu | 1801 | 1507 | 43.1 | **436** | 136 | 169 | 267 |  |
| nollmseeds | fallback seeds (no LLM seeds) | 1801 | 1371 | 46.1 | **396** | 129 | 160 | 236 | 326 / 70 / 110 |
| mandatory | mandatory sanitizers only (no LLM selection) | 1801 | 1501 | 44.6 | **311** | 103 | 135 | 176 | 216 / 95 / 220 |
| nollm | no LLM at all (fallback seeds + mandatory) | 1801 | 1369 | 46.1 | **293** | 100 | 120 | 173 | 188 / 105 / 248 |
| noseeds | empty corpus (no seeds at all) | 1801 | 1258 | 43.5 | **244** | 93 | 123 | 121 | 168 / 76 / 268 |
| allsan | all sanitizers (no LLM selection) | 1801 | 1512 | 43.5 | **960** | 191 | 335 | 625 | 319 / 641 / 117 |

## Oracle ablations (derived from the `full` arm's logs; no extra run)

shared/only-here/lost compared per (repo, tool).

| arm | what is removed | configs run | executed | median exec/s | bugs | repos | py | js | shared / only-here / lost vs full |
|---|---|---|---|---|---|---|---|---|---|
| full | sanitizer AND (success OR tracer) | 1801 | 1507 | 43.1 | **436** | 136 | 169 | 267 |  |
| tracers-only | only runtime-observed ops count | 1801 | 1507 | 43.1 | **87** | 32 | 86 | 1 | 87 / 0 / 349 |
| outcome-only | tracer off: sanitizer AND success | 1801 | 1507 | 43.1 | **373** | 122 | 107 | 266 | 373 / 0 / 63 |
| sanitizers-only | every sanitizer fire, success or not | 1801 | 1507 | 43.1 | **450** | 136 | 132 | 318 | 383 / 67 / 53 |

shadow-oracle lines present in 343 of 1801 full-arm configs

Bugs = distinct (repo, tool, class) via triage_findings.classify, same rule as the headline. Extra bugs in `allsan` are raw candidates: precision must be labelled before they count.
