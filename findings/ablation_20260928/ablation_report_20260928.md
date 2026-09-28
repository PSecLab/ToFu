# ToFu ablation (1672 configs)

## Stage ablations (each arm = its own run)

| arm | what is removed | configs run | executed | median exec/s | bugs | repos | py | js | shared / only-here / lost vs full |
|---|---|---|---|---|---|---|---|---|---|
| full | full ToFu | 1672 | 1450 | 45.7 | **408** | 130 | 154 | 254 |  |
| nollmseeds | fallback seeds (no LLM seeds) | 1672 | 1328 | 46.3 | **369** | 124 | 143 | 226 | 303 / 66 / 105 |
| mandatory | mandatory sanitizers only (no LLM selection) | 1672 | 1455 | 46.1 | **303** | 98 | 134 | 169 | 212 / 91 / 196 |
| nollm | no LLM at all (fallback seeds + mandatory) | 1672 | 1321 | 46.3 | **286** | 96 | 118 | 168 | 185 / 101 / 223 |
| noseeds | empty corpus (no seeds at all) | 1672 | 1209 | 44.6 | **223** | 89 | 106 | 117 | 153 / 70 / 255 |
| allsan | all sanitizers (no LLM selection) | 1672 | 1456 | 45.9 | **928** | 185 | 318 | 610 | 307 / 621 / 101 |

## Oracle ablations (derived from the `full` arm's logs; no extra run)

shared/only-here/lost compared per (repo, tool).

| arm | what is removed | configs run | executed | median exec/s | bugs | repos | py | js | shared / only-here / lost vs full |
|---|---|---|---|---|---|---|---|---|---|
| full | sanitizer AND (success OR tracer) | 1672 | 1450 | 45.7 | **408** | 130 | 154 | 254 |  |
| tracers-only | only runtime-observed ops count | 1672 | 1450 | 45.7 | **85** | 30 | 85 | 0 | 85 / 0 / 323 |
| outcome-only | tracer off: sanitizer AND success | 1672 | 1450 | 45.7 | **347** | 117 | 93 | 254 | 347 / 0 / 61 |
| sanitizers-only | every sanitizer fire, success or not | 1672 | 1450 | 45.7 | **408** | 128 | 118 | 290 | 357 / 51 / 51 |

shadow-oracle lines present in 310 of 1672 full-arm configs

Bugs = distinct (repo, tool, class) via triage_findings.classify, same rule as the headline. Extra bugs in `allsan` are raw candidates: precision must be labelled before they count.
