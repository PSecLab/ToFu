# Baseline comparison (refreshed) — ToFu (python arm fixed) vs Viper vs CodeQL vs Cisco — 2026-09-16

Supersedes baseline_comparison_20260915.md, which was taken while ToFu's Python
arm was silently broken (item 86). With the arm fixed, ToFu now has findings on
host-39 **Python** repos the static/heuristic baselines already covered — so the
comparison is finally apples-to-apples on both languages.

Scope = the **host-39** set (the only scope where all four tools have run).
NOTE: the whole-MCPCorpus ToFu run (1,404 repos) launched 2026-09-16 and is
IN PROGRESS — not reflected here. gpt-4.1 for all LLM roles, temp 0, fixed seed.

## ⚠ The counts are NOT the same unit (unchanged)
| tool | one "finding" is | confirmed? |
|---|---|---|
| ToFu | a semantic silent-bug: tool accepts adversarial input **and returns success** | **yes, hand-verified** |
| Viper-MCP | CodeQL taint flow (Phase I), 3 classes: cmd-inj / SSRF / path-or-file-access | taint-proven |
| CodeQL security-extended | any SAST rule match | **no** (static flag) |
| Cisco MCP Scanner | YARA/LLM heuristic on tool descriptions | **no** (heuristic) |

## Totals on host-39
| tool | findings | repos | coverage |
|---|---|---|---|
| **ToFu** | **7** (4 + 3 potential) | 5 | 39/39 |
| Viper-MCP | 12 (taint) | 5 | 32/39 (7 ERR) |
| CodeQL set-A | 309 (unconfirmed) | 20 | 39/39 |
| Cisco | 28 (unconfirmed) | 8 | 39/39 |

(Was 3 confirmed before the python fix — V3 had been mislabelled confirmed; it
is potential. The genuine gain is V4/V6 on tumf/mcp-text-editor and V7 on
yzfly/mcp-python-interpreter, all Python, none of which the pre-fix arm could
even execute.)

## Per-repo, bug level: what each tool found on ToFu's 5 finding-repos
| repo | ToFu | Viper | CodeQL-A | Cisco | same bug elsewhere? |
|---|---|---|---|---|---|
| excel-reader-mcp | V1 arbitrary **WRITE** | 5× file-access (all **READ**) | 0 | 0 | **no** (write vs read) |
| locallama-mcp | V2 log-inj + V3 self-update | ERR (not run) | 11 (rate-limit/fs-race/http-to-file/…) | 4 (YARA on 3 tools) | **no** |
| **mcp-text-editor** | V4 arbitrary **READ** + V6 arbitrary **WRITE** | not run | 2 (`py/overly-permissive-file` only) | 0 | **no** — CodeQL flagged file *perms*, missed the traversal/absolute-path R/W |
| **uml-mcp** | V5 CRLF log-injection | not run | **11 incl. `py/log-injection` ×4** | 0 | **YES (partial)** — CodeQL flags the same family; ToFu confirms it at runtime |
| **mcp-python-interpreter** | V7 unsandboxed code exec | not run | 0 | 0 | **no** |

## Read (the complementarity thesis, now with the Python arm)
- **6 of ToFu's 7 findings are ToFu-unique** — no baseline reports the same bug,
  even though the baselines *scanned the same repos*. The sharpest case:
  CodeQL ran on tumf/mcp-text-editor and returned only `py/overly-permissive-file`
  (a 0o664-mode note) — it **missed the arbitrary read AND write**, because the
  path is caller-controlled at runtime, not a static constant. ToFu drove the
  tool to actually read `/etc/passwd`+`/proc/self/environ` and write `/tmp`,`/var/tmp`.
- **1 honest overlap: V5 (uml log-injection) ↔ CodeQL `py/log-injection` (×4)** on
  the same repo. Not disjoint — and that's a *good* result: ToFu confirms at
  runtime a bug SAST also flags statically, while separating it from the 305 other
  CodeQL flags that are unconfirmed.
- **Conversely**, CodeQL's 309 and Cisco's 28 sit almost entirely on repos/classes
  ToFu did not confirm (SAST family noise; heuristic tool-description matches).
- **Viper has no data on ToFu's Python findings** (locallama ERR'd; text-editor,
  uml, python-interpreter have no report.json — among its 7 non-completions), so
  the Python comparison is effectively **ToFu vs CodeQL**, and there ToFu wins on
  4/5 python-repo findings (text-editor R/W and python-interpreter exec unique;
  uml log-inj shared).

## Caveats (state these)
- Units differ (top table). Headline = "4 confirmed semantic + 3 potential" vs
  "12 taint" vs "309 / 28 unconfirmed" — never a single ranked score.
- Viper 32/39 coverage; Phase-II runtime hook host-dependent (per 0913 writeup).
- host-39 CodeQL = set-A (309). The large-scale CodeQL number is set-E (5,361 on
  300 repos), a separate scale point, not this table.
- ToFu attribution (RQ2/RQ3): V5/V6/V7 fired via evidence-gated introspection
  checks, not LLM selection — subtract the mandatory/evidence layer before
  crediting selection (see the per-finding writeups).
