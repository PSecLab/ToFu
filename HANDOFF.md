# ToFu — Session Handoff

**Last rewritten 2026-09-10 after a full audit of the eval harness and LLM path.**
This file is the single source of truth for the state of the project. The deep
detail lives in `ToFu_src/nazmul.todo` (the lab notebook) — this file tells you
what is true right now and what to do next; the notebook tells you how each
conclusion was reached.

Read in this order: **this file → `ToFu_src/nazmul.todo` → `eval/README.md`.**

Repo root: `~/pseclab/ToFu` (renamed from `toolfuzzer` on 2026-09-10).
Machine: Ananto's MacBook Pro, Apple Silicon **M2 Pro, 16 GB unified memory**.
Git remote: `https://github.com/PSecLab/toolfuzzer.git` (name not yet updated).

---

## 0. THE ONE THING TO UNDERSTAND FIRST

ToFu's failure mode is **not** crashing. It is reporting a healthy-looking
"0 findings" while something upstream is silently broken. As of 2026-09-10 this
has happened **fourteen separate times**. The first four were found in the
2026-09-09/10 audit; bugs 5-14 were found on 2026-09-10 by actually running the
thing and checking every number against a log. Full detail for 5-14 is in
`ToFu_src/nazmul.todo`; the first four:

1. `select_sanitizers()` used `str.strip("```json")` — which strips a character
   set, not a substring — so every LLM call raised, was caught, and fell back to
   default sanitizers. RQ2/RQ3 had no evidence behind them.
2. `run_eval.py` counted findings by strings the reporter never prints.
3. `run_eval.py` used `re.*` without importing `re`, discarding nine **completed**
   runs as failures.
4. `FuzzInputParser.parse()` ran the FDP generator before the JSON branch, making
   the JSON branch unreachable, so no semantic seed ever reached a target intact.

All fourteen are fixed. The lesson to carry: **when this codebase reports nothing,
suspect the instrument before you suspect the target.** Verify every measurement
against a real log, never against what the source appears to print.

**The single most useful thing added on 2026-09-10** is executability
accounting. The fuzzer now emits, periodically during a run:

```
EXEC_SUMMARY tool=<t> n_exec=<n> n_success=<s> success_rate=<r>
EXEC_ERROR   n=<n> detail=<the recurring error>
NOT_EXECUTABLE tool=<t> -- all <n> executions returned an error ...
```

and `run_eval` records `executable: yes|no|unknown` per run and shouts in the
summary. **"Ran and found nothing" and "never actually ran" can no longer look
alike.** That distinction is what all fourteen bugs were hiding behind.

---

## 1. WHAT ToFu IS

**ToFu — "Exploiting and Fuzzing the LLM–Orchestrator–Tool Trust Boundary."**
A security paper plus a tool that fuzzes MCP (Model Context Protocol) servers for
**semantic** implementation bugs: cases where a tool executes normally, returns a
plausible result, and still violates a security property its own interface or
description claims. Distinct from crash-based fuzzing, and distinct from
taint-style scanners.

Pipeline: an **LLM selects** which sanitizers apply to a tool (from its name,
description and schema) and **generates seeds**; Atheris does coverage-guided
fuzzing; a **differential/semantic oracle** derived from the tool's own contract
decides violations. The LLM is deliberately confined to selection + seed
generation, never to judging whether something is a vulnerability.

Paper concepts: A1–A4 weaknesses, C1–C4 challenges, RQ1–RQ4 research questions,
sanitizers `S = ⟨A, G, O, I⟩`.

**Sanitizer inventory (recounted 2026-09-10 — the paper's "~66" is wrong):**
- 73 `def check_*` across `src/sanitizers/`
- 72 keys in `AVAILABLE_SANITIZERS` (what the LLM may select from)
- `check_invalid_git_ref` and `check_unsafe_s3_bucket` are **defined but never
  registered** — dead code, unreachable by selection
- `check_unexpected_crash` is registered with no `def` — special-cased in
  `fuzzer.py`
- 21 runtime tracer classes in `src/sanitizers/introspection.py`
- 10 of the registry are `BASE_MANDATORY_SANITIZERS`, **always on regardless of
  what the LLM selects** — see §2, this matters for attribution

Two runners only: `PythonRunner` and `JSRunner`. Repos in other languages are
reported and excluded — that is a stated exclusion in the paper, not an oversight.

---

## 2. CURRENT STATE — WHAT IS PROVEN AND WHAT IS NOT

**Nothing publishable has been measured yet.** The pipeline is now believed
correct but is unproven end to end.

**Proven working:**
- LLM sanitizer selection runs and parses (`llm_selection: ok`).
- LLM seed generation runs (`LLM_SEEDGEN_OK`), with retries; occasionally falls
  back to the deterministic mapper.
- A structured seed now reaches the target verbatim (regression-tested).
- The eval harness records findings, sanitizers, LLM stage health and provenance.
- Full test suite passes on the Mac: **87 passed, 0 skipped** (was 66/1 skipped;
  the skipped test now runs, and 21 regression tests were added on 2026-09-10,
  one per bug, with fixtures copied verbatim from real logs and measured V8
  ranges).
- A JS target's coverage now discriminates between branches: a control target
  with 6 branch-distinct inputs, driven through the real `JSRunner`, produces
  **6 distinct coverage sets**. Before the 2026-09-10 fixes it produced 1.
- `exec/s` on JS targets is **100-227** (was 0-33).

**Not proven / open:**
- **No credible finding exists.** The only alerts ever recorded came from the
  broken input path and are quarantined.
- **Sanitizer-selection precision is unmeasured.** The one precision signal we
  have was sampled at temperature 0.7 and cannot be attributed to the model.
- **JS coverage guidance has never been observed working.** The fix is in but
  unverified — see the acceptance test in §4.
- Cisco baseline: built, never validated with a clean smoke run.
- Set D: built and wired, never run.

**The active run index is 54 runs** (`eval/state/runs.jsonl`). 173 configs
exist, from 14 repos that survived preparation (44 of 58 skipped -- that skip
list IS the paper's exclusion list; one entry, a stale `/sessions/rcw-.../`
cloud-sandbox path, is NOT a legitimate exclusion and should be retried).

**None of those 54 runs is evidence about ToFu.** 46 are the gemma4 overnight
campaign that timed out at 780 s each without reaching libFuzzer (4096-token
context + uncapped reasoning); the rest predate the 2026-09-10 fixes. Three
diagnostic runs are quarantined under `eval/state/preRevertFix2/` and
`eval/state/postRevertFix2-preBlockCov/`, each with a WHY.md.

**HOW MUCH OF THE CORPUS CAN ACTUALLY BE FUZZED HERE** -- measured, not guessed
(`eval/state/executability_survey.json`, one representative tool per repo driven
with ToFu's own deterministic seeds):

| repo | tools | executes? | why not |
|---|---|---|---|
| chatmcp/mcp-server-chatsum | 1 | 23/23 | |
| freestylefly/mcp-server-weread | 4 | 32/32 | |
| AppiumTestDistribution/mcp-appium-gestures | 5 | 21/40 | |
| yan5236/bing-cn-mcp-server | 2 | 4/23 | |
| Heratiki/locallama-mcp | 17 | 3/14 | |
| maoxiaoke/create-mcp-server | 1 | 2/2 | |
| api7/apisix-mcp | 32 | **0** | `ECONNREFUSED 127.0.0.1:9180` -- needs APISIX Admin API |
| graphlit/graphlit-mcp-server | 71 | **0** | needs a Graphlit organization credential |
| spences10/mcp-n8n-builder | 10 | **0** | needs an n8n backend |
| tonypan2/minesweeper-mcp-server | 4 | **0** | its own game server fails |
| thomasgazzoni/vsc-mcp | 7 | **0** | workspace-confined; denies paths outside its root |
| ArchimedesCrypto/excel-reader-mcp | 14 | **0*** | *executes fine with a real .xlsx; the deterministic mapper cannot guess a sheet name. The LLM path emits `Sheet1`. |
| screenshotone/mcp, tubone24/midi-mcp-server | 5 | **0** | schema validation |

**30 of 173 configs are executable in this environment, and 103 of the 173 come
from just two repos (apisix 32, graphlit 71) -- both of which are dead.** Decide
the policy before the campaign (nazmul.todo item 31): stand the backends up,
exclude and report, or both. This is now a measured number rather than a
silent stream of clean-looking zeroes.

**ATTRIBUTION TRAP — read before writing any result.** `fuzzer.py` merges
`BASE_MANDATORY_SANITIZERS` (10 always-on checks) into whatever the LLM selects.
In the quarantined runs, 3 of the 4 sanitizers in most finding signatures were
mandatory, and one tool had **zero** LLM-attributable sanitizers fire. So an
alert firing is **not** evidence for the LLM-selection design unless you subtract
the mandatory layer. `eval/score_set_d.py` splits TPs into "LLM path" vs
"deterministic fallback" but has **no third bucket for the mandatory layer** —
add one before Set D is scored.

---

## 3. WHAT TO DO NEXT (prioritized)

1. **Verify the JS coverage fix** with the acceptance test in §4. Do not launch a
   campaign whose coverage numbers you intend to publish until `cov:` is observed
   increasing during a run.
2. **Re-collect selection-precision evidence at temperature 0.** The earlier
   evidence is void (§6, Fix 1).
3. **Build the sanitizer-selection ground truth.** 30–50 tools across Set A/B,
   hand-labelled with which sanitizer families genuinely apply. Without it,
   "precision" is anecdote and RQ2/RQ3 say nothing. This is cheap and is itself a
   contribution. **Ananto has not yet decided to do this — ask.**
4. **Run the model sweep**: `llama3.1:8b` (old baseline), `gemma4:12b` (chosen
   local mid arm), optionally `granite4.1:8b`. Same seed and temperature. This
   doubles as Pierre's A4 sanitizer-selection ablation.
5. **Run the real Set A+B campaign**, then Set D, then the Cisco baseline smoke.
6. **Decide on the credential history rewrite** (§8) — prepared, not pushed.
7. Paper TODOs A3–A7 in `nazmul.todo` unblock once real run data exists.

---

## 4. RUNNING IT

Environment (local Ollama; **the model is an experimental variable — record it**):

```bash
cd ~/pseclab/ToFu
# Ollama defaults gemma4:12b to a 4096-token context on 16 GB, which truncated
# every sanitizer-selection reply mid-JSON. 32768 is enough (largest measured
# prompt: 3660 tokens); 262144 also fits (~8.8 GB) but buys nothing.
OLLAMA_CONTEXT_LENGTH=32768 ollama serve
ollama pull gemma4:12b
pip install pyflakes            # the undefined-name preflight skips silently without it

export TOFU_LLM_BASE_URL=http://localhost:11434/v1
export TOFU_LLM_MODEL=gemma4:12b        # or llama3.1:8b for the baseline arm
export TOFU_LLM_TEMPERATURE=0           # default 0; NEVER run a campaign at 0.7
export TOFU_LLM_SEED=20260910
export OLLAMA_CLOUD_API_KEY=ollama      # local Ollama ignores the value
export OLLAMA_NUM_PARALLEL=1            # 16 GB + a 12B: avoid daemon contention
export TOFU_LLM_REASONING=none          # gemma4 is a THINKING model. Uncapped it
                                        # reasons past the harness ceiling: a run
                                        # hung 720s without completing one HTTP
                                        # request. EXPERIMENTAL VARIABLE -- unset
                                        # it for the thinking arm (item 24).
export TOFU_LLM_MAX_TOKENS=4096         # hard runaway stop

# .env IS INERT ON ITS OWN -- nothing calls load_dotenv and python-dotenv is not
# installed. eval/run_overnight.sh sources it for you; otherwise:
#     set -a; . ./.env; set +a
```

Campaign:

```bash
python3 eval/prepare_targets.py            # clone@commit -> install -> probe -> configs
python3 eval/run_eval.py --time 600 --workers 2
python3 eval/run_eval.py --status          # progress + LLM-stage health
python3 eval/run_eval.py --reparse         # rebuild the index from logs, never re-run
python3 eval/run_eval.py --set D --time 600
python3 eval/score_set_d.py --md set_d_scorecard.md
./eval/run_cisco_baseline.sh smoke
```

**ACCEPTANCE TEST for the JS coverage fix — do this first:**

```bash
python3 eval/run_eval.py --time 120 --limit 1 --workers 1
grep -oE "cov: [0-9]+ ft: [0-9]+ corp: [0-9]+" eval/runs/<that>.log | awk '!s[$0]++'
```

**STATUS 2026-09-10: ALL THREE NOW PASS.** Verified on
`ArchimedesCrypto/excel-reader-mcp::get_cell`, 90 s, gemma4:12b, temperature 0:

```
LLM_SELECTION_OK  n_selected=3 n_dropped=0
LLM_SEEDGEN_OK    n_seeds=10 n_rejected=0 validated=1
EXEC_SUMMARY      n_exec=2048 n_success=227 success_rate=0.111
cov:  97 ft: 146 corp: 3      <- increasing
cov: 105 ft: 161 corp: 4
cov: 107 ft: 169 corp: 5
cov: 109 ft: 179 corp: 6
alerts: 0
```

That is the first trustworthy "0 findings" this project has produced: the tool
really ran, coverage really grew, and nothing fired. The previous run of the
same config reported **295 alerts, every one a false positive** (bug 14).

Three things must be true, and all three were false before the fix:
- **(a)** `cov:` **increases** during the run. Previously pinned — observed
  `cov: 2766` identical from execution #4 to #309 across 600 s.
- **(b)** `corp:` grows past 2–4 entries.
- **(c)** `exec/s` rises substantially (was 0–33).

If (a) still fails, the next suspect is **worker threads**:
`coverage_wrapper.js` attaches profiler sessions to Node Workers but
`combinedResults` only collects from the main session. Not fixed; no known Set
A/B target uses workers. Check that before blaming the delta logic.

**Determinism check** (needed before claiming reproducibility): run one tool
twice and diff the selected sanitizers. `temperature=0` is necessary but not
sufficient — llama.cpp/Ollama batching and GPU scheduling can still perturb
logits.

Python 3.11 is required (`.python-version` → 3.11, venv is 3.11.15): Atheris
needs `dis.Positions`, which is 3.11+.

---

## 5. REPO MAP

```
~/pseclab/ToFu/
├── HANDOFF.md                  <- THIS FILE
├── src/                        ToFu implementation
│   ├── llm.py                  LLM backend. temperature/seed pinned; fence-aware
│   │                           JSON extraction; LLM_SELECTION_* / LLM_SEEDGEN_*
│   │                           markers that eval/ parses. Imports seed_generators.
│   ├── seed_generators.py      RESTORED from b1b657e (was deleted, still called)
│   ├── seed_bank/              6 semantic seed categories
│   ├── predefined_seeds/       37 binary seeds, RESTORED from b1b657e
│   ├── input_parser.py         JSON-first, FDP-fallback (ORDER MATTERS — §6)
│   ├── fuzzer.py               MCPDifferentialFuzzer; merges BASE_MANDATORY (§2)
│   ├── sanitizers/             73 check_*; introspection.py has the 21 tracers
│   ├── runners/
│   │   ├── js_runner.py        V8 coverage bridge; COV_SLOTS index space
│   │   ├── coverage_wrapper.js per-call coverage deltas (§6 Fix 2)
│   │   ├── fake_coverage.py    GENERATED, do not edit; regenerates on size change
│   │   └── python_runner.py
│   ├── reporters.py            prints "[POTENTIAL VULNERABILITY / BUG FOUND]"
│   └── __main__.py             python -m src --config X --time N
│                               --corpus-dir / --metrics-dir (REQUIRED for parallel)
│
├── eval/                       THE EVALUATION HARNESS
│   ├── README.md               runbook
│   ├── prepare_targets.py      STEP 1. --only-set a|b|d
│   ├── run_eval.py             STEP 2. resumable; --reparse; --status; --set A|B|D
│   ├── score_set_d.py          ToFu vs VIPER on VIPER's metric
│   ├── run_cisco_scanner.py    Cisco AI Defense baseline, same targets
│   ├── configs/                19 per-tool configs (Set A/B)
│   ├── runs/                   per-run logs — ALWAYS written before parsing
│   ├── corpora/, metrics/      per-run, created by run_eval (never share these)
│   └── state/
│       ├── runs.jsonl          ACTIVE index (2 runs)
│       ├── prepared.jsonl      2 repos ready
│       ├── skipped.jsonl       prep exclusions = the paper's exclusion list
│       ├── quarantine-pre-llmfix/     pre-LLM-fix junk + WHY.md
│       └── quarantine-pre-parserfix/  9 runs + 9 logs + WHY.md (§6)
│
├── ToFu_src/                   THE PAPER (LaTeX, USENIX Sec 2027). `make` to build
│   ├── nazmul.todo             THE LAB NOTEBOOK — read it; NEVER delete an item
│   ├── paper.bib               50 entries, audited (§9)
│   └── sec0..sec10_*.tex, table/motivation.tex, casestudy.tex, ...
│
├── Benchmarks/
│   ├── extraction/             corpus extraction; set_a/b/d.json; set_d_manifest
│   ├── papers/                 23 cached PDFs + README inventory
│   ├── Viper-MCP/, Cisco-MCP-Scanner/, MCPCorpus/, MCPSecBench/, MCPSafetyScanner/
│
├── targets/                    ORIGINAL hand-written fuzz targets (see §2 warning:
│                               these pass explicit override_rules, bypassing the
│                               LLM selection the paper claims)
├── tests/                      66 tests incl. test_audit_regressions.py
├── _preaudit_backups/          every file the audit touched, pre-change
├── _history_scrub/             credential-scrubbed git mirror, NOT pushed (§8)
└── .venv/                      uv venv, Python 3.11.15
```

---

## 6. THE AUDIT — EVERY BUG, AND WHY EACH MATTERS

Full narrative in `nazmul.todo` under "DEEP AUDIT", "COVERAGE ON JS TARGETS IS
INERT" and "DETERMINISM + JS COVERAGE FIXES". Condensed:

**Fix 1 — the LLM was sampling at temperature 0.7.** `ChatOpenAI` was built with
no `temperature` and no `seed`, inheriting LangChain's 0.7 default. Every
sanitizer selection was a sample. No run was reproducible; any model comparison
would have measured noise. **Consequence you must respect: the observed
selection failures (llama3.1:8b picking `check_markitdown_uri_validation` and the
SSRF/URL family for an Appium gesture code generator taking
`{language, useElement, elementId, x, y}`) were sampled at 0.7 and CANNOT be
attributed to the model as they stand.** Re-collect at 0.

**Fix 2 — JS coverage was cumulative, so guidance did nothing.**
`coverage_wrapper.js` started precise coverage once and reported every range with
`count > 0`, against counters V8 never resets. So the coverage array was
identical every call after warm-up; libFuzzer's `cov:` was pinned for whole runs;
no input was ever "interesting"; the corpus never grew past 2–4; ToFu degenerated
to random mutation of three inputs on **every Node/TS target** — 1,039 of the
1,847 runnable repos. `js_runner.py` had an `already_covered` set that was
initialised and never used: the missing delta, never wired up. Now the wrapper
reports only ranges whose count increased since the last take. Also reconciled a
`% 10000` index assignment against a 2000-branch bridge chain.

**Fix 3 — the input parser destroyed every semantic seed.** `parse()` called
`_generate_fallback_inputs` first; that method fills every declared property
unconditionally, so it always returned non-empty and the JSON branch below was
unreachable for any tool with a schema. A seed `{"path": "../../../etc/passwd"}`
went to `FuzzedDataProvider` as raw bytes and came back as UTF-16 mojibake of its
own JSON text. Proof in the quarantined logs: `'慬杮慵敧㨢∠慪慶Ⱒ'` is
`language": "java", "useElement":`. Now JSON-first, FDP-fallback, seed values
completing the schema. **This changes what the fuzzer sends** — it is the one
audit change that alters measured behaviour.

**Fix 4 — `import re` missing in `run_eval.py`.** The NameError fired after each
subprocess finished and after its log was written, so nine **completed** runs were
recorded as failures with `finding_hits=0`. Recovered via the new `--reparse`.

**Fix 5 — all parallel runs shared one corpus.** `__main__.py` never passed
`corpus_dir`, so every run used `./fuzz_corpus`, which `_setup_corpus_seeds()`
`rmtree`s at tool start — with 4 workers at `cwd=ROOT`. Every parallel campaign
before this is non-reproducible for that reason alone. Now `--corpus-dir` /
`--metrics-dir`, one per run.

**Fix 6 — `seed_generators.py` was never restored.** Commit `87d8602` (Pierre,
"latest edit") deleted 86 files including `src/seed_generators.py`,
`src/predefined_seeds/`, `src/interfaces.py`, `dictionaries/` and `configs/`. A
previous session restored `seed_bank/` but missed `seed_generators.py`, while
`llm.py` still called it in all 8 `@tool` functions. Every LLM seed-generation
tool call died with `name 'seed_generators' is not defined`. Restored.

**Smaller fixes in `run_eval.py`:** timeouts discarded the entire log including
any findings; timed-out runs leaked their MCP server (now `start_new_session` +
`killpg`); harness bugs were recorded in the same field as target crashes (now a
separate `harness_error`, counted and shouted about); `finding_hits`
double-counted every finding; no provenance was recorded (now budget, model,
endpoint, temperature, seed, commit, python, platform, cov slots); `--set`
rejected D.

**New guardrails:** `run_eval.py` runs pyflakes over itself, `llm.py`,
`fuzzer.py` and `input_parser.py` and **refuses to start** on any undefined name.
Logs are always written before they are parsed, so a parser bug can never destroy
data again — `--reparse` re-derives the index. `tests/test_audit_regressions.py`
has one test per bug, with fixtures copied **verbatim from real logs**.

---

## 7. THE PAPER

USENIX Security 2027 format (`usenixsecurity2027.tex`). Build: `make` in `ToFu_src/`.

- **sec8_related.tex** — fully rewritten. 4 paragraphs: adversarial-value attacks;
  defenses + landscape; catalog-bounded scanners & large-scale dynamic measurement
  (**this is where the VIPER-MCP differentiation lives**); description-code
  inconsistency + fuzzing + LLM-assisted testing. Every citation checked against
  the actual paper. Read the current file before editing — it encodes a lot of
  hard-won accuracy.
- **sec6_eval.tex** — RQ4 written; typos fixed; labels added.
- **table/motivation.tex** (Table 2) — 5 rows added: Cisco MCP Scanner,
  MCPSecBench, VIPER-MCP, MCPZoo, description-code inconsistency. ToFu is the only
  all-✓ row **by construction — keep it honest**.
- Other sections largely inherited and untouched.

**43 `\TODO{Pierre...}` comments remain in place ON PURPOSE** — 15 in
`casestudy.tex`, 5 in `sec4_design.tex`, 23 in `sec6_eval.tex`. Ananto wants a
reading pass and will delete them himself. **Do not strip them.** They collapse
into 7 actions (A1–A7) mapped out in `nazmul.todo`; A3–A7 are blocked on real run
data.

**Claims in the paper that the audit shows are wrong or unsupported:**
- "~66 sanitizer families" — the registry has 72 (§1). Recount before submission.
- Any coverage-over-time claim on JS targets, including "plateaus in under an
  hour" — that plateau was an artifact of the cumulative-coverage bug. Even after
  the fix, Python and JS coverage are **not comparable**: Python targets are
  instrumented directly by Atheris, JS goes through the bridge.
- The binary-seed claim (`create_pdf`/`docx`/`zip` → `predefined_seed:<name>`) —
  the path can now run, but has never been observed working. Verify or drop.

---

## 8. SECURITY — CREDENTIAL, SCRUBBED LOCALLY, PUSH NOT DONE

A live Ollama Cloud key was hardcoded as the default for `OLLAMA_CLOUD_API_KEY` in
**12 files**: 11 `targets/fuzz_*.py` and `src/__main__.py` (the entrypoint the
whole eval uses). All 12 now read the env var. **Ananto has revoked the key at the
provider**, so there is no live-credential risk.

History: `git filter-repo --replace-text` over a mirror clone, verified by walking
every blob in every ref — 0 blobs, 0 commits contain it. The rewritten mirror is
at `_history_scrub/tofu-scrubbed.git`. **NOT pushed** — it rewrites every commit
hash including Pierre's, and the remote is a shared org repo.

```bash
cd _history_scrub/tofu-scrubbed.git
git push --force --mirror https://github.com/PSecLab/toolfuzzer.git
```
Then everyone re-clones. If that repo is or ever was public, treat the key as
disclosed regardless; GitHub keeps unreferenced objects reachable via the API
until GC, so open a support request if it matters.

---

## 9. BIBLIOGRAPHY — THE RULE THAT MATTERS MOST

A previous model **fabricated a large part of `paper.bib`**, generating entries
from search-result snippets. On audit, **13 of 19** checked entries had invented
titles and/or invented author given names; system names "DCIChecker", "Corvus",
"MTGuard" appear nowhere in their papers; `wang2025mcpguard` was fabricated end to
end; `spellsmith` was cited backwards as an attack when it is a defense.

**RULE: never write a bib entry or a numeric claim you have not verified against
the primary source.** Ananto will not trust generated citations, and he is right
not to. `paper.bib` has 50 entries; adding one means verifying title, all author
names, venue and pages against the actual paper. Standing preference: **latest
published version at a reputable venue > arXiv preprint.**

Corrections that must be preserved, and the remaining unverified items (5 DOIs,
9 framework-doc URLs), are listed in full in `nazmul.todo`.

Useful precedent recorded there: when Google Scholar says "arXiv" but the arXiv
comments field claims a venue **and** supplies a publisher DOI, the arXiv comments
win — Scholar's index lags on newly published venues.

---

## 10. DATASETS

Replaced an indefensible original selection ("top of github.com/mcp") with a
seeded, stratified sample from **MCPCorpus** (Lin et al., ASE 2025). Corpus
extraction produced **1778 repos, 1404 with ≥1 tool, 24,194 tools**.

- **Set A** — 50 repos, seed **20260909**, fingerprint **aa6f0cffff64**. The
  reproducible "ecosystem" set. 20/21 tracer families represented.
- **Set B** — 8 repos purposively added to close rare tracer-family gaps.
- **Set D** — 63 repos: VIPER-MCP's own 0-day servers, "run ToFu in VIPER's
  court". **Opt-in, not part of the default sweep.**

**Set D bounds — state these with every Set D number:**
1. VIPER's Table 2 (130 vulnerable + 130 benign) is **not reproducible** — the 63
   historical CVEs are never listed. Set D is VIPER's own finds, so the deck is
   **stacked toward VIPER**. It answers "can ToFu also catch what VIPER caught",
   not a neutral head-to-head.
2. Every CVE is redacted `CVE-2026-XXXXX`; no commit hashes; VIPER's artifact
   removed all datasets.
3. Therefore Set D commits are **GitHub HEAD**, not the vulnerable revision. A
   since-patched repo is a false negative that is **not ToFu's fault** — the
   scorer flags it, never scores it as a miss.

**VIPER-MCP vs ToFu — get this argument right.** VIPER pairs CodeQL taint queries
with an LLM prompt-evolution agent; 106 0-days / 67 CVEs across ~39,884 repos — a
scale no single-institution study matches. **The difference is not scale; it is
what a check can express.** VIPER models exactly 3 taint classes against a fixed
sink inventory. ToFu's checks are bounded by what a tool *documents* about its
arguments, so properties with no corresponding sink (a destination restricted to
an allow-list, a path confined to a declared workspace, an enumerated argument)
are inside ToFu's reach and outside a taint formulation. Report them as
**complementary**, never as ToFu being "better".

---

## 11. INFRASTRUCTURE GOTCHAS

- **Long campaigns must be run natively in Terminal.** Do not launch them through
  an agent's remote shell — each call is a fresh process namespace and background
  jobs die when the call returns.
- **`arxiv.org`, `doi.org` and HuggingFace are blocked** by the egress proxies in
  both the cloud sandbox and the desktop VM. GitHub raw and
  `git ls-remote https://github.com/owner/repo` work fine (that is how Set D
  resolves HEADs). The 23 cached PDFs were fetched by driving Chrome with a
  same-origin `fetch → blob → <a download>`.
- **Google Scholar throws CAPTCHAs.** An agent must not solve them; Ananto does it
  manually.
- **Ollama contention:** `run_eval --workers N` means N concurrent LLM calls at
  run start. On 16 GB with a 12B, use `OLLAMA_NUM_PARALLEL=1` and `--workers 2`.
  Part of the fixed ~90–140 s per-run overhead (a 60 s budget produced 150 s and
  200 s actual) is likely this.
- For OpenReview, use `openreview-mcp` or `openreview-py`.

---

## 12. WORKING WITH ANANTO

- PhD student at Penn State, NLP/AI + security. He **inherited** this paper and
  framework and is rehabilitating both.
- **Rigorous, and reacts badly to fabrication or hand-waving** — with cause, see
  §9. Verify against primary sources; say plainly when something is unverified;
  own mistakes without padding.
- He **maintains the "TO DOUBLE-CHECK" items in `nazmul.todo` himself.** Add to
  them freely; **never delete one** unless he says he has done it. Same for the
  `\TODO{Pierre...}` comments in the `.tex` files.
- He runs the evals himself in Terminal. Prepare scripts for him: resumable,
  Ctrl-C-safe, writing to predictable locations.
- Direct, no fluff. Do not pad answers or re-explain what he just read.

---

## 13. OPEN DECISIONS FOR ANANTO (do not resolve these unilaterally)

1. Sign-off on the `input_parser.py` parse-order change — it alters what the
   fuzzer sends. (`nazmul.todo` item 5)
2. Are `check_file_access` / `check_process_and_fd_leaks` firing on a pure
   string-templating tool true positives at all, or are the Layer-1 tracers
   catching the Node runtime's own I/O? If the latter, every mandatory-layer
   alert is noise and needs a filter. (item 6)
3. Force-push the scrubbed history? (item 7, §8)
4. Fix JS coverage and re-run, or scope all coverage claims to Python? — the fix
   is now applied, so this becomes: verify it, then decide whether JS and Python
   coverage can appear in the same figure. (items 8–10)
5. Build the sanitizer-selection ground-truth set? (§3 step 3)
6. Whether to add a hosted frontier model as a ceiling arm — deferred until the
   local sweep is in. If added, `sec10_ethical.tex` needs a note that third-party
   tool descriptions leave the machine.
7. Recount the sanitizer families and fix the "~66" claim. (§1)
8. Set D open items: recount Appendix B (66 rows transcribed, paper claims 67);
   confirm each gold repo's HEAD still exposes its vulnerable tool; decide whether
   to run the Cisco baseline on Set D for a 3-way row.

---

## 14. QUICK START

```bash
cd ~/pseclab/ToFu
# 1. read: HANDOFF.md -> ToFu_src/nazmul.todo -> eval/README.md
.venv/bin/python -m pytest tests/ -q             # expect 87 passed, 0 skipped
# 2. verify the JS coverage fix (§4 acceptance test) BEFORE any real campaign
python3 eval/run_eval.py --time 120 --limit 1 --workers 1
# 3. then the campaign, then Set D, then the Cisco baseline
```

When in doubt: verify against the primary source, write what you found in
`nazmul.todo`, and do not report a number you cannot trace to a log.
