# Case-study candidates — ranked for sec:casestudy (2026-09-22)

The **current** active case study (casestudy.tex) = `excel-reader-mcp :: export_to_json`
— path-traversal → arbitrary file write (CWE-73/22), a **JS** target detected by
**outcome-divergence** (no in-process tracer; sanitizer flags the arg, tool returns
silent success). It's a complete A/G/O walkthrough. Everything below is picked to
ADD a dimension that case does not already cover.

Selection axes: (a) different detection mode, (b) different sink family / CWE,
(c) ToFu-exclusive vs baselines, (d) demonstrated-live, (e) maps to a challenge
C1–C4 the paper wants to land.

---

## Tier 1 — write these (each adds a distinct dimension)

### 1. yzfly/mcp-python-interpreter :: `run_python_code`  (CWE-94, RCE-equiv)
- **Adds:** the *other* detection mode. This is a **Python** target, so the
  introspection layer **directly observes** the dangerous operation (file read /
  `exec`) — the exact contrast to the excel case's outcome-divergence. One case
  shows each oracle path → covers C3 (oracles under partial visibility) end to end.
- **Demonstrated:** live read of `/etc/passwd` returned in tool output
  (writeup: `mcp-python-interpreter_inline-unsandboxed-code-execution.md`).
- **Impact:** highest (arbitrary in-process code exec; blast radius = whole host).
- **Caveat for framing:** "dangerous by design" — the honest angle is *default*
  `execution_mode="inline"` is unsandboxed/in-process. Frame as capability-safe-
  until-it-isn't, not a subtle logic bug.

### 2. AminForou/mcp-gsc :: `add_site` / `inspect_url_enhanced` / … (CWE-918 SSRF)
- **Adds:** the **largest class (SSRF, 199)** — currently unrepresented in the
  case study — and a **fully ToFu-exclusive** repo. H2H: ToFu **13 (13 hi)**,
  viper n/a, **codeql 0, cisco 0, sonnet-5 0, toolfuzz –**. Nobody else found it.
- **Story:** 7 tools all succ=1.000 → whole-server SSRF surface, all high-conf.
  Strongest "ToFu catches what static + LLM-audit both miss" narrative → C1/C2
  (semantic properties from metadata: a URL arg implies scheme/destination limits)
  and directly supports the miss-analysis / complementary-coverage claim.

### 3. CheMiguel23/memorymesh :: reflected-output  (CWE-79/116)  — extensibility
- **Adds:** the **C4 story (beyond a fixed corpus)** that no other case tells.
  A sanitizer added *after* the miss-analysis (`check_reflected_output`) recovered
  an entire class: **+14 findings on this repo**, 21 corpus-wide (18 hi). Pairs
  with `coverage_rerun_20260922.png` (coverage kept climbing past the 60s budget,
  cache-accelerated, 0 extra LLM calls).
- **Use as:** a short "extending ToFu" case — demonstrates the framework is not
  pinned to a fixed sanitizer set (RQ1 + C4), with an empirical recovery number.

---

## Tier 1.5 — the false-positive / alert-volume exemplar (do NOT skip this one)

### wonderwhy-er/DesktopCommanderMCP :: `create_directory` (817 alerts → 0 promoted)
- **Adds:** the honesty story the current case study only *asserts*. `create_directory`
  fired **817** `check_path_traversal` alerts (list_directory 324), all succ=1.000,
  yet **0 are promoted** — the tool documents `allowedDirectories: []` = full
  filesystem access (server.ts:346), so traversal is the intended default → fails
  promotion condition 1 (Role). This is the corpus-scale proof of "alert volume is
  not a proxy for vulnerability count" that casestudy.tex claims.
- **Three-way disagreement (great table):** ToFu 817 raw alerts (correctly
  unpromoted) · vanilla-claude cleared every tool as "guarded" (right verdict,
  wrong reason) · human triage = FP-documented (right verdict, right reason). Only
  sink-read triage reasons correctly → argues for the role/action/effect gate.
- **Also** the operational-hazard datapoint (below).
- writeup: `DesktopCommanderMCP_full-access-default_and_host-hazard.md`.
- **Evidence caveat:** the host-load spike is real (why it's skipped) but the exact
  loadavg number is NOT in a committed log — state it qualitatively (CLAUDE.md 3).

## Tier 2 — demonstrated-live blast-radius sidebar (unique to this eval)

These literally attacked the eval host **during fuzzing** — runtime proof that
needs no directed re-test. Best as a boxed "real-world impact" paragraph, not a
full A/G/O walkthrough (they're missing-authorization, not subtle semantics). All
three are on `set_e2_unsafe_repos.txt` (the OS-control skip list, item 91).

- **m-ahmed-elbeskeri/UltimateCoderMCP :: `tool_delete_path`** (CWE-22/73) —
  arbitrary file/dir deletion; **deleted ToFu's own working tree** (5830 configs,
  .venv, 116 tracked files) from fuzz input alone.
  (`UltimateCoderMCP_tool_delete_path_arbitrary-file-deletion.md`)
- **nickgnd/tmux-mcp :: `kill-session` / `execute-command`** (CWE-284) — unscoped
  control of the host tmux; **killed the running campaign's own tmux session**.
  (`tmux-mcp_session-hijack-and-kill.md`)
- **wonderwhy-er/DesktopCommanderMCP :: `start_process` / process tools** (CWE-284)
  — unrestricted local process spawn; **host-load spike stopped the campaign** →
  skipped. (Same repo as Tier 1.5; here for the operational-hazard angle.)

Framing: "the same tool that erased our harness erases a user's home directory" —
a powerful local capability exposed as an unauthenticated MCP tool. Motivates the
adversarial-argument thesis viscerally, and motivates the isolation + skip-list
methodology (item 91).

---

## Tier 3 — solid true positives if a slot opens

- **PhialsBasement/CMD-MCP-Server :: `execute_command`** (CWE-78, succ 1.000) —
  clean command-injection oracle demo; but viper also flags (cmd-inj is viper's
  lane), so not exclusive.
- **joshrutkowski/applescript-mcp :: `iterm_run` + `finder_search_files`**
  (CWE-78 + CWE-22, both 1.000) — repo *everyone* flags (viper 4, codeql 2,
  toolfuzz 32, sonnet 21): a triangulation/agreement example if the paper wants
  a "all tools agree, ToFu adds runtime evidence" contrast.
- **antoinebou12/uml-mcp :: `list_diagram_types`** (CWE-117 CRLF log-injection) —
  useful for the **attribution** section: the oracle fired via the **evidence
  path**, NOT the LLM selection (`uml-mcp_..._crlf-log-injection.md`). Lower impact.

---

## Recommended final set for the paper
Keep excel-reader-mcp as the primary walkthrough. **Add #1 (python-interpreter,
the introspection-observed mode) and #2 (mcp-gsc, ToFu-exclusive SSRF)** as full
mini-walkthroughs; **DesktopCommander (Tier 1.5)** as the FP/alert-volume exemplar
(it makes the promotion-gate claim concrete); and **#3 (memorymesh) + the Tier 2
trio** as short paragraphs. That gives: both detection modes, 4 CWE families
(write/RCE/SSRF/XSS), a ToFu-exclusive, an extensibility result, a false-positive
exemplar, and three demonstrated-live host impacts — one case per challenge C1–C4
plus the honesty/FP story RQ2 needs.
