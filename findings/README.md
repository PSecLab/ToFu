# ToFu findings — gpt-4.1 full run (arm gpt41-full, commit e14a363)

Every item here is verified against the target's SOURCE and, where the effect
is a filesystem/side effect, by a DIRECTED test against the live server. Raw
alert counts from the run are NOT evidence on their own — see the FP note.

## confirmed/  (reproduced; disclose to maintainer)
- **CWE-73_excel-reader-mcp_export_arbitrary-file-write.md**
  export_to_json / export_to_csv write to an unconstrained caller `outputPath`.
  Validated: create outside cwd, `../` escape, overwrite existing file with
  attacker-influenced content.
- **CWE-117_locallama-mcp_subtask-log-injection.md**
  subtask_results.log built from unsanitised caller task text; 602 KB, NUL
  bytes, broken record structure on disk; no cap.

## potential/  (mechanism real, exploitability conditional; disclose as design)
- **locallama-mcp_update_server_unauthenticated-self-update.md**
  Zero-arg tool runs git pull + npm install + build. Currently inert because
  the hardcoded branch `future-testing` does not exist on origin.
- **mcp-text-editor_get_text_file_contents_unrestricted-sensitive-file-read.md**
  (V4, 2026-09-15 — FIRST PYTHON-ARM FINDING, sandbox py3.13, item 86.)
  `get_text_file_contents` serves any absolute path: `/etc/passwd` 1225x and the
  server's own `/proc/self/environ` 1105x, as SUCCESS. The code ships a
  `base_dir` sandbox (`utils.normalize_and_validate_path`) that no caller ever
  enables. Oracle: LLM-selected `check_introspection_sensitive_file_access`
  (+ mandatory `check_file_access` for the /proc paths). Evidence is redacted:
  the served environment contained ToFu's own API key (rotated).
- **uml-mcp_list_diagram_types_crlf-log-injection.md**
  (V5, 2026-09-15, Python arm.) `list_diagram_types` logs the raw caller
  strings with `%s`; `\r`/`\n` in `query` forge log records while the tool
  returns SUCCESS (9 alerts / 5 inputs in 30 s). CWE-117 like V2 but the sink is
  `logging`, not a server-owned file -> potential. ATTRIBUTION NOTE: fired by
  `check_introspection_log_injection`, which was NOT LLM-selected — on the
  Python arm introspection checks run whenever their tracer has evidence
  (`_run_sanitizers`: `in selected or <evidence>`); do not credit LLM selection.

## evidence/
Raw artifacts kept next to the write-ups so disclosure does not depend on any
scratchpad: the gpt-4.1-generated adversarial seed, the fuzzer alert log, the
directed-test outputs, and the polluted locallama log head.

## Positive control (NOT a finding, but useful for the paper)
aaronsb/google-workspace-mcp `manage_scratchpad` was heavily alerted
(208 check_path_traversal) yet is SAFE: resolveWorkspacePath() sanitises each
segment, resolves, and rejects anything escaping the workspace dir, and
verifyPathSafety() adds a realpath symlink check. It is the correct
implementation of exactly what excel-reader-mcp omits. Good contrast pair.

## Why the big alert counts are NOT findings
bsv-mcp (3788), cursor10x (10040), google-workspace (5561) are dominated by
check_url_structure_and_parsing / check_url_hostname_canonicalization /
check_url_ssrf_ip_ranges and check_strict_har/markitdown_security_contract
firing on arguments that are NOT URLs and on tools unrelated to HAR/markitdown.
These sanitizers are not in the parameter-name context guard (fuzzer.py:944),
so they run on every string argument (bug-22 family, item 56). The silent-bug
oracle then fires because the tool correctly succeeds. FP cascade.

Environment exclusions (never executed, not evidence): apisix-mcp (no APISIX
backend, ECONN, 0/2000 success), pluggedin clipboard_set and nationalparks
(no API key).
