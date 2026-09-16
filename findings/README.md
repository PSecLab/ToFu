# ToFu findings — node (arm gpt41-full) + Python (arm gpt41-vm)

Every item is verified against the target's SOURCE and, where the effect is a
filesystem/side effect, by the tool's own success output (and, for the node
confirmed pair, a directed test). Raw alert counts are NOT evidence on their
own — see the FP section. Node arm: laptop, commit e14a363. Python arm: VM,
commit ccbbf24..787a906 (per-row `tofu_commit` authoritative).

Tally: **4 confirmed + 3 potential** across 5 repos.

## confirmed/  (reproduced/demonstrated; disclose to maintainer)
- **CWE-73_excel-reader-mcp_export_arbitrary-file-write.md** (V1, node)
  export_to_json/csv write to an unconstrained caller `outputPath`; directed
  test created files outside cwd, `../` escape, overwrote existing files.
- **CWE-117_locallama-mcp_subtask-log-injection.md** (V2, node)
  subtask_results.log built from unsanitised caller task text; 602 KB, NUL
  bytes, broken record structure; no cap.
- **CWE-22_mcp-text-editor_get_text_file_contents_arbitrary-file-read.md** (V4, python)
  Returned actual `/etc/passwd` and the server's own `/proc/self/environ`
  content as success. Dead `base_dir` jail. (Elevated from potential: content
  was returned, not merely reachable.)
- **CWE-73_mcp-text-editor_create_text_file_arbitrary-file-write.md** (V6, python)
  create_text_file writes any absolute path (/tmp, /var/tmp -> result:ok+hash;
  /etc denied by OS only). Same dead `base_dir`. tumf/mcp-text-editor = full
  arbitrary R/W. ATTRIBUTION: no check_arbitrary_write exists; ToFu supplied the
  adversarial inputs + showed acceptance (alerts that fired were evidence-gated
  cleanup/perms, not LLM-selected).

## potential/  (mechanism real, exploitability conditional; disclose as design risk)
- **locallama-mcp_update_server_unauthenticated-self-update.md** (V3, node)
  Zero-arg tool runs git pull + npm install + build; inert only because the
  hardcoded branch `future-testing` does not exist on origin.
- **uml-mcp_list_diagram_types_crlf-log-injection.md** (V5, python)
  Raw caller strings logged with `%s`; CR/LF in `query` forge log records while
  the tool returns success. CWE-117, sink is `logging` not a server file.
- **mcp-python-interpreter_inline-unsandboxed-code-execution.md** (V7, python)
  run_python_code inline (default) `exec()`s attacker code in-process, no
  sandbox: arbitrary file R/W + env exfiltration + RCE within the MCP host.
  Read /etc/passwd on demand. "By design," but the accident-waiting case.

## Positive controls (NOT findings — the precision contrast for the paper)
- aaronsb/google-workspace-mcp `manage_scratchpad`: resolveWorkspacePath()
  sanitises + realpath symlink check; rejects escapes. Heavily alerted, SAFE.
- yzfly/mcp-python-interpreter `read_file`/`write_file`: jailed to WORKING_DIR
  ("Access denied: Can only read/write files in working directory"). The jail
  tumf/mcp-text-editor ships but never enables (V4/V6).

## Why the big alert counts are NOT findings (FP cascade, verified from source)
- cursor10x-mcp store* (2.5k alerts): stores caller strings (e.g. title
  `file:///etc/passwd`) in its memory DB and echoes them back; path_traversal/
  url_* fired on the string, the tool never opens it. isError:false = "stored ok".
- google-workspace manage_workspace / bsv utils_convertData: HAR-contract FPs
  (`harzip must be str, got NoneType`) firing on tools unrelated to HAR; the
  tools list their own workspace / echo converted data.
- Dominant sanitizers overall — check_url_* , check_strict_har/markitdown,
  check_introspection_incomplete_cleanup (mandatory), _temp_file_leak,
  _resource_exhaustion — fire on nearly every tool. Report deduplicated, and
  subtract the mandatory/evidence-gated layer before crediting LLM selection.

## Exclusions (never executed; not evidence)
apisix (no APISIX backend), meilisearch/supabase (need live backend + creds),
replicate (no REPLICATE_API_TOKEN), locallama on the VM (GLIBC_2.38 native
sqlite), gmail (binds :3000). Recorded in eval/state/skipped.jsonl + run index.
