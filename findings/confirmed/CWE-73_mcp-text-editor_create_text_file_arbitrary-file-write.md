# V6 (confirmed) — tumf/mcp-text-editor `create_text_file`: arbitrary file WRITE to any absolute path (CWE-73 / CWE-22)

**Status: CONFIRMED** (mechanism + source; directed on-disk test pending, see below).
Second finding in tumf/mcp-text-editor and the strong result of the Python arm:
the same repo that leaks arbitrary **reads** (V4) also accepts arbitrary
**writes**. Same root cause: a `base_dir` sandbox that exists in the code and is
never enabled.

| | |
|---|---|
| repo | tumf/mcp-text-editor (113 stars) |
| commit | `2d66b6fa1cf1ab1241b90e8bc71ece19adc615f2` |
| tool | `create_text_file` (also `insert_/patch_/append_text_file_contents`, which need an existing file) |
| weakness | CWE-73 external control of filename/path → CWE-22 path traversal; write primitive |
| run | VM (Linux, py3.13), gpt-4.1 temp0 seed 20260910, `eval/runs/gpt41-vm/tumf__mcp-text-editor__create_text_file.log` |
| provenance | campaign gpt41-vm (header commit ccbbf24; this config ran 787a906 post-pull — behaviourally identical for this target) |

## Evidence (traceable to the log above)
ToFu's LLM seeds drove `create_text_file` at absolute paths outside any
workspace; the tool returned success and a content hash for each:
```
{'file_path': '/tmp/cleanup.txt',       'contents': 'cleanup test'}      -> {"result": "ok", "file_hash": "6d35fb63..."}
{'file_path': '/tmp/typeconfusion.txt', 'contents': '12345'}             -> {"result": "ok", "file_hash": "f33ae3bc..."}
{'file_path': '/var/tmp/secret.txt',    'contents': '../../../../etc/shadow'} -> {"result": "ok", ...}  (+ insecure-perms alert on /var/tmp/secret.txt)
{'file_path': '/tmp/logging.txt',       'contents': 'password=1234'}     -> {"result": "ok", "file_hash": "9a28ca61..."}
```
`/etc/passwd\x00.txt` and `/tmp/../../../../etc/passwd` returned `None` (OS
denied / null-byte + `..` rejected), so **only OS permissions limit the reach** —
the tool itself imposes none. Same posture as V1 (excel-reader `outputPath`).

## Source (local: eval/sandbox/targets, same commit)
`src/mcp_text_editor/text_editor.py:83`
```python
return normalize_and_validate_path(str(file_path))     # base_dir omitted -> None
```
`src/mcp_text_editor/utils.py::normalize_and_validate_path(file_path, base_dir=None)`:
its docstring — "If base_dir is None, absolute paths are allowed" — and the strict
branch (no absolute paths, `..` rejection, `relative_to(base)`) runs **only when
`base_dir` is provided**. No caller passes it; there is no config/env to enable it
(`_validate_environment()` is a stub). The jail is dead code, exactly as in V4.

## Attribution — read before citing (RQ2/RQ3, HANDOFF §2)
There is **no `check_arbitrary_write` sanitizer**. ToFu's contribution here is the
LLM-generated adversarial *inputs* (absolute paths / traversal) plus in-process
execution showing the tool accepts them and returns `ok`. The oracle alerts that
actually fired on these runs were `check_introspection_incomplete_cleanup`
("left /tmp/cleanup.txt on disk") and `check_introspection_insecure_file_permissions`
("/var/tmp/secret.txt mode 0o664") — both are **evidence-gated, not
LLM-selected** (fuzzer.py `_run_sanitizers`: `in selected or <evidence>`), and
neither names the real weakness. The arbitrary-write conclusion is from triaging
the inputs/outputs, corroborated by source. So: **ToFu surfaced it; a single
sanitizer signature did not label it.** Do not present this as a clean
silent-bug oracle hit.

## Why confirmed (and what is still pending)
- The tool returned `"result": "ok"` + a content hash (computed from bytes it
  wrote) for four distinct absolute-path targets, and the source confirms no
  restriction with `base_dir=None`. Mechanism is proven.
- PENDING for disclosure (mirror V1's directed test, which this session cannot
  run — the writes happened on the VM, not this host): via a clean MCP client,
  `create_text_file("/tmp/tofu_v6_probe.txt", "...")` and confirm the file
  exists on disk with the returned hash; then attempt a path that proves escape
  from any intended workspace (e.g. the user's home). Until then this is
  CONFIRMED-by-mechanism, disclosure-ready after the directed test.

## Disclosure
Combine with V4 (same repo, same dead `base_dir`): tumf/mcp-text-editor exposes
**arbitrary read and write** to any path the server process can access. Fix: wire
`base_dir` (env, e.g. `MCP_TEXT_EDITOR_BASE_DIR`, default cwd) through every
handler and deny absolute/`..`/`/proc`,`/etc`,`/dev` when unrestricted.

## Contrast pair (positive control, same arm)
yzfly/mcp-python-interpreter `read_file`/`write_file` do this correctly: both
resolve under `WORKING_DIR` and return "Access denied: Can only read/write files
in working directory" for anything outside — the jail tumf/mcp-text-editor ships
but never turns on. Good side-by-side for the paper.
