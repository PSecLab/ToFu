# Why ToFu "missed" Viper's findings — full analysis (reference)

Answers the recurring question: *we built ToFu to catch ANY vulnerability, so why
didn't it find Viper's?* Short answer: ToFu and Viper detect different things by
design; of Viper's 12, ~5 are false positives ToFu was correct to ignore, ~7 are
static path-read flows ToFu can't confirm at runtime (a narrow, real blind spot),
and Viper's entire **python** side produced no valid data (its taint queries error).

## Viper's 12 findings, dissected (all from the NODE / jsql run)
Source lines verified in eval/sandbox/targets (same commits).

### The 5 "command-injection-from-request" — ALL false positives (4 distinct sinks)
Viper's CodeQL query keys on the method name `.exec(`; it cannot tell
`RegExp.prototype.exec` from `child_process.exec`.

| repo | sink | actual code | verdict |
|---|---|---|---|
| aaronsb/google-workspace-mcp | gmail/patch.ts:100 | `/(\d\d?) ([A-Za-z]{3}) (\d{4})/.exec(dateHeader)` | regex — FP |
| aurda012/cursor10x-mcp | index.js:3890 | `codeBlockRegex.exec(text)` | regex — FP |
| jeanibarz/knowledge-base-mcp-server | mcp-resources.ts:107 | `/^kb:\/\/([^/?#]*)…/.exec(uri)` | regex — FP |
| wonderwhy-er/DesktopCommanderMCP | open-browser.ts:29 (×2) | `execFile('open',[url])` / `spawn('cmd',['/c','start','',url],{shell:false})` | argv, no shell — FP |

ToFu did not flag any of these because **they are not bugs**. Static taint with no
runtime check over-reports; this is the precision gap, not a ToFu miss.

### The 7 "file-access-from-request" — real path→read flows, ToFu's genuine blind spot
| repo | sinks | why ToFu missed it |
|---|---|---|
| ArchimedesCrypto/excel-reader-mcp | readExcelFile, WorkbookCache.get×2/.set, loadWorkbook (5) | **format-gated read.** `loadWorkbook(filePath)` parses as xlsx; feed `/etc/passwd` → not a valid workbook → **throws** → no success → the silent-bug oracle cannot fire. Also low-severity: a non-xlsx cannot be exfiltrated as content. |
| aurda012/cursor10x-mcp | indexCodeFile (2) | **not executable in ToFu.** 13/18 cursor10x tools were non-executable (need a project/DB context ToFu didn't provide) → no runtime data. |

Contrast: tumf/mcp-text-editor `get_text_file_contents` is a **plaintext** reader, so
`/etc/passwd` returns its content → ToFu confirmed it (V4). The excel case fails only
because of the format gate.

## The three reasons ToFu "misses" a static-taint finding
1. **It's a Viper FP** (5/12 here). ToFu is correct to stay silent. Not a miss.
2. **Format/semantics gate**: the sink needs an input of a specific format to succeed
   (xlsx, image, …). ToFu requires the tool to RETURN SUCCESS to fire the oracle, so a
   sensitive-but-wrong-format input errors before the sink. (excel ×5.)
3. **Execution gap**: the tool/repo can't run in ToFu (creds/backend/project setup, or
   the repo is excluded). No runtime → no ToFu data. Static taint reads source anyway.
   (cursor10x ×2; DesktopCommander was excluded entirely.)

## Viper's PYTHON taint is broken here — the 6 python "0 vulns" are INVALID
2026-09-16: re-checked. Viper DID attempt all 6 host-python repos on 09-13
(`viper_runs.jsonl`: ok:true, skip_codeql:false, n_result_files:3) but produced NO
`report.json`. The run log (`eval/viper_runs/<repo>/fuzzer.log`) shows why:
```
Running CodeQL analyze with queries: ['pyql/src/CommandInjectionFromRequest.ql',
  'pyql/src/FileAccessFromRequest.ql', 'pyql/src/RequestForgeryFromRequest.ql']
CodeQL analyze failed with exit code 2
Anchor enrichment skipped: report not found
```
So Viper's **pyql** (python) taint queries fail to analyze (jsql/node works). The
6 python "0 vulns" mean *analysis errored*, NOT *repo is clean*. Therefore:
- Viper's 12 findings are **node-only**.
- We CANNOT claim "Viper ran on mcp-text-editor and missed V4/V6." The honest
  statement is "Viper's python taint analysis errored (CodeQL exit 2); no valid
  python comparison data." (The comparison doc's "not run" understated; the precise
  reason is "pyql analyze failed".)
- To get real python data: fix the pyql exit-2 (query-pack/CodeQL-version issue),
  delete the 6 rows from eval/state/viper_runs.jsonl, re-run `--only <repo>`.

## The honest framing (paper: complementarity + ToFu limitations)
- ToFu = **dynamic, runtime-confirmed, high precision**. It reports a bug only when a
  real call with an adversarial input returns success at a modeled sink. Its 7
  findings are hand-confirmed exploitable (V4/V6 return real file content/writes).
- Viper Phase-I = **static taint reachability, low precision** here (5/12 provable FPs)
  and its python side did not run.
- Neither subsumes the other. ToFu's real blind spots: **format-gated sinks** and
  **unexecutable tools**. Fix directions: seed valid-format carrier files whose
  path/name carries the traversal (defeats the format gate), and provide per-tool
  setup so more tools execute.

Bottom line: "ToFu catches ANY vulnerability" is bounded to *any bug that is
runtime-reachable, returns success, and hits a modeled sink* — a deliberate
precision choice. Viper's 12 are not 12 bugs ToFu should have found; they are 5 FPs +
7 low-confidence static flows, on the node side only.
