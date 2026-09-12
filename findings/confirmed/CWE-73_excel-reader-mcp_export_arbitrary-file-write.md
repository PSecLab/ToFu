# Arbitrary File Write / Overwrite via unconstrained `outputPath`

- **Project**: ArchimedesCrypto/excel-reader-mcp  (npm `@archimdescrypto/excel-reader-mcp` 1.0.0)
- **Commit**: 2c41e8a9ecd1d611b7b87896d791c16e5ea98f28
- **Tools**: `export_to_json`, `export_to_csv`
- **Class**: CWE-73 (External Control of File Name or Path); `../` escape is CWE-22
- **Status**: CONFIRMED by directed test (create outside cwd, `../` escape, overwrite existing file)
- **Severity**: High (arbitrary write + attacker-influenced content) if the MCP server is exposed to untrusted tool arguments

## Summary
`export_to_json` / `export_to_csv` accept an `outputPath` argument documented as
"Path to save JSON/CSV file (optional, returns content if not provided)". The
implementation validates only the *type* (`typeof outputPath === 'string'`) and
then calls `writeFileSync(outputPath, content, 'utf-8')` with no path
containment. A caller can therefore write to any path the server process can
reach, including absolute paths and `../`-escapes, and can overwrite existing
files. The written content is the serialised spreadsheet the caller supplied,
so both destination AND content are attacker-influenced.

## Affected code
`src/tools/export/export-to-json.ts`
```js
// validation (type only)
(args.outputPath === undefined || typeof args.outputPath === 'string')
// sink
if (outputPath) { writeFileSync(outputPath, jsonContent, 'utf-8'); }
```
`src/tools/export/export-to-csv.ts:100` is identical with `csvContent`.

## Proof of concept (validated 2026-09-11, server launched from its own dir)
| test | outputPath | result |
|------|-----------|--------|
| write outside cwd | `/<abs>/scratch/abs_write.json` | SUCCESS, file created |
| relative escape | `../../item54_rel_escape.json` | SUCCESS, wrote one level above the target dir |
| overwrite existing | `<existing>/victim_config.txt` | SUCCESS, original replaced with xlsx cell content |

Overwrite proof: a file containing `ORIGINAL CONTENT` was replaced with the
cell value `CELL_FROM_XLSX` from the supplied spreadsheet.

## How it was found
ToFu selected `check_path_traversal` for this tool from its metadata (NOT a
mandatory sanitizer). The LLM adversarial-seed stage generated a seed placing
`../../../../tmp/evil.json` into `outputPath` (see
`evidence/excel-reader-seed_4-gpt41-generated.json`). The tool executed the
write and returned success; ToFu's outcome oracle flagged the silent
acceptance (`evidence/excel-reader-export_to_json-fuzzer-alert.log`).

## Suggested fix
Resolve `outputPath` to an absolute canonical path and require it to stay
within an explicitly configured output directory; reject otherwise. Refuse to
overwrite existing files unless a caller explicitly opts in.

## NOT claimed
Parent-directory creation and storage/inode-exhaustion DoS were not tested; do
not cite them without separate validation.
