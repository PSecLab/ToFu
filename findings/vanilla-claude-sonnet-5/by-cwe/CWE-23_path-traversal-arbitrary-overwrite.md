# CWE-23 -- Relative Path Traversal (2 findings: 2 Tier-A, 0 Tier-B)

vanilla-claude-sonnet-5 static audit, 2026-09-21. Grounded per Phase 2 (verify_findings.py). Static reading only, no execution.

| repo | tool | tier | cwe | file:line | param -> sink | why |
|---|---|---|---|---|---|---|
| zhiwei5576/excel-mcp-server | `writeDataBySheetName` | A | CWE-23 | `src/handlers/excelHandlers.ts:241` | fileAbsolutePath -> XLSX.writeFile(workbook, filePathWithName) | Personally verified excelHandlers.ts:199-241: no existence check gates this path; if a file already exists at the caller-chosen absolute/relative path, its workbook is loaded, one sheet is replaced/added, and the whole file is rewritten in place -- an arbitrary-file-overwrite primitive at any fil... |
| zhiwei5576/excel-mcp-server | `writeSheetData` | A | CWE-23 | `src/handlers/excelHandlers.ts:190` | fileAbsolutePath -> XLSX.writeFile(workbook, filePathWithName) | normalizePath has no root restriction (verified above); caller can create a new file at any writable absolute path on the filesystem, e.g. planting files outside any intended working directory. |
