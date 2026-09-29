#!/usr/bin/env python3
"""Run Cisco MCP Scanner's Behavioral Code Analyzer on a target's SOURCE, keeping every finding.

Run with the scanner's own venv python:
  Benchmarks/Cisco-MCP-Scanner/.venv/bin/python eval/cisco_behavioral.py <source_dir> <out.json>

Why not the CLI: in `stdio` mode the scanner never reads source -- it emits placeholder
`behavioral_analyzer: SAFE` rows for every tool (0 LLM calls; measured 2026-09-29), and the
`behavioral` subcommand drops every finding classified VULNERABILITY, surfacing THREATs only
(cli.py `_behavioral_findings_for_cli` / the classification filter). VULNERABILITY rows are the
class closest to ToFu's bugs, so this driver calls BehavioralCodeAnalyzer.analyze() directly and
records THREAT and VULNERABILITY rows separately. Static only: nothing in the target is executed.
LLM settings come from MCP_SCANNER_LLM_* (same as the CLI).
"""
import asyncio, json, os, sys, time, collections


def main():
    src, out = sys.argv[1], sys.argv[2]
    from mcpscanner.cli import _build_config
    from mcpscanner.core.models import AnalyzerEnum
    from mcpscanner.core.analyzers.behavioral import BehavioralCodeAnalyzer
    cfg = _build_config([AnalyzerEnum.BEHAVIORAL])
    analyzer = BehavioralCodeAnalyzer(cfg)
    t0 = time.time()
    err = None
    try:
        findings = asyncio.run(analyzer.analyze(src, context={"file_path": src}))
    except Exception as e:                      # record, never crash the campaign
        findings, err = [], f"{type(e).__name__}: {e}"[:300]
    rows = []
    for f in findings or []:
        d = f.details or {}
        rows.append({
            "function_name": d.get("function_name"), "source_file": d.get("source_file"),
            "severity": f.severity, "threat_category": f.threat_category, "summary": (f.summary or "")[:500],
            "classification": (d.get("threat_vulnerability_classification") or "").upper() or None,
            "details": {k: (v if isinstance(v, (int, float, bool)) or v is None else str(v)[:400])
                        for k, v in d.items()},
        })
    flagged = [r for r in rows if (r["severity"] or "").upper() not in ("SAFE", "", "UNKNOWN", "INFO")]
    res = {
        "source_path": src, "seconds": round(time.time() - t0, 1), "error": err,
        "n_analyzed_functions": len(getattr(analyzer, "analyzed_functions", []) or []),
        "n_rows": len(rows), "n_flagged": len(flagged),
        "flagged_by_class": dict(collections.Counter(r["classification"] or "UNLABELED" for r in flagged)),
        "flagged_by_severity": dict(collections.Counter(r["severity"] for r in flagged)),
        "flagged_tools": sorted({r["function_name"] for r in flagged if r["function_name"]}),
        "rows": rows,
    }
    json.dump(res, open(out, "w"), indent=1)
    print(json.dumps({k: v for k, v in res.items() if k != "rows"}))


if __name__ == "__main__":
    main()
