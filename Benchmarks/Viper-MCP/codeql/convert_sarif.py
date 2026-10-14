"""
Convert CodeQL SARIF output to fuzzer report.json format.

Report format expected by CodeQLParser:
  - vulnerabilities: list of { type, tool_name, message, rule_id, location }
  - tools: dict of tool_name -> { name, source }
"""
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


def _extract_tool_name(location: Dict[str, Any]) -> str:
    """Extract tool/module name from SARIF location."""
    phys = location.get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    uri = artifact.get("uri", "")
    if not uri:
        return "unknown"
    name = Path(uri).stem
    return name if name else "unknown"


def convert_sarif_to_report(
    sarif_path: str,
    output_path: str,
    log: Optional[Any] = None,
) -> None:
    def _log(msg: str) -> None:
        if log and hasattr(log, "info"):
            log.info(msg)
        else:
            print(msg, file=sys.stderr)

    path = Path(sarif_path)
    if not path.exists():
        _log(f"SARIF file not found: {sarif_path}")
        return

    with open(path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    vulnerabilities: List[Dict[str, Any]] = []
    tools_info: Dict[str, Dict[str, str]] = {}

    for run in sarif_data.get("runs", []):
        results = run.get("results", [])
        for result in results:
            rule_id = result.get("ruleId", "")
            message = result.get("message", {})
            msg_text = message.get("text", "") if isinstance(message, dict) else str(message)
            # Vuln type from ruleId (e.g. js/command-injection -> command-injection)
            vuln_type = rule_id.split("/")[-1] if "/" in rule_id else rule_id

            for location in result.get("locations", []):
                tool_name = _extract_tool_name(location)
                phys = location.get("physicalLocation", {})
                vuln = {
                    "type": vuln_type,
                    "tool_name": tool_name,
                    "module_name": tool_name,
                    "message": msg_text,
                    "rule_id": rule_id,
                    "location": phys,
                }
                vulnerabilities.append(vuln)
                if tool_name not in tools_info:
                    tools_info[tool_name] = {"name": tool_name, "source": "codeql"}

    report = {
        "vulnerabilities": vulnerabilities,
        "tools": tools_info,
        "summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerable_tools": list(tools_info.keys()),
            "vulnerability_types": list({v["type"] for v in vulnerabilities}),
        },
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    _log(f"Converted SARIF to report: {len(vulnerabilities)} vulnerabilities, {len(tools_info)} tools -> {output_path}")
