"""
Build static fuzz context by consolidating SARIF findings with discovered MCP tools.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..codeql.parser import normalize_static_vulnerability_type

if TYPE_CHECKING:
    from ..llm.base import LLMClient


def _extract_sarif_results(sarif_content: Optional[str]) -> List[Dict[str, Any]]:
    if not sarif_content:
        return []
    try:
        obj = json.loads(sarif_content)
    except Exception:
        return []
    if not isinstance(obj, dict):
        return []
    runs = obj.get("runs")
    if not isinstance(runs, list):
        return []
    out: List[Dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if isinstance(result, dict):
                out.append(result)
    return out


def _parse_chain(chain: str) -> Dict[str, Any]:
    tool = ""
    vuln = ""
    line = None
    if "->" in chain:
        tool = chain.split("->", 1)[0].strip().lower()
        vuln = chain.split("->", 1)[1].strip().lower()
    match = re.search(r"@(\d+)", vuln)
    if match:
        try:
            line = int(match.group(1))
        except Exception:
            line = None
    return {"tool": tool, "vuln": vuln, "line": line}


def _extract_function_hint(result: Dict[str, Any]) -> str:
    message = str(result.get("message", {}).get("text", "")).strip()
    match = re.search(r"function\s+([A-Za-z_][A-Za-z0-9_]*)", message)
    return match.group(1) if match else ""


def _build_sarif_hint_map(sarif_results: List[Dict[str, Any]]) -> Dict[tuple[str, Optional[int]], Dict[str, Any]]:
    out: Dict[tuple[str, Optional[int]], Dict[str, Any]] = {}
    for result in sarif_results:
        rule_id = str(result.get("ruleId", "")).strip().lower()
        vuln_type = normalize_static_vulnerability_type(rule_id.split("/")[-1] if rule_id else "")
        locations = result.get("locations")
        if not isinstance(locations, list) or not locations:
            continue
        physical_location = (locations[0] or {}).get("physicalLocation") or {}
        region = physical_location.get("region") or {}
        line = region.get("startLine")
        out[(vuln_type, line)] = {
            "function_hint": _extract_function_hint(result),
            "sink_family": _sink_family(vuln_type),
        }
    return out


def _sink_family(vuln_type: str) -> str:
    normalized = normalize_static_vulnerability_type(vuln_type)
    if normalized == "command_injection":
        return "command"
    if normalized == "ssrf":
        return "request"
    if normalized == "path_traversal":
        return "file"
    return "general"


def _build_report_hint_map(
    report_vulnerabilities: Optional[List[Dict[str, Any]]],
) -> Dict[tuple[str, Optional[int]], Dict[str, Any]]:
    out: Dict[tuple[str, Optional[int]], Dict[str, Any]] = {}
    if not isinstance(report_vulnerabilities, list):
        return out

    for vuln in report_vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        vuln_type = normalize_static_vulnerability_type(
            str(vuln.get("type") or vuln.get("rule_id") or "").strip().lower()
        )
        location = vuln.get("location") if isinstance(vuln.get("location"), dict) else {}
        region = location.get("region") if isinstance(location.get("region"), dict) else {}
        line = region.get("startLine")
        try:
            line = int(line) if line is not None else None
        except Exception:
            line = None

        anchor_function = vuln.get("anchor_function") if isinstance(vuln.get("anchor_function"), dict) else {}
        anchored_flow = vuln.get("anchored_flow") if isinstance(vuln.get("anchored_flow"), dict) else {}
        source_functions = vuln.get("source_functions") if isinstance(vuln.get("source_functions"), list) else []
        tool_candidates = vuln.get("tool_candidates") if isinstance(vuln.get("tool_candidates"), list) else []
        function_hint = (
            str(anchor_function.get("name") or "").strip()
            or str(vuln.get("function_name") or "").strip()
            or str(vuln.get("tool_name") or "").strip()
        )
        evidence = anchored_flow.get("evidence") if isinstance(anchored_flow.get("evidence"), list) else []
        out[(vuln_type, line)] = {
            "tool_name": str(vuln.get("tool_name") or "").strip(),
            "function_hint": function_hint,
            "sink_family": _sink_family(vuln_type),
            "anchor_function": anchor_function,
            "source_functions": [str(item).strip() for item in source_functions if str(item).strip()],
            "tool_candidates": [str(item).strip() for item in tool_candidates if str(item).strip()],
            "anchored_flow": {
                "confirmed": bool(anchored_flow.get("confirmed")),
                "query": anchored_flow.get("query", ""),
                "count": anchored_flow.get("count", 0),
                "evidence": evidence[:3],
            } if anchored_flow else {},
        }
    return out


def _extract_json_object(raw: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        try:
            obj = json.loads(raw[start : end + 1])
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


def _fallback_entries(
    target_chains: List[str],
    tools_info: List[Dict[str, Any]],
    sarif_hint_map: Dict[tuple[str, Optional[int]], Dict[str, Any]],
    report_hint_map: Dict[tuple[str, Optional[int]], Dict[str, Any]],
) -> List[Dict[str, Any]]:
    known_tools = {str(t.get("name", "")).strip().lower() for t in tools_info if isinstance(t, dict)}
    entries: List[Dict[str, Any]] = []
    for chain in target_chains:
        parsed = _parse_chain(chain)
        vuln_no_line = re.sub(r"@\d+$", "", parsed["vuln"]).strip()
        sarif_hint = sarif_hint_map.get((vuln_no_line, parsed["line"]), {})
        report_hint = report_hint_map.get((vuln_no_line, parsed["line"]), {})
        function_hint = report_hint.get("function_hint") or sarif_hint.get("function_hint", "")
        sink_family = report_hint.get("sink_family") or sarif_hint.get("sink_family", "general")
        anchored_flow = report_hint.get("anchored_flow") if isinstance(report_hint.get("anchored_flow"), dict) else {}
        focus = [
            "keep prompt benign and operational",
            "prefer parameters likely to flow into command construction",
            "vary optional flags and edge-case argument combinations",
        ]
        if parsed["tool"] and parsed["tool"] in known_tools:
            focus.append(f"use MCP tool `{parsed['tool']}` explicitly and repeatedly")
        if function_hint:
            focus.append(f"exercise the anchored code path around `{function_hint}`")
        if anchored_flow.get("confirmed"):
            focus.append("prioritize inputs that preserve the confirmed static source-to-sink flow")
        entries.append(
            {
                "target_call_chain": chain,
                "tool_name": parsed["tool"] or "mcp_tool",
                "vulnerability_type": vuln_no_line or "general",
                "line": parsed["line"],
                "function_hint": function_hint,
                "sink_family": sink_family,
                "anchor_function": report_hint.get("anchor_function", {}),
                "source_functions": report_hint.get("source_functions", []),
                "tool_candidates": report_hint.get("tool_candidates", []),
                "anchored_flow": anchored_flow,
                "risk_score": 0.5,
                "prompt_focuses": focus[:5],
            }
        )
    return entries


def _normalize_entries(entries: Any, target_chains: List[str]) -> List[Dict[str, Any]]:
    if not isinstance(entries, list):
        return []
    target_set = set(target_chains)
    out: List[Dict[str, Any]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        chain = str(item.get("target_call_chain") or "").strip()
        if not chain or chain not in target_set:
            continue
        risk = item.get("risk_score", 0.5)
        try:
            risk_score = float(risk)
        except Exception:
            risk_score = 0.5
        risk_score = max(0.0, min(1.0, risk_score))
        parsed = _parse_chain(chain)
        focuses = item.get("prompt_focuses")
        if not isinstance(focuses, list):
            focuses = []
        focuses = [str(x).strip() for x in focuses if str(x).strip()]
        out.append(
            {
                "target_call_chain": chain,
                "tool_name": str(item.get("tool_name") or parsed["tool"] or "mcp_tool").strip(),
                "vulnerability_type": str(item.get("vulnerability_type") or parsed["vuln"] or "general").strip(),
                "line": item.get("line", parsed["line"]),
                "function_hint": str(item.get("function_hint") or "").strip(),
                "sink_family": str(item.get("sink_family") or "general").strip(),
                "anchor_function": item.get("anchor_function") if isinstance(item.get("anchor_function"), dict) else {},
                "source_functions": item.get("source_functions") if isinstance(item.get("source_functions"), list) else [],
                "tool_candidates": item.get("tool_candidates") if isinstance(item.get("tool_candidates"), list) else [],
                "anchored_flow": item.get("anchored_flow") if isinstance(item.get("anchored_flow"), dict) else {},
                "risk_score": risk_score,
                "prompt_focuses": focuses[:8],
            }
        )
    return out


class StaticContextBuilder:
    def __init__(self, llm_client: Optional["LLMClient"] = None):
        self.llm_client = llm_client

    async def build(
        self,
        sarif_content: Optional[str],
        tools_info: List[Dict[str, Any]],
        target_chains: List[str],
        report_vulnerabilities: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        sarif_results = _extract_sarif_results(sarif_content)
        report_hint_map = _build_report_hint_map(report_vulnerabilities)
        fallback = _fallback_entries(
            target_chains,
            tools_info,
            _build_sarif_hint_map(sarif_results),
            report_hint_map,
        )
        entries = fallback
        llm_notes = ""

        if self.llm_client and target_chains:
            prompt_payload = {
                "target_call_chains": target_chains,
                "mcp_tools": tools_info,
                "sarif_results": sarif_results,
                "anchored_report_hints": list(report_hint_map.values()),
            }
            prompt = (
                "Consolidate static findings for MCP fuzzing.\n"
                "You must use all provided SARIF results and MCP tools.\n"
                "Return strict JSON only with schema:\n"
                "{"
                "\"entries\":[{"
                "\"target_call_chain\":\"...\","
                "\"tool_name\":\"...\","
                "\"vulnerability_type\":\"...\","
                "\"line\":123,"
                "\"function_hint\":\"...\","
                "\"sink_family\":\"...\","
                "\"risk_score\":0.0,"
                "\"prompt_focuses\":[\"...\"]"
                "}],"
                "\"notes\":\"short rationale\""
                "}\n"
                "Rules:\n"
                "- target_call_chain must be chosen from target_call_chains only.\n"
                "- risk_score in [0,1].\n"
                "- prompt_focuses should be specific, actionable, and benign-looking.\n"
                "- prefer anchored_report_hints when function_hint or anchored_flow is present.\n"
                "- include one entry per target_call_chain if possible.\n\n"
                f"INPUT:\n{json.dumps(prompt_payload, ensure_ascii=False)}"
            )
            try:
                raw = await self.llm_client.generate(
                    prompt=prompt,
                    system_prompt="Return JSON only. No markdown.",
                    temperature=0.2,
                    max_tokens=3500,
                )
                raw = (raw or "").strip()
                parsed = _extract_json_object(raw)
                if parsed:
                    llm_entries = _normalize_entries(parsed.get("entries"), target_chains)
                    llm_notes = str(parsed.get("notes") or "").strip()
                    if llm_entries:
                        merged = {entry["target_call_chain"]: entry for entry in fallback}
                        for entry in llm_entries:
                            merged[entry["target_call_chain"]] = entry
                        entries = list(merged.values())
            except Exception:
                pass

        entries = sorted(entries, key=lambda x: x.get("risk_score", 0.0), reverse=True)
        chain_map = {entry["target_call_chain"]: entry for entry in entries}
        return {
            "schema_version": "2.0",
            "entries": entries,
            "chain_map": chain_map,
            "summary": {
                "total_entries": len(entries),
                "target_chain_count": len(target_chains),
                "tool_count": len([t for t in tools_info if isinstance(t, dict)]),
                "sarif_result_count": len(sarif_results),
                "anchored_hint_count": len(report_hint_map),
                "tools": sorted(
                    {str(entry.get("tool_name", "")).strip() for entry in entries if entry.get("tool_name")}
                ),
            },
            "llm_notes": llm_notes,
        }
