import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional


def _is_placeholder_function_name(name: Any) -> bool:
    text = str(name or "").strip().lower()
    return not text or text in {"anonymous function", "<top-level>"}


def normalize_static_vulnerability_type(vuln_type: Any) -> str:
    text = str(vuln_type or "").strip().lower()
    if not text:
        return "general"
    if "/" in text:
        text = text.split("/")[-1]
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    if not text:
        return "general"

    if (
        "command" in text
        or "exec" in text
        or "spawn" in text
        or "shell" in text
    ):
        return "command_injection"
    if (
        "ssrf" in text
        or "request-forgery" in text
        or ("request" in text and "forg" in text)
    ):
        return "ssrf"
    if (
        "path" in text
        or "file" in text
        or "travers" in text
    ):
        return "path_traversal"
    return text


class CodeQLParser:
    def __init__(self, report_path: str):
        self.report_path = Path(report_path)
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.tools_info: Dict[str, Any] = {}
    
    def load(self) -> bool:
        if not self.report_path.exists():
            return False
        
        with open(self.report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        self.vulnerabilities = data.get("vulnerabilities", [])
        self.tools_info = data.get("tools", {})
        return True

    def _tool_candidates(self, vuln: Dict[str, Any]) -> List[str]:
        ordered: List[str] = []

        candidates = vuln.get("tool_candidates")
        if isinstance(candidates, list):
            ordered.extend(
                str(item).strip()
                for item in candidates
                if str(item).strip() and not _is_placeholder_function_name(item)
            )

        source_functions = vuln.get("source_functions")
        if isinstance(source_functions, list):
            ordered.extend(
                str(item).strip()
                for item in source_functions
                if str(item).strip() and not _is_placeholder_function_name(item)
            )

        anchor_function = vuln.get("anchor_function")
        if isinstance(anchor_function, dict):
            anchor_name = str(anchor_function.get("name") or "").strip()
            if anchor_name and not _is_placeholder_function_name(anchor_name):
                ordered.append(anchor_name)

        deduped: List[str] = []
        for item in ordered:
            if item and item not in deduped:
                deduped.append(item)
        if deduped:
            return deduped

        fallback = [
            str(vuln.get("function_name") or "").strip(),
            str(vuln.get("tool_name") or "").strip(),
            str(vuln.get("module_name") or "").strip(),
        ]
        ordered.extend(item for item in fallback if item and not _is_placeholder_function_name(item))

        for item in ordered:
            if item and item not in deduped:
                deduped.append(item)
        return deduped
    
    def get_vulnerable_tools(self) -> List[str]:
        tools = set()
        for vuln in self.vulnerabilities:
            for tool_name in self._tool_candidates(vuln):
                tools.add(tool_name)
        return list(tools)
    
    def get_vulnerability_types(self) -> List[str]:
        types = set()
        for vuln in self.vulnerabilities:
            vuln_type = normalize_static_vulnerability_type(vuln.get("type", ""))
            if vuln_type:
                types.add(vuln_type)
        return list(types)
    
    def get_tool_vulnerabilities(self, tool_name: str) -> List[Dict[str, Any]]:
        matched = []
        for vuln in self.vulnerabilities:
            if tool_name in self._tool_candidates(vuln):
                matched.append(vuln)
        return matched
    
    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerable_tools": self.get_vulnerable_tools(),
            "vulnerability_types": self.get_vulnerability_types(),
            "tools_count": len(self.tools_info)
        }

    def get_target_call_chains(self) -> List[str]:
        """
        Build target chains from static analysis results.
        Format: "<tool_name> -> <vuln_type>@<line>".
        """
        chains: List[str] = []
        seen = set()
        for vuln in self.vulnerabilities:
            vuln_type = normalize_static_vulnerability_type(vuln.get("type") or "general")

            location = vuln.get("location") or {}
            region = location.get("region") or {}
            line = region.get("startLine")
            suffix = f"@{line}" if line is not None else ""

            for tool_name in self._tool_candidates(vuln) or ["mcp_tool"]:
                chain = f"{tool_name} -> {vuln_type}{suffix}"
                if chain not in seen:
                    seen.add(chain)
                    chains.append(chain)
        return chains
