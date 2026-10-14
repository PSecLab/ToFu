"""
SARIF extractor for JavaScript/TypeScript CodeQL outputs.

This module extracts oracle and enter-hook metadata from standard CodeQL
SARIF reports.
"""
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple


RULE_TO_SINK = {
    "command-injection-from-request": "exec",
    "command-line-injection": "exec",
    "command-injection": "exec",
    "eval-injection": "eval",
    "path-traversal": "readFile",
    "sql-injection": "query",
    "unsafe-file-operation": "writeFile",
    "unvalidated-input": "input",
    "request-forgery-from-request": "request",
    "server-side-request-forgery": "request",
    "full-server-side-request-forgery": "request",
    "mcp-full-ssrf": "request",
    "ssrf": "request",
}

_FLOW_CHAIN_RE = re.compile(
    r"Data flow \(functions\):\s*(.+?)\.\s*",
    flags=re.IGNORECASE | re.DOTALL,
)
_FUNC_TOKEN_RE = re.compile(r"^(anonymous function|<top-level>|function\s+[A-Za-z_$][\w$]*)$")


def _uri_to_file_path(uri: str, base_path: str) -> str:
    if not uri:
        return ""
    if uri.startswith("file://"):
        return uri[7:] or uri
    return str(Path(base_path) / uri) if base_path else uri


def _extract_module_name(file_path: str) -> str:
    """Extract the module name from a file path."""
    name = Path(file_path).stem
    return name


def _message_text(msg: Any) -> str:
    if isinstance(msg, dict):
        return str(msg.get("text", "") or "")
    return str(msg or "")


def _extract_rule_key(rule_id: str) -> str:
    return rule_id.split("/")[-1] if "/" in rule_id else rule_id


def _infer_sink_type(rule_id: str, message_text: str) -> str:
    key = _extract_rule_key(rule_id)
    sink = RULE_TO_SINK.get(key)
    if sink:
        return sink

    lowered = message_text.lower()
    if "exec" in lowered or "command line" in lowered:
        return "exec"
    if "eval" in lowered:
        return "eval"
    if "query" in lowered or "sql" in lowered:
        return "query"
    if "readfile" in lowered or "path" in lowered:
        return "readFile"
    if (
        "ssrf" in lowered
        or "request is sent" in lowered
        or "outbound request" in lowered
        or "full url" in lowered
        or "hostname" in lowered
        or "scheme" in lowered
    ):
        return "request"
    return "unknown"


def _extract_chain_from_result_message(message_text: str) -> List[str]:
    m = _FLOW_CHAIN_RE.search(message_text or "")
    if not m:
        return []
    raw = m.group(1).strip()
    chain = [p.strip() for p in raw.split("->")]
    return [c for c in chain if c]


def _extract_chain_from_thread_flow(thread_flow: Dict[str, Any]) -> List[str]:
    chain: List[str] = []
    for flow_loc in thread_flow.get("locations", []):
        loc = flow_loc.get("location", {})
        token = _message_text(loc.get("message", "")).strip()
        if not token:
            continue
        if _FUNC_TOKEN_RE.match(token):
            if not chain or chain[-1] != token:
                chain.append(token)
    return chain


def _extract_flow_steps(thread_flow: Dict[str, Any], base_path: str) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    for flow_loc in thread_flow.get("locations", []):
        loc = flow_loc.get("location", {})
        phys = loc.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        region = phys.get("region", {})
        file_path = _uri_to_file_path(artifact.get("uri", ""), base_path)
        steps.append(
            {
                "file_path": file_path,
                "line": int(region.get("startLine", 0) or 0),
                "column": int(region.get("startColumn", 0) or 0),
                "text": _message_text(loc.get("message", "")).strip(),
            }
        )
    return steps


def _pick_entry_function(chain: List[str], fallback: str) -> str:
    for fn in chain:
        if fn and fn not in {"anonymous function", "<top-level>"}:
            return fn
    return fallback


def extract_enter_hook(sarif_data: Dict, base_path: str) -> List[Dict]:
    """
    Extract enter-hook rules (call sites / entry functions) from SARIF.

    Each vulnerability result location corresponds to one candidate entry point.
    """
    rules: List[Dict] = []
    seen: set = set()

    for run in sarif_data.get("runs", []):
        results = run.get("results", [])
        for result in results:
            message_text = _message_text(result.get("message", ""))
            chain_from_message = _extract_chain_from_result_message(message_text)

            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                uri = artifact.get("uri", "")
                if not uri:
                    continue

                file_path = _uri_to_file_path(uri, base_path)
                module_name = _extract_module_name(file_path)
                # Prefer the function chain extracted from the message and
                # fall back to threadFlow extraction when needed.
                func_name = _pick_entry_function(chain_from_message, module_name)
                if func_name == module_name:
                    for cf in result.get("codeFlows", []):
                        for tf in cf.get("threadFlows", []):
                            chain = _extract_chain_from_thread_flow(tf)
                            if chain:
                                func_name = _pick_entry_function(chain, module_name)
                                break
                        if func_name != module_name:
                            break

                key = f"{module_name}:{func_name}"
                if key not in seen:
                    seen.add(key)
                    rules.append(
                        {
                            "package_name": "*",
                            "module_name": module_name,
                            "func_name": func_name,
                        }
                    )
    return rules


def extract_oracle(sarif_data: Dict, base_path: str) -> Dict[str, List[Dict]]:
    """
    Extract oracle records (sensitive sinks and locations) from SARIF.

    Format: { "call_chain_key": [ { file_path, sink, line, expr, ... } ] }
    """
    oracle: Dict[str, List[Dict]] = {}

    for run in sarif_data.get("runs", []):
        results = run.get("results", [])
        for result_idx, result in enumerate(results):
            rule_id = result.get("ruleId", "")
            message_text = _message_text(result.get("message", ""))
            sink_type = _infer_sink_type(rule_id, message_text)
            chain_from_message = _extract_chain_from_result_message(message_text)

            # Use result.location as the sink anchor so the reported location
            # matches the original CodeQL alert location.
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                uri = artifact.get("uri", "")
                if not uri:
                    continue

                file_path = _uri_to_file_path(uri, base_path)
                line = int(region.get("startLine", 0) or 0)
                snippet = region.get("snippet", {}).get("text", "")
                expr = snippet.strip() if snippet else f"{sink_type}(...)"
                module_name = _extract_module_name(file_path)

                key = f"{module_name} -> {sink_type}"
                if key not in oracle:
                    oracle[key] = []

                # One SARIF result may contain multiple thread flows.
                flows: List[Tuple[int, int, List[str], List[Dict[str, Any]]]] = []
                for cf_idx, cf in enumerate(result.get("codeFlows", [])):
                    for tf_idx, tf in enumerate(cf.get("threadFlows", [])):
                        chain = chain_from_message or _extract_chain_from_thread_flow(tf)
                        steps = _extract_flow_steps(tf, base_path)
                        flows.append((cf_idx, tf_idx, chain, steps))

                # Preserve at least one record even when codeFlows are absent,
                # using the function chain embedded in the result message.
                if not flows:
                    flows.append((-1, -1, chain_from_message, []))

                for cf_idx, tf_idx, chain, steps in flows:
                    chain_text = " -> ".join(chain) if chain else ""
                    oracle[key].append(
                        {
                            "file_path": file_path,
                            "sink": sink_type,
                            "line": line,
                            "expr": expr,
                            "rule_id": rule_id,
                            "result_index": result_idx,
                            "flow_id": f"r{result_idx}-cf{cf_idx}-tf{tf_idx}",
                            "call_chain": chain_text,
                            "call_chain_functions": chain,
                            "source_function": chain[0] if chain else "",
                            "sink_function": chain[-1] if chain else "",
                            "flow_steps": steps,
                            "result_message": message_text,
                        }
                    )
    return oracle


def extract_from_sarif(
    sarif_path: str,
    output_dir: str,
    base_path: str,
) -> Tuple[str, str]:
    """
    Extract enter_hook.json and oracle.json from a SARIF file.

    Returns:
      (enter_hook_path, oracle_path)
    """
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    enter_hook = extract_enter_hook(sarif_data, base_path)
    enter_path = out / "enter_hook.json"
    with open(enter_path, "w", encoding="utf-8") as f:
        json.dump(enter_hook, f, indent=2, ensure_ascii=False)

    oracle = extract_oracle(sarif_data, base_path)
    oracle_path = out / "oracle.json"
    with open(oracle_path, "w", encoding="utf-8") as f:
        json.dump(oracle, f, indent=2, ensure_ascii=False)

    return str(enter_path), str(oracle_path)
