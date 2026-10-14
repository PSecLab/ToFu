from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


JS_FUNCTION_QUERY = "jsql/src/EnclosingFunctionForAnchor.ql"
JS_COMMAND_FLOW_QUERY = "jsql/src/AnchoredCommandFlow.ql"
JS_FILE_FLOW_QUERY = "jsql/src/AnchoredFileFlow.ql"
JS_REQUEST_FLOW_QUERY = "jsql/src/AnchoredRequestFlow.ql"
JS_TOOL_ROOT_QUERY = "jsql/src/McpToolRootsForAnchor.ql"
JS_CALL_EDGE_QUERY = "jsql/src/JsFunctionCallEdgesForAnchor.ql"

PY_FUNCTION_QUERY = "pyql/src/EnclosingFunctionForAnchor.ql"
PY_COMMAND_FLOW_QUERY = "pyql/src/AnchoredCommandFlow.ql"
PY_PATH_FLOW_QUERY = "pyql/src/AnchoredPathFlow.ql"
PY_REQUEST_FLOW_QUERY = "pyql/src/AnchoredRequestFlow.ql"


def _log(log: Any, level: str, message: str, *args: Any) -> None:
    if log and hasattr(log, level):
        getattr(log, level)(message, *args)


def _load_report(report_file: Path) -> Dict[str, Any]:
    if not report_file.exists():
        return {}
    try:
        data = json.loads(report_file.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _vulnerabilities(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    vulns = report.get("vulnerabilities")
    return vulns if isinstance(vulns, list) else []


def _vulnerability_count(report: Dict[str, Any]) -> int:
    return len(_vulnerabilities(report))


def _normalize_path(value: str) -> str:
    return str(value or "").replace("\\", "/").lstrip("./")


def _same_file(left: str, right: str) -> bool:
    left_norm = _normalize_path(left)
    right_norm = _normalize_path(right)
    return left_norm == right_norm or left_norm.endswith("/" + right_norm) or right_norm.endswith("/" + left_norm)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _clean_function_name(name: Any) -> str:
    text = str(name or "").strip()
    if text.startswith("function "):
        return text[len("function ") :].strip()
    return text


def _is_placeholder_function_name(name: Any) -> bool:
    text = _clean_function_name(name)
    return not text or text.lower() in {"<top-level>", "anonymous function"}


def _merge_tool_candidates(vuln: Dict[str, Any], candidates: Iterable[Any]) -> None:
    merged: List[str] = []
    for candidate in candidates:
        text = _clean_function_name(candidate)
        if not _is_placeholder_function_name(text) and text not in merged:
            merged.append(text)
    existing = vuln.get("tool_candidates")
    if isinstance(existing, list):
        for candidate in existing:
            text = _clean_function_name(candidate)
            if not _is_placeholder_function_name(text) and text not in merged:
                merged.append(text)
    if merged:
        vuln["tool_candidates"] = merged


def _promote_anchor_tool_name(vuln: Dict[str, Any], preferred: Iterable[Any]) -> None:
    for candidate in preferred:
        text = _clean_function_name(candidate)
        if _is_placeholder_function_name(text):
            continue
        current = str(vuln.get("tool_name") or "").strip()
        if current and current != text and not vuln.get("original_tool_name"):
            vuln["original_tool_name"] = current
        if not str(vuln.get("module_name") or "").strip():
            vuln["module_name"] = current
        vuln["tool_name"] = text
        return


def _mark_anchor_tools(report: Dict[str, Any], vuln: Dict[str, Any]) -> None:
    tools = report.setdefault("tools", {})
    if not isinstance(tools, dict):
        return
    for candidate in vuln.get("tool_candidates", []) if isinstance(vuln.get("tool_candidates"), list) else []:
        name = str(candidate or "").strip()
        if not name:
            continue
        item = tools.setdefault(name, {"name": name})
        if isinstance(item, dict):
            item["name"] = name
            item["source"] = "codeql+anchor"


def _query_path(query_pack_root: Optional[str], rel: str) -> Path:
    root = Path(query_pack_root or ".").resolve()
    rel_path = Path(rel)
    candidates = [root / rel_path]
    rel_parts = rel_path.parts
    if rel_parts and root.name == rel_parts[0]:
        candidates.append(root.joinpath(*rel_parts[1:]))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def _run_codeql_query(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    query_rel: str,
    log: Any = None,
) -> List[List[Any]]:
    query = _query_path(query_pack_root, query_rel)
    if not query.exists():
        raise FileNotFoundError(f"Anchor query not found: {query}")
    database = Path(database_path).resolve()

    with tempfile.TemporaryDirectory(prefix="mcp_anchor_") as tmp:
        bqrs_path = Path(tmp) / (query.stem + ".bqrs")
        run_cmd = [
            codeql_binary,
            "query",
            "run",
            f"--database={database}",
            f"--output={bqrs_path}",
            str(query),
        ]
        cwd = str(Path(query_pack_root).resolve()) if query_pack_root else None
        _log(log, "debug", "Running anchor query: %s", " ".join(run_cmd))
        subprocess.run(run_cmd, cwd=cwd, check=True, capture_output=True, text=True)

        decode_cmd = [codeql_binary, "bqrs", "decode", "--format=json", str(bqrs_path)]
        decoded = subprocess.run(decode_cmd, check=True, capture_output=True, text=True)
        data = json.loads(decoded.stdout or "{}")
        rows = data.get("#select", {}).get("tuples", [])
        return rows if isinstance(rows, list) else []


def _load_anchor_functions(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    query_rel: str,
    log: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    rows = _run_codeql_query(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        query_rel=query_rel,
        log=log,
    )
    functions: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        if len(row) < 4:
            continue
        file_path = _normalize_path(str(row[0]))
        item = {
            "file": file_path,
            "start_line": _safe_int(row[1]),
            "end_line": _safe_int(row[2]),
            "name": _clean_function_name(row[3]),
        }
        functions.setdefault(file_path, []).append(item)
    for file_items in functions.values():
        file_items.sort(key=lambda x: (x["end_line"] - x["start_line"], -x["start_line"]))
    return functions


def _load_js_functions(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    log: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    return _load_anchor_functions(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        query_rel=JS_FUNCTION_QUERY,
        log=log,
    )


def _load_py_functions(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    log: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    return _load_anchor_functions(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        query_rel=PY_FUNCTION_QUERY,
        log=log,
    )


def _smallest_enclosing_function(
    functions_by_file: Dict[str, List[Dict[str, Any]]],
    file_path: str,
    line: int,
) -> Optional[Dict[str, Any]]:
    for candidate_file, functions in functions_by_file.items():
        if not _same_file(candidate_file, file_path):
            continue
        for fn in functions:
            if fn["start_line"] <= line <= fn["end_line"]:
                return {
                    "name": fn["name"],
                    "start_line": fn["start_line"],
                    "end_line": fn["end_line"],
                }
    return None


def _flow_kind_for_vuln(vuln: Dict[str, Any]) -> Optional[str]:
    text = " ".join(
        str(vuln.get(key, "") or "").lower()
        for key in ("type", "rule_id", "message")
    )
    if "ssrf" in text or "request forgery" in text or "request-forgery" in text:
        return "request"
    if "command" in text or "exec" in text:
        return "command"
    if "file" in text or "path" in text or "traversal" in text:
        return "file"
    return None


def _flow_kinds_for_report(report: Dict[str, Any]) -> List[str]:
    kinds = {_flow_kind_for_vuln(vuln) for vuln in _vulnerabilities(report)}
    return sorted(kind for kind in kinds if kind)


def _load_js_flows(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    kinds: Optional[Iterable[str]] = None,
    log: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    query_map = {
        "command": (JS_COMMAND_FLOW_QUERY, "AnchoredCommandFlow.ql"),
        "file": (JS_FILE_FLOW_QUERY, "AnchoredFileFlow.ql"),
        "request": (JS_REQUEST_FLOW_QUERY, "AnchoredRequestFlow.ql"),
    }
    flows: Dict[str, List[Dict[str, Any]]] = {"command": [], "file": [], "request": []}
    requested_kinds = set(query_map if kinds is None else kinds)
    for kind, (query_rel, query_name) in query_map.items():
        if kind not in requested_kinds:
            continue
        rows = _run_codeql_query(
            codeql_binary=codeql_binary,
            database_path=database_path,
            query_pack_root=query_pack_root,
            query_rel=query_rel,
            log=log,
        )
        for row in rows:
            if len(row) < 6:
                continue
            item = {
                "source_file": _normalize_path(str(row[0])),
                "source_line": _safe_int(row[1]),
                "sink_file": _normalize_path(str(row[2])),
                "sink_line": _safe_int(row[3]),
                "source_function": _clean_function_name(row[4]),
                "sink_function": _clean_function_name(row[5]),
                "query": query_name,
            }
            if len(row) >= 7:
                item["kind"] = str(row[6] or "")
            flows[kind].append(item)
    return flows


def _function_name_for_location(
    functions_by_file: Dict[str, List[Dict[str, Any]]],
    file_path: str,
    line: int,
) -> str:
    fn = _smallest_enclosing_function(functions_by_file, file_path, line)
    if not fn:
        return "<top-level>"
    return _clean_function_name(fn.get("name", ""))


def _load_py_flows(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    functions_by_file: Dict[str, List[Dict[str, Any]]],
    kinds: Optional[Iterable[str]] = None,
    log: Any = None,
) -> Dict[str, List[Dict[str, Any]]]:
    query_map = {
        "command": (PY_COMMAND_FLOW_QUERY, "AnchoredCommandFlow.ql"),
        "file": (PY_PATH_FLOW_QUERY, "AnchoredPathFlow.ql"),
        "request": (PY_REQUEST_FLOW_QUERY, "AnchoredRequestFlow.ql"),
    }
    flows: Dict[str, List[Dict[str, Any]]] = {"command": [], "file": [], "request": []}
    requested_kinds = set(query_map if kinds is None else kinds)
    for kind, (query_rel, query_name) in query_map.items():
        if kind not in requested_kinds:
            continue
        rows = _run_codeql_query(
            codeql_binary=codeql_binary,
            database_path=database_path,
            query_pack_root=query_pack_root,
            query_rel=query_rel,
            log=log,
        )
        for row in rows:
            if len(row) < 4:
                continue
            source_file = _normalize_path(str(row[0]))
            source_line = _safe_int(row[1])
            sink_file = _normalize_path(str(row[2]))
            sink_line = _safe_int(row[3])
            item = {
                "source_file": source_file,
                "source_line": source_line,
                "sink_file": sink_file,
                "sink_line": sink_line,
                "source_function": _function_name_for_location(functions_by_file, source_file, source_line),
                "sink_function": _function_name_for_location(functions_by_file, sink_file, sink_line),
                "query": query_name,
            }
            if len(row) >= 5:
                item["kind"] = str(row[4] or "")
            flows[kind].append(item)
    return flows


def _flow_matches_vuln(flow: Dict[str, Any], vuln_file: str, vuln_line: int) -> bool:
    return _same_file(flow.get("sink_file", ""), vuln_file) and abs(_safe_int(flow.get("sink_line")) - vuln_line) <= 1


def _js_function_key(file_path: str, start_line: Any, name: Any) -> Optional[Tuple[str, int, str]]:
    file_norm = _normalize_path(file_path)
    line = _safe_int(start_line)
    clean_name = _clean_function_name(name)
    if not file_norm or line <= 0 or not clean_name:
        return None
    return (file_norm, line, clean_name)


def _load_js_tool_roots(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    log: Any = None,
) -> Dict[Tuple[str, int, str], Set[str]]:
    rows = _run_codeql_query(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        query_rel=JS_TOOL_ROOT_QUERY,
        log=log,
    )
    roots: Dict[Tuple[str, int, str], Set[str]] = {}
    for row in rows:
        if len(row) < 4:
            continue
        tool_name = str(row[0] or "").strip()
        if not tool_name:
            continue
        key = _js_function_key(str(row[1] or ""), row[2], row[3])
        if not key:
            continue
        roots.setdefault(key, set()).add(tool_name)
    return roots


def _load_js_call_edges(
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    log: Any = None,
) -> Dict[Tuple[str, int, str], Set[Tuple[str, int, str]]]:
    rows = _run_codeql_query(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        query_rel=JS_CALL_EDGE_QUERY,
        log=log,
    )
    reverse_edges: Dict[Tuple[str, int, str], Set[Tuple[str, int, str]]] = {}
    for row in rows:
        if len(row) < 6:
            continue
        caller = _js_function_key(str(row[0] or ""), row[1], row[2])
        callee = _js_function_key(str(row[3] or ""), row[4], row[5])
        if not caller or not callee:
            continue
        reverse_edges.setdefault(callee, set()).add(caller)
    return reverse_edges


def _resolve_js_tool_candidates(
    *,
    vuln_file: str,
    anchor_fn: Dict[str, Any],
    tool_roots: Dict[Tuple[str, int, str], Set[str]],
    reverse_edges: Dict[Tuple[str, int, str], Set[Tuple[str, int, str]]],
) -> List[str]:
    anchor_key = _js_function_key(vuln_file, anchor_fn.get("start_line"), anchor_fn.get("name"))
    if not anchor_key:
        return []

    discovered: List[str] = []
    seen_tools: Set[str] = set()
    visited: Set[Tuple[str, int, str]] = {anchor_key}
    stack: List[Tuple[str, int, str]] = [anchor_key]

    while stack:
        current = stack.pop()
        for tool_name in sorted(tool_roots.get(current, set())):
            if tool_name and tool_name not in seen_tools:
                seen_tools.add(tool_name)
                discovered.append(tool_name)
        for caller in reverse_edges.get(current, set()):
            if caller not in visited:
                visited.add(caller)
                stack.append(caller)
    return discovered


def _debug_vuln_item(index: int, vuln: Dict[str, Any]) -> Dict[str, Any]:
    location = vuln.get("location") if isinstance(vuln.get("location"), dict) else {}
    artifact = location.get("artifactLocation") if isinstance(location.get("artifactLocation"), dict) else {}
    region = location.get("region") if isinstance(location.get("region"), dict) else {}
    return {
        "index": index,
        "type": vuln.get("type", ""),
        "rule_id": vuln.get("rule_id", ""),
        "file": _normalize_path(str(artifact.get("uri", ""))),
        "line": _safe_int(region.get("startLine")),
        "tool_name": vuln.get("tool_name", ""),
        "function_name": vuln.get("function_name", ""),
        "tool_candidates": vuln.get("tool_candidates", []),
        "tool_source_candidates": vuln.get("tool_source_candidates", []),
        "anchor_function": vuln.get("anchor_function"),
        "source_functions": vuln.get("source_functions", []),
        "anchored_flow": vuln.get("anchored_flow"),
    }


def _build_debug_payload(report: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    anchors: List[Dict[str, Any]] = []
    confirmed_flows: List[Dict[str, Any]] = []
    unconfirmed_flows: List[Dict[str, Any]] = []
    for index, vuln in enumerate(_vulnerabilities(report)):
        item = _debug_vuln_item(index, vuln)
        if item.get("anchor_function"):
            anchors.append(item)
        flow = item.get("anchored_flow")
        if isinstance(flow, dict) and flow.get("confirmed"):
            confirmed_flows.append(item)
        elif isinstance(flow, dict):
            unconfirmed_flows.append(item)
    return {
        **payload,
        "anchors": anchors,
        "confirmed_flows": confirmed_flows,
        "unconfirmed_flows": unconfirmed_flows,
    }


def _attach_js_anchors(
    report: Dict[str, Any],
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    log: Any = None,
) -> Dict[str, Any]:
    functions = _load_js_functions(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        log=log,
    )
    # Temporarily disable the JS tool-root -> sink/anchor mapping stage.
    # We keep the default CodeQL report plus the enclosing-function / flow
    # evidence, but do not run the extra MCP tool identity recovery queries.
    #
    # tool_roots = _load_js_tool_roots(
    #     codeql_binary=codeql_binary,
    #     database_path=database_path,
    #     query_pack_root=query_pack_root,
    #     log=log,
    # )
    # reverse_edges = _load_js_call_edges(
    #     codeql_binary=codeql_binary,
    #     database_path=database_path,
    #     query_pack_root=query_pack_root,
    #     log=log,
    # )
    tool_roots: Dict[Tuple[str, int, str], Set[str]] = {}
    reverse_edges: Dict[Tuple[str, int, str], Set[Tuple[str, int, str]]] = {}
    flows = _load_js_flows(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        kinds=_flow_kinds_for_report(report),
        log=log,
    )

    anchor_count = 0
    confirmed_count = 0
    for vuln in _vulnerabilities(report):
        location = vuln.get("location") if isinstance(vuln.get("location"), dict) else {}
        artifact = location.get("artifactLocation") if isinstance(location.get("artifactLocation"), dict) else {}
        region = location.get("region") if isinstance(location.get("region"), dict) else {}
        vuln_file = _normalize_path(str(artifact.get("uri", "")))
        vuln_line = _safe_int(region.get("startLine"))
        if not vuln_file or not vuln_line:
            continue

        anchor_fn = _smallest_enclosing_function(functions, vuln_file, vuln_line)
        if anchor_fn:
            anchor_count += 1
            vuln["anchor_function"] = anchor_fn
            function_name = _clean_function_name(anchor_fn.get("name", ""))
            vuln["function_name"] = function_name
            _merge_tool_candidates(vuln, [function_name])
            _promote_anchor_tool_name(vuln, [function_name])
            # Temporarily disable the extra JS tool-source recovery stage.
            # tool_candidates = _resolve_js_tool_candidates(
            #     vuln_file=vuln_file,
            #     anchor_fn=anchor_fn,
            #     tool_roots=tool_roots,
            #     reverse_edges=reverse_edges,
            # )
            # if tool_candidates:
            #     vuln["tool_source_candidates"] = tool_candidates
            #     _merge_tool_candidates(vuln, tool_candidates)
            #     _promote_anchor_tool_name(vuln, tool_candidates)
            tool_candidates = []
        else:
            tool_candidates = []

        flow_kind = _flow_kind_for_vuln(vuln)
        if not flow_kind:
            _mark_anchor_tools(report, vuln)
            continue
        matched = [
            flow
            for flow in flows.get(flow_kind, [])
            if _flow_matches_vuln(flow, vuln_file, vuln_line)
        ]
        if matched:
            confirmed_count += 1
            source_functions = sorted(
                {
                    _clean_function_name(flow.get("source_function", ""))
                    for flow in matched
                    if not _is_placeholder_function_name(flow.get("source_function", ""))
                }
            )
            vuln["source_functions"] = source_functions
            _merge_tool_candidates(vuln, source_functions)
            if not tool_candidates:
                _promote_anchor_tool_name(vuln, source_functions or [matched[0].get("sink_function", "")])
            vuln["anchored_flow"] = {
                "confirmed": True,
                "query": matched[0].get("query", ""),
                "count": len(matched),
                "evidence": matched[:10],
            }
        elif flow_kind in {"command", "file", "request"}:
            vuln["anchored_flow"] = {
                "confirmed": False,
                "query": {
                    "command": JS_COMMAND_FLOW_QUERY,
                    "file": JS_FILE_FLOW_QUERY,
                    "request": JS_REQUEST_FLOW_QUERY,
                }[flow_kind],
                "count": 0,
                "evidence": [],
            }
        _mark_anchor_tools(report, vuln)

    return {
        "enabled": True,
        "language": "javascript",
        "anchor_count": anchor_count,
        "confirmed_flow_count": confirmed_count,
        "function_query": str(_query_path(query_pack_root, JS_FUNCTION_QUERY)),
        "flow_queries": [
            Path(JS_COMMAND_FLOW_QUERY).name,
            Path(JS_FILE_FLOW_QUERY).name,
            Path(JS_REQUEST_FLOW_QUERY).name,
        ],
        "tool_root_query": Path(JS_TOOL_ROOT_QUERY).name,
        "call_edge_query": Path(JS_CALL_EDGE_QUERY).name,
        "mode": "codeql_anchor_queries",
    }


def _attach_py_anchors(
    report: Dict[str, Any],
    *,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    log: Any = None,
) -> Dict[str, Any]:
    functions = _load_py_functions(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        log=log,
    )
    flows = _load_py_flows(
        codeql_binary=codeql_binary,
        database_path=database_path,
        query_pack_root=query_pack_root,
        functions_by_file=functions,
        kinds=_flow_kinds_for_report(report),
        log=log,
    )

    anchor_count = 0
    confirmed_count = 0
    query_by_kind = {
        "command": PY_COMMAND_FLOW_QUERY,
        "file": PY_PATH_FLOW_QUERY,
        "request": PY_REQUEST_FLOW_QUERY,
    }
    for vuln in _vulnerabilities(report):
        location = vuln.get("location") if isinstance(vuln.get("location"), dict) else {}
        artifact = location.get("artifactLocation") if isinstance(location.get("artifactLocation"), dict) else {}
        region = location.get("region") if isinstance(location.get("region"), dict) else {}
        vuln_file = _normalize_path(str(artifact.get("uri", "")))
        vuln_line = _safe_int(region.get("startLine"))
        if not vuln_file or not vuln_line:
            continue

        anchor_fn = _smallest_enclosing_function(functions, vuln_file, vuln_line)
        if anchor_fn:
            anchor_count += 1
            vuln["anchor_function"] = anchor_fn
            function_name = _clean_function_name(anchor_fn.get("name", ""))
            vuln["function_name"] = function_name
            _merge_tool_candidates(vuln, [function_name])
            _promote_anchor_tool_name(vuln, [function_name])

        flow_kind = _flow_kind_for_vuln(vuln)
        if not flow_kind:
            _mark_anchor_tools(report, vuln)
            continue
        matched = [
            flow
            for flow in flows.get(flow_kind, [])
            if _flow_matches_vuln(flow, vuln_file, vuln_line)
        ]
        if matched:
            confirmed_count += 1
            source_functions = sorted(
                {
                    _clean_function_name(flow.get("source_function", ""))
                    for flow in matched
                    if not _is_placeholder_function_name(flow.get("source_function", ""))
                }
            )
            vuln["source_functions"] = source_functions
            _merge_tool_candidates(vuln, source_functions)
            _promote_anchor_tool_name(vuln, source_functions or [matched[0].get("sink_function", "")])
            vuln["anchored_flow"] = {
                "confirmed": True,
                "query": matched[0].get("query", ""),
                "count": len(matched),
                "evidence": matched[:10],
            }
        elif flow_kind in query_by_kind:
            vuln["anchored_flow"] = {
                "confirmed": False,
                "query": query_by_kind[flow_kind],
                "count": 0,
                "evidence": [],
            }
        _mark_anchor_tools(report, vuln)

    return {
        "enabled": True,
        "language": "python",
        "anchor_count": anchor_count,
        "confirmed_flow_count": confirmed_count,
        "function_query": str(_query_path(query_pack_root, PY_FUNCTION_QUERY)),
        "flow_queries": [
            Path(PY_COMMAND_FLOW_QUERY).name,
            Path(PY_PATH_FLOW_QUERY).name,
            Path(PY_REQUEST_FLOW_QUERY).name,
        ],
        "mode": "codeql_anchor_queries",
    }


def _metadata_only(
    *,
    report: Dict[str, Any],
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str],
    language: str,
    reason: str = "",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "enabled": Path(database_path).exists(),
        "language": language or "",
        "anchor_count": _vulnerability_count(report),
        "codeql_binary": codeql_binary,
        "database_path": str(database_path),
        "query_pack_root": query_pack_root or "",
        "mode": "metadata_only",
    }
    if reason:
        payload["reason"] = reason
    return payload


def enrich_report_with_anchored_evidence(
    report_path: str,
    codeql_binary: str,
    database_path: str,
    query_pack_root: Optional[str] = None,
    language: str = "",
    debug_output_path: Optional[str] = None,
    log: Any = None,
) -> bool:
    """Attach CodeQL-backed anchored evidence to a converted report.

    JavaScript/TypeScript and Python reports get function anchors plus flow
    confirmations from the local anchor QL rules. Unsupported languages keep
    the old best-effort metadata path so experiments are not made brittle.
    """
    report_file = Path(report_path)
    report = _load_report(report_file)
    if not report:
        _log(log, "warning", "Anchored evidence skipped: report is missing or invalid: %s", report_file)
        return False

    database_dir = Path(database_path)
    normalized_language = (language or "").lower()
    if not database_dir.exists():
        payload = _metadata_only(
            report=report,
            codeql_binary=codeql_binary,
            database_path=database_path,
            query_pack_root=query_pack_root,
            language=language,
            reason="CodeQL database path not found",
        )
        report["anchored_evidence"] = payload
        _write_json(report_file, report)
        if debug_output_path:
            _write_json(Path(debug_output_path), _build_debug_payload(report, payload))
        return False

    try:
        if normalized_language in {"javascript", "typescript", "nodejs", "js"}:
            payload = _attach_js_anchors(
                report,
                codeql_binary=codeql_binary,
                database_path=str(database_dir),
                query_pack_root=query_pack_root,
                log=log,
            )
        elif normalized_language in {"python", "py"}:
            payload = _attach_py_anchors(
                report,
                codeql_binary=codeql_binary,
                database_path=str(database_dir),
                query_pack_root=query_pack_root,
                log=log,
            )
        else:
            payload = _metadata_only(
                report=report,
                codeql_binary=codeql_binary,
                database_path=database_path,
                query_pack_root=query_pack_root,
                language=language,
                reason="Full anchored QL flow is currently implemented for JavaScript/TypeScript and Python only",
            )
    except Exception as exc:
        _log(log, "warning", "Anchored evidence query failed, falling back to metadata only: %s", exc)
        payload = _metadata_only(
            report=report,
            codeql_binary=codeql_binary,
            database_path=database_path,
            query_pack_root=query_pack_root,
            language=language,
            reason=f"anchor query failed: {exc}",
        )

    report["anchored_evidence"] = payload
    _write_json(report_file, report)
    if debug_output_path:
        _write_json(Path(debug_output_path), _build_debug_payload(report, payload))

    _log(log, "info", "Anchored evidence written: %s", report_file)
    return payload.get("mode") == "codeql_anchor_queries"
