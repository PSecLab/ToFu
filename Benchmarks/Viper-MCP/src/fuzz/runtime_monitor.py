import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


COMMAND_INJECTION_PATTERN = re.compile(r"(;|&&|\|\||\$\(|`|\$\{|>\s*/|<\s*/|\n)")
PYTHON_FRAME_PATTERN = re.compile(r'^File "(.+?)", line (\d+), in ([A-Za-z_][A-Za-z0-9_]*)$')
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_INTERNAL_ORIGIN_SUFFIXES = (
    "script/mcp_stdio_guard.py",
    "script/python_entrypoint.py",
    "instrumentation/python/mcp_fuzzer_hook.py",
    "instrumentation/javascript/node_hook.js",
)


def _normalize_tool_name(name: Any) -> str:
    raw = str(name or "").strip()
    if not raw or raw == "<module>":
        return ""
    text = raw.lower()
    return re.sub(r"[^a-z0-9_\-]+", "", text)


def _extract_command_text(item: Dict[str, Any]) -> str:
    args = item.get("args")
    if isinstance(args, list) and args:
        first = args[0]
        if isinstance(first, str):
            try:
                payload = json.loads(first)
                if isinstance(payload, dict) and payload.get("command"):
                    return str(payload.get("command", "")).strip()
            except Exception:
                pass
            return first.strip()
    return ""


def _has_injection_signal(command_text: str) -> bool:
    return bool(COMMAND_INJECTION_PATTERN.search(command_text))


def _normalize_path_text(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip()


def _is_internal_launcher_event(item: Dict[str, Any]) -> bool:
    sink_raw = str(item.get("sink", "") or "").strip()
    if sink_raw == "hook_init":
        return True

    origin = item.get("origin") if isinstance(item.get("origin"), dict) else {}
    origin_file = _normalize_path_text(origin.get("file", ""))
    if not origin_file:
        return False

    root_text = _normalize_path_text(_PROJECT_ROOT)
    if root_text and origin_file.startswith(root_text):
        rel = origin_file[len(root_text) :].lstrip("/")
        if any(rel.endswith(suffix) for suffix in _INTERNAL_ORIGIN_SUFFIXES):
            return True

    return any(origin_file.endswith("/" + suffix) or origin_file.endswith(suffix) for suffix in _INTERNAL_ORIGIN_SUFFIXES)


class RuntimeMonitor:
    def __init__(self, oracle_path: Path):
        self.oracle_path = oracle_path
        self.logger = logging.getLogger("viper_mcp.fuzz.runtime_monitor")

    def clear(self) -> None:
        try:
            self.oracle_path.parent.mkdir(parents=True, exist_ok=True)
            self.oracle_path.write_text("", encoding="utf-8")
            self.logger.debug("Cleared oracle file: %s", self.oracle_path)
        except Exception:
            self.logger.exception("Failed to clear oracle file: %s", self.oracle_path)

    def read(self) -> str:
        if not self.oracle_path.exists():
            self.logger.debug("Oracle file does not exist: %s", self.oracle_path)
            return ""
        try:
            text = self.oracle_path.read_text(encoding="utf-8", errors="replace").strip()
            self.logger.debug(
                "Read oracle file: path=%s bytes=%d",
                self.oracle_path,
                len(text),
            )
            return text or ""
        except Exception:
            self.logger.exception("Failed to read oracle file: %s", self.oracle_path)
            return ""

    def collect(self) -> Dict[str, Any]:
        oracle_content = self.read()
        tools_invoked, oracle_hits, is_hit_for_chain = self._parse_oracle_for_trace(oracle_content)
        trace_parts = [
            f"{hit.get('tool') or 'unknown'}@{hit.get('line') or '?'}:{hit.get('sink')}"
            for hit in oracle_hits[:8]
        ]
        oracle_commands = [
            hit.get("command_text", "")
            for hit in oracle_hits
            if isinstance(hit, dict) and str(hit.get("command_text", "")).strip()
        ][:6]
        call_trace = (
            ", ".join(trace_parts)
            if trace_parts
            else ", ".join(tools_invoked) if tools_invoked else "no tools called"
        )
        call_stack_text = self._extract_call_stack_text(oracle_content)
        return {
            "oracle_content": oracle_content,
            "tools_invoked": tools_invoked,
            "oracle_hits": oracle_hits,
            "is_hit_for_chain": is_hit_for_chain,
            "call_trace": call_trace,
            "oracle_commands": oracle_commands,
            "call_stack_text": call_stack_text,
        }

    def _extract_call_stack_text(self, oracle_content: str) -> str:
        stacks: List[str] = []
        for line in oracle_content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            stack = item.get("stack")
            if not isinstance(stack, list) or not stack:
                continue
            frames = [str(frame).strip() for frame in stack if str(frame).strip()]
            if not frames:
                continue
            stacks.append("\n".join(frames[:12]))
            if len(stacks) >= 4:
                break
        return "\n\n---\n\n".join(stacks)

    def _parse_oracle_for_trace(
        self,
        oracle_content: str,
    ) -> Tuple[List[str], List[Dict[str, Any]], Dict[str, bool]]:
        tools_invoked: List[str] = []
        oracle_hits: List[Dict[str, Any]] = []
        is_hit_for_chain: Dict[str, bool] = {}
        if not oracle_content.strip():
            return tools_invoked, oracle_hits, is_hit_for_chain
        try:
            data = json.loads(oracle_content)
            if not isinstance(data, dict):
                raise TypeError("oracle is not dict json")
            self.logger.debug("Parsing oracle content as aggregated JSON map")
            for chain_key, hits in data.items():
                if not isinstance(hits, list):
                    continue
                is_hit_for_chain[chain_key] = len(hits) > 0
                if "->" in chain_key:
                    tool = chain_key.split("->")[0].strip()
                    if tool and tool not in tools_invoked:
                        tools_invoked.append(tool)
                for hit in hits[:3]:
                    if isinstance(hit, dict):
                        oracle_hits.append(
                            {
                                "tool": chain_key.split("->")[0].strip() if "->" in chain_key else "",
                                "sink": hit.get("sink", ""),
                                "line": hit.get("line"),
                                "file_path": hit.get("file_path", ""),
                            }
                        )
            self.logger.info(
                "Runtime monitor parsed aggregated oracle: tools=%s hits=%d chains=%d",
                tools_invoked,
                len(oracle_hits),
                len(is_hit_for_chain),
            )
            return tools_invoked, oracle_hits, is_hit_for_chain
        except (json.JSONDecodeError, TypeError):
            self.logger.debug("Oracle content is not aggregated JSON; fallback to JSONL parsing")

        for line in oracle_content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            if _is_internal_launcher_event(item):
                continue
            sink_raw = str(item.get("sink", "")).strip()
            sink = sink_raw.split(".")[-1].strip().lower() if sink_raw else ""

            stack = item.get("stack") if isinstance(item.get("stack"), list) else []
            file_path = ""
            line_no: Optional[int] = None
            tool = ""
            origin = item.get("origin") if isinstance(item.get("origin"), dict) else {}
            origin_function = str(origin.get("function", "")).strip()
            origin_file = str(origin.get("file", "")).strip()
            origin_line = origin.get("line")
            try:
                origin_line = int(origin_line) if origin_line is not None else None
            except Exception:
                origin_line = None

            command_text = _extract_command_text(item)
            business_function = origin_function

            for frame in stack:
                if not isinstance(frame, str):
                    continue
                if not tool:
                    py_match = PYTHON_FRAME_PATTERN.match(frame)
                    if py_match:
                        tool = _normalize_tool_name(py_match.group(3))
                    match_fn = re.search(r"\bat\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|$)", frame)
                    if match_fn and not tool:
                        function_name = match_fn.group(1)
                        tool = _normalize_tool_name(function_name)
                if not file_path:
                    py_match = PYTHON_FRAME_PATTERN.match(frame)
                    if py_match:
                        file_path = py_match.group(1)
                        try:
                            line_no = int(py_match.group(2))
                        except Exception:
                            line_no = None
                    match_loc = re.search(r"\((.*?):(\d+):(\d+)\)$", frame)
                    if not match_loc and not file_path:
                        match_loc = re.search(r"\bat\s+(.*?):(\d+):(\d+)$", frame)
                    if match_loc and not file_path:
                        file_path = match_loc.group(1)
                        try:
                            line_no = int(match_loc.group(2))
                        except Exception:
                            line_no = None
                if not tool and not file_path:
                    match_file = re.search(r"/src/([a-z0-9_-]+)\.(?:t|j)s", frame, re.IGNORECASE)
                    if match_file:
                        tool = match_file.group(1).lower()

            if origin_file:
                file_path = origin_file
            if origin_line is not None:
                line_no = origin_line
            if not tool and origin_function:
                tool = _normalize_tool_name(origin_function)

            if tool and tool not in tools_invoked:
                tools_invoked.append(tool)
            if sink:
                oracle_hits.append(
                    {
                        "tool": tool,
                        "sink": sink,
                        "line": line_no,
                        "file_path": file_path,
                        "function": business_function,
                        "command_text": command_text,
                        "has_injection_signal": _has_injection_signal(command_text),
                    }
                )
        self.logger.info(
            "Runtime monitor parsed JSONL oracle: tools=%s hits=%d trace=%s",
            tools_invoked,
            len(oracle_hits),
            ", ".join(
                f"{hit.get('tool') or 'unknown'}:{hit.get('sink')}" for hit in oracle_hits[:6]
            ) or "none",
        )
        self.logger.debug("Runtime monitor chain hit flags: %s", is_hit_for_chain)
        return tools_invoked, oracle_hits, is_hit_for_chain
