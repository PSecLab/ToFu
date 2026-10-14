import json
import logging
from pathlib import Path
from typing import Any, Dict, List


class InteractionMonitor:
    def __init__(self, interaction_log_path: Path):
        self.interaction_log_path = interaction_log_path
        self.logger = logging.getLogger("viper_mcp.fuzz.interaction_monitor")

    def clear(self) -> None:
        try:
            self.interaction_log_path.parent.mkdir(parents=True, exist_ok=True)
            self.interaction_log_path.write_text("", encoding="utf-8")
            self.logger.debug("Cleared interaction log: %s", self.interaction_log_path)
        except Exception:
            self.logger.exception("Failed to clear interaction log: %s", self.interaction_log_path)

    def read(self) -> str:
        if not self.interaction_log_path.exists():
            self.logger.debug("Interaction log does not exist: %s", self.interaction_log_path)
            return ""
        try:
            text = self.interaction_log_path.read_text(encoding="utf-8", errors="replace").strip()
            self.logger.debug(
                "Read interaction log: path=%s bytes=%d",
                self.interaction_log_path,
                len(text),
            )
            return text or ""
        except Exception:
            self.logger.exception("Failed to read interaction log: %s", self.interaction_log_path)
            return ""

    @staticmethod
    def _stringify(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            pieces = []
            for item in value:
                if isinstance(item, dict):
                    if "text" in item:
                        pieces.append(str(item.get("text", "")))
                    else:
                        pieces.append(json.dumps(item, ensure_ascii=False))
                else:
                    pieces.append(str(item))
            return "\n".join(piece.strip() for piece in pieces if str(piece).strip()).strip()
        if isinstance(value, dict):
            if "text" in value:
                return str(value.get("text", "")).strip()
            return json.dumps(value, ensure_ascii=False)
        return str(value).strip()

    def collect(self) -> Dict[str, Any]:
        interaction_content = self.read()
        request_events: List[Dict[str, Any]] = []
        response_events: List[Dict[str, Any]] = []

        for line in interaction_content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            event = str(item.get("event", "")).strip().lower()
            if event == "request":
                request_events.append(item)
            elif event == "response":
                response_events.append(item)

        request_packets = "\n".join(
            json.dumps(
                {
                    "tool": item.get("tool"),
                    "args": item.get("args", {}),
                    "step": item.get("step"),
                },
                ensure_ascii=False,
            )
            for item in request_events[:12]
        )
        requested_tools: List[str] = []
        for item in request_events:
            tool = str(item.get("tool", "")).strip()
            if tool and tool not in requested_tools:
                requested_tools.append(tool)
        tool_feedbacks: List[Dict[str, Any]] = []
        for item in response_events[:24]:
            tool_feedbacks.append(
                {
                    "tool": item.get("tool"),
                    "step": item.get("step"),
                    "stdout": self._stringify(item.get("stdout")),
                    "stderr": self._stringify(item.get("stderr")),
                    "result": self._stringify(item.get("result")),
                    "error": self._stringify(item.get("error")),
                    "is_error": bool(item.get("is_error", False)),
                }
            )
        self.logger.info(
            "Interaction monitor collected requests=%d responses=%d tool_feedbacks=%d path=%s",
            len(request_events),
            len(response_events),
            len(tool_feedbacks),
            self.interaction_log_path,
        )
        self.logger.debug("Interaction request packets: %s", request_packets[:2000])
        self.logger.debug("Interaction tool feedbacks: %s", json.dumps(tool_feedbacks[:8], ensure_ascii=False)[:2000])
        return {
            "interaction_content": interaction_content,
            "request_packets": request_packets,
            "requested_tools": requested_tools,
            "tool_feedbacks": tool_feedbacks,
            "request_count": len(request_events),
            "response_count": len(response_events),
        }
