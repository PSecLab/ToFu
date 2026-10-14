import json
import logging
from pathlib import Path
from typing import Any, Dict, List


class FeedbackCollector:
    def __init__(self) -> None:
        self.logger = logging.getLogger("viper_mcp.feedback.collector")

    def save_static_context(self, filepath: Path, data: Dict[str, Any]) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, indent=2, ensure_ascii=False)
        self.logger.info(
            "Saved static context: path=%s entries=%d",
            filepath,
            len(data.get("entries", [])) if isinstance(data, dict) else 0,
        )

    def save_round_result(
        self,
        filepath: Path,
        round_id: Any,
        prompt: str,
        response: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "round": round_id,
            "prompt": prompt,
            "response": response,
            "analysis": analysis,
        }
        with open(filepath, "w", encoding="utf-8") as file_obj:
            json.dump(data, file_obj, indent=2, ensure_ascii=False)
        self.logger.info("Saved round result: round=%s path=%s", round_id, filepath)

    def save_triggered(self, filepath: Path, triggered: List[Dict[str, Any]]) -> None:
        if not triggered:
            self.logger.debug("No triggered prompts to save for path=%s", filepath)
            return
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as file_obj:
            json.dump(triggered, file_obj, indent=2, ensure_ascii=False)
        self.logger.info("Saved triggered prompts: count=%d path=%s", len(triggered), filepath)

    def save_anomalies(self, filepath: Path, anomalies: List[Dict[str, Any]]) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as file_obj:
            json.dump(anomalies, file_obj, indent=2, ensure_ascii=False)
        self.logger.info("Saved anomalies: count=%d path=%s", len(anomalies), filepath)
