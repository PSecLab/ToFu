import json
import logging
from typing import Any, Dict, List

from .hit_judge import TargetHitJudge


class ResponseAnalyzer:
    def __init__(self):
        self.anomalies: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("viper_mcp.feedback.response_analyzer")

    def analyze(self, response: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        analysis = {
            "is_anomaly": False,
            "anomaly_type": None,
            "severity": "low",
            "details": {},
        }

        if not response.get("success"):
            error = str(response.get("error", "") or "")
            lowered = error.lower()
            if "timeout" in lowered:
                analysis["is_anomaly"] = True
                analysis["anomaly_type"] = "timeout"
                analysis["severity"] = "medium"
            elif "crash" in lowered or "exception" in lowered:
                analysis["is_anomaly"] = True
                analysis["anomaly_type"] = "crash"
                analysis["severity"] = "high"

        if "response" in response:
            mcp_response = response["response"]
            if "error" in mcp_response:
                error_code = mcp_response["error"].get("code", 0)
                if error_code < -32600:
                    analysis["is_anomaly"] = True
                    analysis["anomaly_type"] = "protocol_error"
                    analysis["severity"] = "high"

            tool_errors = mcp_response.get("tool_errors", [])
            if tool_errors:
                analysis["is_anomaly"] = True
                analysis["anomaly_type"] = "tool_error"
                analysis["severity"] = "medium"
                analysis["details"]["tool_errors"] = tool_errors

        if response.get("refusal_info"):
            refusal = response["refusal_info"]
            if refusal.get("type") == "refusal":
                analysis["is_anomaly"] = True
                analysis["anomaly_type"] = "refusal"
                analysis["severity"] = "low"
                analysis["details"]["refusal_message"] = refusal.get("message", "")

        if analysis["is_anomaly"]:
            self.anomalies.append({
                "prompt": prompt,
                "response": response,
                "analysis": analysis,
            })
            self.logger.warning(
                "Anomaly detected type=%s severity=%s prompt=%s",
                analysis["anomaly_type"],
                analysis["severity"],
                prompt[:200],
            )
        else:
            self.logger.debug("No anomaly detected for prompt=%s", prompt[:200])

        return analysis

    def get_anomalies(self) -> List[Dict[str, Any]]:
        return self.anomalies

    def save_anomalies(self, filepath: str) -> None:
        with open(filepath, "w", encoding="utf-8") as file_obj:
            json.dump(self.anomalies, file_obj, indent=2, ensure_ascii=False)


class ExecutionValidator:
    def __init__(self, hit_judge: TargetHitJudge):
        self.hit_judge = hit_judge
        self.response_analyzer = ResponseAnalyzer()
        self.logger = logging.getLogger("viper_mcp.feedback.validator")

    async def validate(
        self,
        target_call_chain: str,
        target_function_hint: str,
        prompt: str,
        call_trace: str,
        tools_invoked: List[str],
        oracle_hits: List[Dict[str, Any]],
        is_hit_for_chain: Dict[str, bool],
        oracle_content: str,
        response: Dict[str, Any],
    ) -> Dict[str, Any]:
        self.logger.info(
            "Execution validation start target=%s tools=%s oracle_hits=%d",
            target_call_chain,
            tools_invoked[:6],
            len(oracle_hits),
        )
        hit_judge_details = await self.hit_judge.judge(
            target_call_chain=target_call_chain,
            target_function_hint=target_function_hint,
            prompt=prompt,
            call_trace=call_trace,
            tools_invoked=tools_invoked,
            oracle_hits=oracle_hits,
            is_hit_for_chain=is_hit_for_chain,
            oracle_content=oracle_content,
            response=response,
        )
        anomaly_details = self.response_analyzer.analyze(response, prompt)
        result = {
            "hit_judge": hit_judge_details,
            "anomaly": anomaly_details,
        }
        self.logger.info(
            "Execution validation result target=%s hit=%s anomaly=%s anomaly_type=%s",
            target_call_chain,
            bool(hit_judge_details.get("is_hit", False)),
            bool(anomaly_details.get("is_anomaly", False)),
            anomaly_details.get("anomaly_type"),
        )
        self.logger.debug("Execution validation details target=%s result=%s", target_call_chain, result)
        return result

    def get_anomalies(self) -> List[Dict[str, Any]]:
        return self.response_analyzer.get_anomalies()
