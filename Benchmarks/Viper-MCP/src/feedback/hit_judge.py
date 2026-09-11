import json
import logging
from typing import Any, Dict, List, Optional

from ..llm.base import LLMClient


HIT_JUDGE_SYSTEM_PROMPT = """
You are a senior MCP security analyst responsible for validating exploit
progression in one fuzzing round. Your task is to determine, from concrete
runtime evidence, how far the execution progressed toward triggering the
target vulnerability and whether the observed behavior constitutes meaningful
exploit confirmation.

Think step by step, applying the stage checklists below as strict requirements
(not loose intuition):

Step 1 - Inventory the evidence: List all concrete evidence, including tools
invoked, oracle hits, call trace entries, and the response summary. Note the
vulnerability family.

Step 2 - Check intent: Determine whether the agent attempted the relevant
risky operation or invoked the target tool path. If there is no evidence of
relevant activity, the stage is not_triggered. If a relevant tool was invoked
but there is no evidence of user input reaching the sink, the stage is
intent_only.

Step 3 - Check sink reachability: Determine whether all three conditions hold:
(a) the evidence points to the target vulnerability family, (b) a relevant
sink was reached via an oracle hit, and (c) user-controlled input reached the
sink arguments (command text, URL/host, file path, or equivalent). If all
three hold, the minimum stage is sink_reached.

Step 4 - Check for environmental blockers: After the sink was reached,
determine whether there is explicit blocker evidence such as permission
denied, binary missing, connection refused, timeout, or sandbox restriction.
If so and the final effect was not observed, the stage is
triggered_but_blocked.

Step 5 - Check for observed effect: Determine whether there is concrete
evidence that the risky side effect actually materialized, such as observed
command output, a completed outbound request, or a successful file write/read.
If yes, the stage is effect_observed.

Step 6 - Assign the highest stage whose checklist is fully satisfied and set
boolean fields consistently: sink_reached is true for sink_reached and above,
environment_blocked is true only for triggered_but_blocked, effect_success is
true only for effect_observed, and is_hit is true only for
triggered_but_blocked or effect_observed.

Additional interpretation rules:
- The target line number may come from source files while runtime traces may
  come from compiled dist files.
- Use only the supplied evidence.
- Do not wrap the JSON in markdown and do not add commentary outside JSON.
- Use real JSON booleans and a JSON array of strings for evidence.

Vulnerability-family guidance:
- command_injection: Treat subprocess/exec/spawn/shell-like sinks as relevant.
  sink_reached requires user-controlled input in command text or argv.
- ssrf: Treat outbound HTTP/request/network-call sinks as relevant.
  sink_reached requires a user-controlled URL/host in the outbound request
  target.
- path_injection: Treat open/read/write/stat/path-resolution sinks as
  relevant. sink_reached requires a user-controlled path in the file
  operation target.

Return strict JSON only:
{
  "trigger_stage": "sink_reached",
  "intent_success": true,
  "sink_reached": true,
  "effect_success": false,
  "environment_blocked": false,
  "environment_reason": "short optional explanation",
  "is_hit": true,
  "confidence": 0.0,
  "reason": "short explanation",
  "evidence": ["item 1", "item 2"]
}
"""

HIT_JUDGE_JSON_REPAIR_SYSTEM_PROMPT = """
You repair one hit_judge output into a strict JSON object.

Rules:
- Output exactly one JSON object and nothing else.
- Preserve the original judgment semantics as much as possible.
- Keep the stage decision consistent with these requirements:
  - sink_reached must be true for stages sink_reached, triggered_but_blocked, and effect_observed.
  - environment_blocked must be true only for triggered_but_blocked.
  - effect_success must be true only for effect_observed.
  - is_hit must be true only for triggered_but_blocked or effect_observed.
- Do not add markdown, explanations, or code fences.
- Use this exact schema and field names:
{
  "trigger_stage": "not_triggered|intent_only|sink_reached|triggered_but_blocked|effect_observed",
  "intent_success": true,
  "sink_reached": true,
  "effect_success": false,
  "environment_blocked": false,
  "environment_reason": "",
  "is_hit": true,
  "confidence": 0.0,
  "reason": "short explanation",
  "evidence": ["item 1", "item 2"]
}
"""

_TRIGGER_STAGES = {
    "not_triggered",
    "intent_only",
    "sink_reached",
    "triggered_but_blocked",
    "effect_observed",
}


def _extract_json_object(raw: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _validate_hit_judge_payload(parsed: Dict[str, Any]) -> Optional[str]:
    required_fields = {
        "trigger_stage",
        "intent_success",
        "sink_reached",
        "effect_success",
        "environment_blocked",
        "environment_reason",
        "is_hit",
        "confidence",
        "reason",
        "evidence",
    }
    missing = [key for key in required_fields if key not in parsed]
    if missing:
        return f"missing required fields: {', '.join(sorted(missing))}"

    trigger_stage = parsed.get("trigger_stage")
    if not isinstance(trigger_stage, str) or trigger_stage not in _TRIGGER_STAGES:
        return "trigger_stage must be one of the allowed stage strings"

    for key in ("intent_success", "sink_reached", "effect_success", "environment_blocked", "is_hit"):
        if type(parsed.get(key)) is not bool:
            return f"{key} must be a JSON boolean"

    if not isinstance(parsed.get("environment_reason"), str):
        return "environment_reason must be a string"
    if not isinstance(parsed.get("reason"), str):
        return "reason must be a string"

    confidence = parsed.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        return "confidence must be a JSON number"
    if confidence < 0.0 or confidence > 1.0:
        return "confidence must be in [0, 1]"

    evidence = parsed.get("evidence")
    if not isinstance(evidence, list):
        return "evidence must be a JSON array"
    if any(not isinstance(item, str) for item in evidence):
        return "evidence must be an array of strings"

    return None

def _infer_vulnerability_family(target_call_chain: str) -> str:
    lower = str(target_call_chain or "").lower()
    if "command" in lower:
        return "command_injection"
    if "ssrf" in lower or "request-forgery" in lower or "request_forgery" in lower:
        return "ssrf"
    if "path" in lower or "file" in lower or "travers" in lower:
        return "path_injection"
    return "generic"


class TargetHitJudge:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.logger = logging.getLogger("viper_mcp.feedback.hit_judge")

    async def _generate_strict_json(
        self,
        *,
        payload_text: str,
    ) -> Dict[str, Any]:
        raw = ""
        last_error = "unknown error"

        for attempt in range(3):
            if attempt == 0:
                prompt = payload_text
                system_prompt = HIT_JUDGE_SYSTEM_PROMPT
                temperature = 0.1
            else:
                prompt = (
                    "The previous hit_judge output was invalid.\n"
                    f"Validation error: {last_error}\n\n"
                    "Rewrite it into a valid JSON object that preserves the same judgment semantics.\n"
                    "Previous output:\n"
                    f"{raw}"
                )
                system_prompt = HIT_JUDGE_JSON_REPAIR_SYSTEM_PROMPT
                temperature = 0.0

            raw = await self.llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=700,
                json_mode=True,
            )
            raw = (raw or "").strip()
            parsed = _extract_json_object(raw)
            if parsed is None:
                last_error = "response is not a valid JSON object"
                continue
            validation_error = _validate_hit_judge_payload(parsed)
            if validation_error is None:
                return {"raw": raw, "parsed": parsed}
            last_error = validation_error

        raise ValueError(f"hit judge LLM returned invalid JSON after retries: {last_error}")

    async def judge(
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
        if not self.llm_client:
            self.logger.warning("Hit judge LLM unavailable for target=%s", target_call_chain)
            return {
                "is_hit": False,
                "confidence": 0.0,
                "reason": "hit judge LLM is not configured",
                "evidence": [],
                "source": "llm_unavailable",
            }

        payload = {
            "target_call_chain": target_call_chain,
            "vulnerability_family": _infer_vulnerability_family(target_call_chain),
            "target_function_hint": target_function_hint,
            "prompt": prompt,
            "call_trace": call_trace,
            "tools_invoked": tools_invoked[:20],
            "oracle_hits": oracle_hits[:20],
            "is_hit_for_chain": is_hit_for_chain,
            "oracle_content_excerpt": (oracle_content or "")[:4000],
            "response_summary": {
                "success": bool(response.get("success", False)),
                "error": str(response.get("error", "") or "")[:1000],
                "tool_errors": response.get("response", {}).get("tool_errors", [])[:5]
                if isinstance(response.get("response"), dict)
                else [],
            },
        }
        self.logger.info(
            "Hit judge request target=%s tools=%s oracle_hits=%d trace=%s",
            target_call_chain,
            tools_invoked[:6],
            len(oracle_hits),
            call_trace[:200],
        )
        try:
            generated = await self._generate_strict_json(
                payload_text=json.dumps(payload, ensure_ascii=False, indent=2),
            )
        except ValueError as e:
            self.logger.warning("Hit judge returned invalid JSON for target=%s error=%s", target_call_chain, e)
            return {
                "is_hit": False,
                "confidence": 0.0,
                "reason": "hit judge LLM returned invalid JSON",
                "evidence": [],
                "source": "llm_invalid_output",
            }
        except Exception as e:
            self.logger.exception("Hit judge request failed for target=%s error=%s", target_call_chain, e)
            return {
                "is_hit": False,
                "confidence": 0.0,
                "reason": f"hit judge LLM request failed: {e}",
                "evidence": [],
                "source": "llm_error",
            }

        raw = generated["raw"]
        parsed = generated["parsed"]
        result = {
            "trigger_stage": parsed["trigger_stage"],
            "intent_success": parsed["intent_success"],
            "sink_reached": parsed["sink_reached"],
            "effect_success": parsed["effect_success"],
            "environment_blocked": parsed["environment_blocked"],
            "environment_reason": parsed["environment_reason"],
            "is_hit": parsed["is_hit"],
            "confidence": float(parsed["confidence"]),
            "reason": parsed["reason"],
            "evidence": parsed["evidence"],
            "source": "llm",
            "llm_raw": raw[:2000],
            "vulnerability_family": _infer_vulnerability_family(target_call_chain),
        }
        self.logger.info(
            "Hit judge result target=%s hit=%s stage=%s blocked=%s confidence=%.2f reason=%s",
            target_call_chain,
            result["is_hit"],
            result["trigger_stage"],
            result["environment_blocked"],
            result["confidence"],
            result["reason"][:200],
        )
        self.logger.debug("Hit judge evidence target=%s evidence=%s", target_call_chain, result["evidence"])
        return result
