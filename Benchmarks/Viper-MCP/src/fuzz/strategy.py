import logging
import random
import re
import json
from typing import Any, Dict, List, Optional, Tuple

from ..codeql.parser import CodeQLParser, normalize_static_vulnerability_type
from ..feedback.optimizer import FeedbackOptimizer
from ..llm.base import LLMClient
from .chromosome import Chromosome
from .mutator import MutationScheduler
from . import prompts
from .seed_generator import SeedGenerator


_VULN_SIGNAL_MAP = {
    "command_injection": {"exec", "spawn", "shell", "command", "process"},
    "command-injection": {"exec", "spawn", "shell", "command", "process"},
    "command-injection-from-request": {"exec", "spawn", "shell", "command", "process"},
    "mcp-command-line-injection": {"exec", "spawn", "shell", "command", "process"},
    "mcp-command-injection": {"exec", "spawn", "shell", "command", "process"},
    "command-line-injection": {"exec", "spawn", "shell", "command", "process"},
    "eval-injection": {"eval", "function", "vm"},
    "sql-injection": {"sql", "query", "select", "insert", "update", "delete", "database"},
    "ssrf": {"request", "http", "https", "url", "network", "fetch"},
    "request-forgery-from-request": {"request", "http", "https", "url", "network", "fetch"},
    "server-side-request-forgery": {"request", "http", "https", "url", "network", "fetch"},
    "full-server-side-request-forgery": {"request", "http", "https", "url", "network", "fetch"},
    "mcp-full-ssrf": {"request", "http", "https", "url", "network", "fetch"},
    "path_traversal": {"file", "path", "read", "write", "open", "exists", "stat", "size", "getsize", "metadata"},
    "path-traversal": {"file", "path", "read", "write", "open", "exists", "stat", "size", "getsize", "metadata"},
    "path-injection": {"file", "path", "read", "write", "open", "exists", "stat", "size", "getsize", "metadata"},
    "mcp-path-injection": {"file", "path", "read", "write", "open", "exists", "stat", "size", "getsize", "metadata"},
    "unsafe-file-operation": {"file", "path", "read", "write", "open", "exists", "stat", "size", "getsize", "metadata"},
}


def _parse_target_call_chain(target_call_chain: str) -> Tuple[str, str]:
    tool = ""
    vuln = ""
    if "->" in target_call_chain:
        tool, vuln = target_call_chain.split("->", 1)
    return tool.strip().lower(), re.sub(r"@\d+$", "", vuln.strip().lower())


def _normalize_tool_name(name: str) -> str:
    text = str(name or "").strip().lower()
    if not text:
        return ""
    return re.sub(r"[^a-z0-9_\-]+", "", text)


def _normalize_vuln_type(vuln_type: str) -> str:
    normalized = normalize_static_vulnerability_type(vuln_type)
    return normalized if normalized != "general" else ""


def _tool_match_terms(tool_name: str) -> List[str]:
    normalized = _normalize_tool_name(tool_name)
    if not normalized:
        return []
    terms = {
        normalized,
        normalized.replace("_", " "),
        normalized.replace("_", "-"),
        normalized.replace("-", "_"),
    }
    return sorted(term for term in terms if term)


class FuzzStrategy:
    def __init__(
        self,
        codeql_parser: Optional[CodeQLParser] = None,
        llm_client: Optional[LLMClient] = None,
        rng: Optional[random.Random] = None,
    ):
        self.codeql_parser = codeql_parser
        self.llm_client = llm_client
        self.seed_generator = SeedGenerator(llm_client)
        self.mutator = MutationScheduler(llm_client)
        self.optimizer = FeedbackOptimizer(llm_client, rng=rng)
        self.seed_pool = self.optimizer.seed_pool
        self.result_history: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("viper_mcp.fuzz.strategy")

    def get_target_call_chains(self) -> List[str]:
        if not self.codeql_parser:
            return []
        return self.codeql_parser.get_target_call_chains()

    async def get_initial_chromosome(
        self,
        target_call_chain: str,
        static_hint: Optional[Dict[str, Any]] = None,
    ) -> Chromosome:
        return await self.seed_generator.generate(target_call_chain, static_hint=static_hint)

    async def get_initial_chromosomes(
        self,
        target_call_chain: str,
        static_hint: Optional[Dict[str, Any]] = None,
    ) -> List[Chromosome]:
        return await self.seed_generator.generate_candidates(target_call_chain, static_hint=static_hint)

    def record_result(self, is_anomaly: bool, payload: Dict[str, Any]) -> None:
        item = {
            "is_anomaly": bool(is_anomaly),
            "payload": payload,
        }
        self.result_history.append(item)
        self.result_history = self.result_history[-200:]

    def seed_scheduling(self) -> Optional[Chromosome]:
        return self.optimizer.select_seed()

    async def mutator_scheduling(self, population: Chromosome) -> str:
        return await self.optimizer.choose_mutator(population)

    async def parameter_mutate(self, population: Chromosome) -> Chromosome:
        return await self.mutator.parameter_mutate(population)

    async def parameter_mutate_candidates(self, population: Chromosome) -> List[Chromosome]:
        return await self.mutator.parameter_mutate_candidates(population)

    async def structure_mutate(self, population: Chromosome) -> Chromosome:
        return await self.mutator.structure_mutate(population)

    async def structure_mutate_candidates(self, population: Chromosome) -> List[Chromosome]:
        return await self.mutator.structure_mutate_candidates(population)

    async def score_round(
        self,
        target_call_chain: str,
        response: Dict[str, Any],
        tools_invoked: List[str],
        request_packets: str,
        call_trace: str,
        oracle_hits: List[Dict[str, Any]],
        *,
        target_tool_name: str = "",
        target_vulnerability_type: str = "",
    ) -> Tuple[float, str, float, str]:
        if self.llm_client:
            result = await self._score_round_with_llm(
                target_call_chain,
                response,
                tools_invoked,
                request_packets,
                call_trace,
                oracle_hits,
                target_tool_name=target_tool_name,
                target_vulnerability_type=target_vulnerability_type,
            )
            if result is not None:
                return result
            self.logger.warning(
                "LLM round scoring failed for target=%s, falling back to rule-based scoring",
                target_call_chain,
            )

        structure_score, structure_reason = self._get_structure_score_rule_based(
            target_call_chain,
            tools_invoked,
            call_trace,
            target_tool_name=target_tool_name,
            target_vulnerability_type=target_vulnerability_type,
        )
        parameter_score, parameter_reason = self._get_parameter_score_rule_based(
            target_call_chain,
            tools_invoked,
            oracle_hits,
            target_tool_name=target_tool_name,
            target_vulnerability_type=target_vulnerability_type,
        )
        return structure_score, structure_reason, parameter_score, parameter_reason

    async def _score_round_with_llm(
        self,
        target_call_chain: str,
        response: Dict[str, Any],
        tools_invoked: List[str],
        request_packets: str,
        call_trace: str,
        oracle_hits: List[Dict[str, Any]],
        *,
        target_tool_name: str = "",
        target_vulnerability_type: str = "",
    ) -> Optional[Tuple[float, str, float, str]]:
        if not self.llm_client:
            return None
        parsed_tool, parsed_vuln = _parse_target_call_chain(target_call_chain)
        target_tool = _normalize_tool_name(target_tool_name or parsed_tool)
        vuln_type = _normalize_vuln_type(target_vulnerability_type or parsed_vuln)
        try:
            raw = await self.llm_client.generate(
                prompt=prompts.ROUND_SCORING_TEMPLATE.format(
                    target_call_chain,
                    target_tool or "(unknown)",
                    vuln_type or "(unknown)",
                    self._summarize_agent_response(response),
                    json.dumps([str(tool) for tool in tools_invoked], ensure_ascii=False),
                    (request_packets or "(no request packets)")[:4000],
                    (call_trace or "(no call trace)")[:4000],
                    self._summarize_oracle_hits(oracle_hits),
                ),
                system_prompt=prompts.ROUND_SCORING_SYSTEM_PROMPT,
                temperature=0.1,
                max_tokens=500,
            )
        except Exception as e:
            self.logger.exception("LLM round scoring failed target=%s error=%s", target_call_chain, e)
            return None

        raw = (raw or "").strip()
        structure_score, structure_reason, parameter_score, parameter_reason = (
            prompts.parse_round_scoring_response(raw)
        )
        self.logger.info(
            "LLM round scoring target=%s structure=%.2f parameter=%.2f structure_reason=%s parameter_reason=%s",
            target_call_chain,
            structure_score,
            parameter_score,
            structure_reason[:160],
            parameter_reason[:160],
        )
        self.logger.debug("LLM round scoring raw response target=%s raw=%s", target_call_chain, raw[:1500])
        return structure_score, structure_reason, parameter_score, parameter_reason

    def _summarize_agent_response(self, response: Dict[str, Any]) -> str:
        if not isinstance(response, dict):
            return str(response)
        if response.get("response", {}).get("content"):
            content = response["response"]["content"]
            if isinstance(content, list):
                text = " ".join(
                    str(item.get("text", ""))
                    for item in content
                    if isinstance(item, dict)
                )
            else:
                text = str(content)
        else:
            text = str(response.get("error", "") or "")
        summary = {
            "success": bool(response.get("success", False)),
            "error": str(response.get("error", "") or "")[:500],
            "content": text[:1500],
            "tool_errors": response.get("response", {}).get("tool_errors", [])[:5]
            if isinstance(response.get("response"), dict)
            else [],
        }
        return json.dumps(summary, ensure_ascii=False)

    def _summarize_oracle_hits(self, oracle_hits: List[Dict[str, Any]]) -> str:
        compact_hits = []
        for hit in oracle_hits[:8]:
            compact_hits.append(
                {
                    "tool": str(hit.get("tool", "")),
                    "sink": str(hit.get("sink", "")),
                    "function": str(hit.get("function", "")),
                    "has_injection_signal": bool(hit.get("has_injection_signal", False)),
                }
            )
        return json.dumps(compact_hits, ensure_ascii=False)

    def get_structure_score(
        self,
        target_call_chain: str,
        tools_invoked: List[str],
        call_trace: str,
        *,
        target_tool_name: str = "",
        target_vulnerability_type: str = "",
    ) -> Tuple[float, str]:
        return self._get_structure_score_rule_based(
            target_call_chain,
            tools_invoked,
            call_trace,
            target_tool_name=target_tool_name,
            target_vulnerability_type=target_vulnerability_type,
        )

    def _get_structure_score_rule_based(
        self,
        target_call_chain: str,
        tools_invoked: List[str],
        call_trace: str,
        *,
        target_tool_name: str = "",
        target_vulnerability_type: str = "",
    ) -> Tuple[float, str]:
        parsed_tool, _ = _parse_target_call_chain(target_call_chain)
        target_tool = _normalize_tool_name(target_tool_name or parsed_tool)
        trace_lower = (call_trace or "").lower()
        normalized_tools = {_normalize_tool_name(str(tool)) for tool in tools_invoked if str(tool).strip()}
        normalized_tools.discard("")
        score = 0.0
        reasons: List[str] = []

        if normalized_tools:
            score += 1.0
            reasons.append("tool_invocation_observed")

        tool_terms = _tool_match_terms(target_tool)
        if target_tool and target_tool in normalized_tools:
            score += 7.0
            reasons.append("target_tool_invoked")
            if len(normalized_tools) == 1:
                score += 2.0
                reasons.append("single_tool_path_stable")
            else:
                score += 1.0
                reasons.append("target_tool_among_multiple_tools")
        elif tool_terms and any(term in trace_lower for term in tool_terms):
            score += 5.0
            reasons.append("target_tool_seen_in_trace")
        elif normalized_tools:
            reasons.append("wrong_tool_path_observed")

        score = max(0.0, min(10.0, score))
        if not reasons:
            reasons.append("no_target_tool_signal")
        self.logger.debug(
            "Structure score target=%s score=%.2f reasons=%s",
            target_call_chain,
            score,
            reasons,
        )
        return score, ",".join(reasons)

    def get_parameter_score(
        self,
        target_call_chain: str,
        tools_invoked: List[str],
        oracle_hits: List[Dict[str, Any]],
        *,
        target_tool_name: str = "",
        target_vulnerability_type: str = "",
    ) -> Tuple[float, str]:
        return self._get_parameter_score_rule_based(
            target_call_chain,
            tools_invoked,
            oracle_hits,
            target_tool_name=target_tool_name,
            target_vulnerability_type=target_vulnerability_type,
        )

    def _get_parameter_score_rule_based(
        self,
        target_call_chain: str,
        tools_invoked: List[str],
        oracle_hits: List[Dict[str, Any]],
        *,
        target_tool_name: str = "",
        target_vulnerability_type: str = "",
    ) -> Tuple[float, str]:
        parsed_tool, parsed_vuln = _parse_target_call_chain(target_call_chain)
        target_tool = _normalize_tool_name(target_tool_name or parsed_tool)
        vuln_type = _normalize_vuln_type(target_vulnerability_type or parsed_vuln)
        score = 0.0
        reasons: List[str] = []
        normalized_tools = {_normalize_tool_name(str(tool)) for tool in tools_invoked if str(tool).strip()}
        normalized_tools.discard("")
        if target_tool and target_tool in normalized_tools:
            score += 1.0
            reasons.append("target_tool_received_parameters")
        elif normalized_tools:
            reasons.append("other_tool_received_parameters")

        signal_terms = _VULN_SIGNAL_MAP.get(vuln_type, set())
        for hit in oracle_hits[:8]:
            hit_tool = _normalize_tool_name(str(hit.get("tool", "")))
            sink = str(hit.get("sink", "")).strip().lower()
            function_name = str(hit.get("function", "")).strip().lower()
            if target_tool and hit_tool == target_tool:
                score += 3.0
                if "target_tool_reached_sink_context" not in reasons:
                    reasons.append("target_tool_reached_sink_context")
            if sink and (sink in signal_terms or any(term in sink for term in signal_terms)):
                score += 3.0
                if "sink_family_matched" not in reasons:
                    reasons.append("sink_family_matched")
            if function_name and any(term in function_name for term in signal_terms):
                score += 1.0
                if "sink_function_matched" not in reasons:
                    reasons.append("sink_function_matched")
            if hit.get("has_injection_signal"):
                score += 2.0
                reasons.append("injection_signal_observed")
                break

        score = max(0.0, min(10.0, score))
        self.logger.debug(
            "Parameter score target=%s score=%.2f tools=%s hits=%d reasons=%s",
            target_call_chain,
            score,
            sorted(normalized_tools),
            len(oracle_hits),
            reasons,
        )
        if not reasons:
            reasons.append("no_sink_signal")
        return score, ",".join(reasons)
