import logging
import asyncio
from typing import Any, Dict, Optional

from ..llm.base import LLMClient
from .chromosome import Chromosome
from .prompts import (
    INIT_PROMPT_SYSTEM_PROMPT,
    build_init_prompt_with_style,
    get_prompt_template_variants,
    parse_init_prompt_from_response,
)


class SeedGenerator:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.logger = logging.getLogger("viper_mcp.fuzz.seed_generator")

    async def generate(
        self,
        target_call_chain: str,
        static_hint: Optional[Dict[str, Any]] = None,
    ) -> Chromosome:
        candidates = await self.generate_candidates(target_call_chain, static_hint=static_hint)
        return candidates[0] if candidates else Chromosome(target_call_chain=target_call_chain)

    def _prepare_base_chromosome(
        self,
        target_call_chain: str,
        static_hint: Optional[Dict[str, Any]],
    ) -> tuple[Chromosome, str]:
        chromosome = Chromosome(target_call_chain=target_call_chain)
        extra_hint = ""

        if static_hint:
            static_tool_name = str(static_hint.get("tool_name") or "").strip()
            static_vuln_type = str(static_hint.get("vulnerability_type") or "").strip()
            static_line = static_hint.get("line")
            chromosome.target_tool_name = static_tool_name
            chromosome.target_vulnerability_type = static_vuln_type
            chromosome.target_function_hint = str(static_hint.get("function_hint") or "").strip()
            if static_tool_name or static_vuln_type:
                suffix = ""
                try:
                    suffix = f"@{int(static_line)}" if static_line is not None else ""
                except Exception:
                    suffix = ""
                normalized_tool = static_tool_name or chromosome.target_call_chain.split("->", 1)[0].strip()
                normalized_vuln = static_vuln_type or chromosome.target_call_chain.split("->", 1)[1].split("@", 1)[0].strip()
                chromosome.target_call_chain = f"{normalized_tool} -> {normalized_vuln}{suffix}"
            hint_obj = {
                "tool_name": static_hint.get("tool_name"),
                "vulnerability_type": static_hint.get("vulnerability_type"),
                "line": static_hint.get("line"),
                "function_hint": static_hint.get("function_hint"),
                "sink_family": static_hint.get("sink_family"),
                "risk_score": static_hint.get("risk_score"),
                "prompt_focuses": static_hint.get("prompt_focuses", []),
            }
            extra_hint = (
                "\n\nStatic structured context (use it to design a higher-quality seed prompt):\n"
                f"{hint_obj}\n"
            )
            self.logger.debug("Static hint for target=%s: %s", target_call_chain, hint_obj)
        return chromosome, extra_hint

    def _fallback_prompt_for_style(self, target_call_chain: str, style: Dict[str, str]) -> str:
        label = str(style.get("label") or "Task")
        if label == "Verification Request":
            return f"Check the MCP tool related to {target_call_chain} with one concrete input and report the result."
        if label == "Diagnostic Pretext":
            return f"Investigate the issue handled by the MCP tool related to {target_call_chain} using one explicit input value."
        if label == "Workflow Framing":
            return f"Complete the workflow step handled by the MCP tool related to {target_call_chain} with one exact parameter."
        return f"Use the MCP tool related to {target_call_chain} with one explicit input value."

    async def _generate_candidate_for_style(
        self,
        target_call_chain: str,
        static_hint: Optional[Dict[str, Any]],
        style: Dict[str, str],
    ) -> Chromosome:
        chromosome, extra_hint = self._prepare_base_chromosome(target_call_chain, static_hint)
        chromosome.prompt_template_id = str(style.get("id") or "")
        chromosome.prompt_template_label = str(style.get("label") or "")
        chromosome.parent_prompt_template_id = ""

        if not self.llm_client:
            chromosome.agent_input_prompt = self._fallback_prompt_for_style(target_call_chain, style)
            self.logger.warning(
                "Seed generation fallback without LLM for target=%s template=%s prompt=%s",
                target_call_chain,
                chromosome.prompt_template_id or chromosome.prompt_template_label,
                chromosome.agent_input_prompt,
            )
            return chromosome

        prompt_request = build_init_prompt_with_style(
            chromosome.target_call_chain,
            extra_hint,
            style,
        )
        try:
            raw = await self.llm_client.generate(
                prompt=prompt_request,
                system_prompt=INIT_PROMPT_SYSTEM_PROMPT,
                temperature=0.7,
                max_tokens=800,
            )
        except Exception as e:
            chromosome.agent_input_prompt = self._fallback_prompt_for_style(target_call_chain, style)
            self.logger.exception(
                "Seed generation LLM failed for target=%s template=%s fallback prompt=%s error=%s",
                target_call_chain,
                chromosome.prompt_template_id or chromosome.prompt_template_label,
                chromosome.agent_input_prompt,
                e,
            )
            return chromosome

        raw = (raw or "").strip()
        chromosome.input_prompt = prompt_request
        chromosome.llm_response = raw
        chromosome.agent_input_prompt = (
            parse_init_prompt_from_response(raw)
            or chromosome.agent_input_prompt
            or self._fallback_prompt_for_style(target_call_chain, style)
        )
        self.logger.info(
            "Generated seed for target=%s template=%s function_hint=%s prompt=%s",
            target_call_chain,
            chromosome.prompt_template_id or chromosome.prompt_template_label,
            chromosome.target_function_hint or "n/a",
            chromosome.agent_input_prompt[:240],
        )
        self.logger.debug(
            "Seed generator raw LLM response for target=%s template=%s: %s",
            target_call_chain,
            chromosome.prompt_template_id or chromosome.prompt_template_label,
            raw[:1000],
        )
        return chromosome

    async def generate_candidates(
        self,
        target_call_chain: str,
        static_hint: Optional[Dict[str, Any]] = None,
    ) -> list[Chromosome]:
        self.logger.info("Generating seed candidates for target=%s", target_call_chain)
        styles = get_prompt_template_variants()
        tasks = [
            self._generate_candidate_for_style(
                target_call_chain,
                static_hint,
                style,
            )
            for style in styles
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        candidates: list[Chromosome] = []
        for style, result in zip(styles, results):
            if isinstance(result, Exception):
                fallback = Chromosome(
                    target_call_chain=target_call_chain,
                    agent_input_prompt=self._fallback_prompt_for_style(target_call_chain, style),
                    prompt_template_id=str(style.get("id") or ""),
                    prompt_template_label=str(style.get("label") or ""),
                )
                self.logger.exception(
                    "Seed candidate generation crashed target=%s template=%s error=%s",
                    target_call_chain,
                    fallback.prompt_template_id or fallback.prompt_template_label,
                    result,
                )
                candidates.append(fallback)
                continue
            candidates.append(result)
        return candidates
