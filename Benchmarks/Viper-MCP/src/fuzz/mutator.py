import asyncio
import logging
from typing import Any, Optional

from ..llm.base import LLMClient
from .chromosome import Chromosome
from .prompts import (
    PARAMETER_MUTATE_SYSTEM_PROMPT,
    STRUCTURE_MUTATE_SYSTEM_PROMPT,
    build_parameter_mutate_prompt,
    build_structure_mutate_prompt,
    get_prompt_template_variants,
    parse_new_prompt_from_response,
)


class MutationScheduler:
    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client
        self.logger = logging.getLogger("viper_mcp.fuzz.mutator")

    async def structure_mutate(self, population: Chromosome) -> Chromosome:
        candidates = await self.structure_mutate_candidates(population)
        return candidates[0] if candidates else population.copy()

    async def parameter_mutate(self, population: Chromosome) -> Chromosome:
        candidates = await self.parameter_mutate_candidates(population)
        return candidates[0] if candidates else population.copy()

    async def structure_mutate_candidates(self, population: Chromosome) -> list[Chromosome]:
        return await self._mutate_candidates(population, mutation_kind="structure")

    async def parameter_mutate_candidates(self, population: Chromosome) -> list[Chromosome]:
        return await self._mutate_candidates(population, mutation_kind="parameter")

    async def _mutate_candidates(self, population: Chromosome, mutation_kind: str) -> list[Chromosome]:
        styles = get_prompt_template_variants()
        tasks = [
            self._mutate_candidate_for_style(population, style, mutation_kind)
            for style in styles
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        candidates: list[Chromosome] = []
        for style, result in zip(styles, results):
            if isinstance(result, Exception):
                fallback = population.copy()
                fallback.prompt_template_id = str(style.get("id") or "")
                fallback.prompt_template_label = str(style.get("label") or "")
                fallback.parent_prompt_template_id = population.prompt_template_id
                self.logger.exception(
                    "%s mutation crashed for target=%s template=%s error=%s",
                    mutation_kind.capitalize(),
                    population.target_call_chain,
                    fallback.prompt_template_id or fallback.prompt_template_label,
                    result,
                )
                candidates.append(fallback)
                continue
            candidates.append(result)
        return candidates

    async def _mutate_candidate_for_style(
        self,
        population: Chromosome,
        style: dict[str, str],
        mutation_kind: str,
    ) -> Chromosome:
        new_chromosome = population.copy()
        new_chromosome.prompt_template_id = str(style.get("id") or "")
        new_chromosome.prompt_template_label = str(style.get("label") or "")
        new_chromosome.parent_prompt_template_id = population.prompt_template_id

        if not self.llm_client:
            self.logger.warning(
                "%s mutation fallback without LLM for target=%s template=%s",
                mutation_kind.capitalize(),
                population.target_call_chain,
                new_chromosome.prompt_template_id or new_chromosome.prompt_template_label,
            )
            return new_chromosome

        trace_str = population.call_trace or ", ".join(population.tools_invoked) or "no tools called"
        request_packets = (population.request_packets or "").strip()
        if len(request_packets) > 2000:
            request_packets = request_packets[:2000] + "...(truncated)"
        tool_feedback = self._stringify_tool_feedbacks(population.tool_feedbacks)

        if mutation_kind == "parameter":
            prompt_input = build_parameter_mutate_prompt(
                population.target_call_chain,
                population.target_function_hint,
                trace_str,
                request_packets or "none",
                tool_feedback,
                population.agent_input_prompt,
                population.structure_score,
                population.parameter_score,
                style,
            )
            system_prompt = PARAMETER_MUTATE_SYSTEM_PROMPT
            temperature = 0.4
            max_tokens = 700
        else:
            prompt_input = build_structure_mutate_prompt(
                population.target_call_chain,
                trace_str,
                population.agent_input_prompt,
                f"Structure score: {population.structure_score}. {population.structure_score_reason or ''}",
                f"Parameter score: {population.parameter_score}. {population.parameter_score_reason or ''}",
                style,
            )
            system_prompt = STRUCTURE_MUTATE_SYSTEM_PROMPT
            temperature = 0.6
            max_tokens = 1000

        self.logger.info(
            "%s mutation start target=%s template=%s structure=%.2f parameter=%.2f trace=%s",
            mutation_kind.capitalize(),
            population.target_call_chain,
            new_chromosome.prompt_template_id or new_chromosome.prompt_template_label,
            population.structure_score,
            population.parameter_score,
            trace_str[:200],
        )
        try:
            raw = await self.llm_client.generate(
                prompt=prompt_input,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as e:
            self.logger.exception(
                "%s mutation failed for target=%s template=%s error=%s",
                mutation_kind.capitalize(),
                population.target_call_chain,
                new_chromosome.prompt_template_id or new_chromosome.prompt_template_label,
                e,
            )
            return new_chromosome

        raw = (raw or "").strip()
        new_prompt = parse_new_prompt_from_response(raw)
        if new_prompt:
            new_chromosome.agent_input_prompt = new_prompt
            self.logger.info(
                "%s mutation updated prompt for target=%s template=%s old=%s new=%s",
                mutation_kind.capitalize(),
                population.target_call_chain,
                new_chromosome.prompt_template_id or new_chromosome.prompt_template_label,
                population.agent_input_prompt[:200],
                new_chromosome.agent_input_prompt[:200],
            )
        else:
            self.logger.warning(
                "%s mutation returned no new prompt for target=%s template=%s",
                mutation_kind.capitalize(),
                population.target_call_chain,
                new_chromosome.prompt_template_id or new_chromosome.prompt_template_label,
            )
        new_chromosome.llm_response = raw
        new_chromosome.input_prompt = prompt_input
        self.logger.debug(
            "%s mutation raw LLM response for target=%s template=%s: %s",
            mutation_kind.capitalize(),
            population.target_call_chain,
            new_chromosome.prompt_template_id or new_chromosome.prompt_template_label,
            raw[:1200],
        )
        return new_chromosome

    def _stringify_tool_feedbacks(self, feedbacks: Any) -> str:
        if not isinstance(feedbacks, list) or not feedbacks:
            return "none"
        parts = []
        for item in feedbacks[:4]:
            parts.append(str(item))
        text = "\n".join(parts)
        if len(text) > 1500:
            return text[:1500] + "...(truncated)"
        return text
