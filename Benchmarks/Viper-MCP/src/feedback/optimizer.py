import logging
import random
from typing import List, Optional

from ..llm.base import LLMClient
from ..fuzz.chromosome import Chromosome


class FeedbackOptimizer:
    def __init__(self, llm_client: Optional[LLMClient] = None, rng: Optional[random.Random] = None):
        self.llm_client = llm_client
        self.rng = rng or random.Random()
        self.seed_pool: List[Chromosome] = []
        self.logger = logging.getLogger("viper_mcp.feedback.optimizer")

    def register_seed(self, chromosome: Chromosome) -> None:
        self.seed_pool.append(chromosome)
        self.logger.info(
            "Registered seed target=%s pool_size=%d success=%s structure=%.2f parameter=%.2f",
            chromosome.target_call_chain,
            len(self.seed_pool),
            chromosome.is_successful,
            chromosome.structure_score,
            chromosome.parameter_score,
        )

    def select_seed(self) -> Optional[Chromosome]:
        if not self.seed_pool:
            self.logger.warning("Seed selection skipped because pool is empty")
            return None
        for chromosome in self.seed_pool:
            chromosome.final_score = (
                chromosome.structure_score
                + chromosome.parameter_score
                - chromosome.select_penalty_score
                - chromosome.callchain_penalty_score
            )
        self.seed_pool.sort(key=lambda item: item.final_score, reverse=True)
        top_k = min(5, len(self.seed_pool))
        candidates = self.seed_pool[:top_k]
        min_score = min(candidate.final_score for candidate in candidates)
        weights = [max(0.1, candidate.final_score - min_score + 1.0) for candidate in candidates]
        selected = self.rng.choices(candidates, weights=weights, k=1)[0]
        self.logger.info(
            "Seed selected target=%s final_score=%.2f top_k=%d pool_size=%d",
            selected.target_call_chain,
            selected.final_score,
            top_k,
            len(self.seed_pool),
        )
        self.logger.debug(
            "Seed selection candidates=%s weights=%s",
            [
                {
                    "target": candidate.target_call_chain,
                    "prompt": candidate.agent_input_prompt[:120],
                    "final_score": round(candidate.final_score, 3),
                }
                for candidate in candidates
            ],
            [round(weight, 3) for weight in weights],
        )
        selected.select_penalty_score += 0.5
        for chromosome in self.seed_pool:
            if chromosome.target_call_chain == selected.target_call_chain:
                chromosome.callchain_penalty_score += 0.5
        return selected.copy()

    async def choose_mutator(self, population: Chromosome) -> str:
        if not self.llm_client:
            self.logger.warning(
                "Mutator choice fallback without LLM target=%s -> structure",
                population.target_call_chain,
            )
            return "structure"
        try:
            raw = await self.llm_client.generate(
                prompt=prompts.SCHEDULING_PROMPT.format(
                    population.structure_score,
                    population.parameter_score,
                    population.structure_score_reason or "",
                    population.parameter_score_reason or "",
                    self._summarize_agent_response(population.response),
                    population.request_packets or "(no request packets)",
                    population.call_stack or "(no call stack)",
                ),
                system_prompt=prompts.SCHEDULING_SYSTEM_PROMPT,
                temperature=0.2,
                max_tokens=200,
            )
        except Exception as e:
            self.logger.exception(
                "Mutator choice failed for target=%s error=%s",
                population.target_call_chain,
                e,
            )
            return "structure"
        raw = (raw or "").strip().upper()
        if "PARAMETER" in raw and "STRUCTURE" not in raw:
            self.logger.info(
                "Mutator selected parameter target=%s structure=%.2f parameter=%.2f",
                population.target_call_chain,
                population.structure_score,
                population.parameter_score,
            )
            self.logger.debug("Mutator raw response target=%s raw=%s", population.target_call_chain, raw)
            return "parameter"
        self.logger.info(
            "Mutator selected structure target=%s structure=%.2f parameter=%.2f",
            population.target_call_chain,
            population.structure_score,
            population.parameter_score,
        )
        self.logger.debug("Mutator raw response target=%s raw=%s", population.target_call_chain, raw)
        return "structure"
