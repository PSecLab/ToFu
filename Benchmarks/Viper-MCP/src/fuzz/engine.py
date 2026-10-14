import asyncio
import json
import os
import random
import re
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from ..utils.config import Config
from ..utils.logger import setup_logger
from ..llm import create_llm_client
from ..codeql.anchor_pipeline import ensure_anchored_report
from ..codeql.parser import CodeQLParser
from ..feedback.hit_judge import TargetHitJudge
from ..feedback.validator import ResponseAnalyzer
from ..static_analysis.context_builder import StaticContextBuilder
from ..agent import create_agent_from_config
from .strategy import FuzzStrategy
from .chromosome import Chromosome
from .interaction_monitor import InteractionMonitor
from .runtime_monitor import RuntimeMonitor


COMMAND_INJECTION_PATTERN = re.compile(r"(;|&&|\|\||\$\(|`|\$\{|>\s*/|<\s*/|\n)")
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_INTERNAL_ORIGIN_SUFFIXES = (
    "script/mcp_stdio_guard.py",
    "script/python_entrypoint.py",
    "instrumentation/python/mcp_fuzzer_hook.py",
    "instrumentation/javascript/node_hook.js",
)
_TRIGGER_STAGE_ORDER = {
    "not_triggered": 1,
    "intent_only": 2,
    "sink_reached": 3,
    "triggered_but_blocked": 4,
    "effect_observed": 5,
}
_RESULT_PERSIST_MIN_STAGE = "sink_reached"


def _get_repo_name(repo_path: str) -> str:
    p = Path(repo_path)
    name = p.name if p.is_dir() else p.stem
    return re.sub(r"[^\w\-_.]", "_", name)


def _read_oracle_content(oracle_path: Path) -> str:
    if not oracle_path.exists():
        return ""
    try:
        text = oracle_path.read_text(encoding="utf-8", errors="replace").strip()
        return text or ""
    except Exception:
        return ""


def _clear_oracle(oracle_path: Path) -> None:
    try:
        oracle_path.parent.mkdir(parents=True, exist_ok=True)
        oracle_path.write_text("", encoding="utf-8")
    except Exception:
        pass


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


def _parse_oracle_for_trace(oracle_content: str) -> Tuple[List[str], List[Dict[str, Any]], Dict[str, bool]]:
    """
    Parse the oracle output for one round.

    Expected JSON format:
      {call_chain: [hit1, hit2, ...]}

    Returns:
      (tools_invoked, oracle_hits, is_hit_for_chain)
    """
    tools_invoked: List[str] = []
    oracle_hits: List[Dict[str, Any]] = []
    is_hit_for_chain: Dict[str, bool] = {}
    if not oracle_content.strip():
        return tools_invoked, oracle_hits, is_hit_for_chain
    try:
        data = json.loads(oracle_content)
        if not isinstance(data, dict):
            raise TypeError("oracle is not dict json")
        for chain_key, hits in data.items():
            if not isinstance(hits, list):
                continue
            is_hit_for_chain[chain_key] = len(hits) > 0
            if "->" in chain_key:
                tool = chain_key.split("->")[0].strip()
                if tool and tool not in tools_invoked:
                    tools_invoked.append(tool)
            for h in hits[:3]:  
                if isinstance(h, dict):
                    oracle_hits.append({
                        "tool": chain_key.split("->")[0].strip() if "->" in chain_key else "",
                        "sink": h.get("sink", ""),
                        "line": h.get("line"),
                        "file_path": h.get("file_path", ""),
                    })
    except (json.JSONDecodeError, TypeError):
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
            command_text = ""
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

            for s in stack:
                if not isinstance(s, str):
                    continue
                if not tool:
                    m_fn = re.search(r"\bat\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|$)", s)
                    if m_fn:
                        fn = m_fn.group(1)
                        m_prefix = re.match(r"[a-z]+", fn)
                        if m_prefix:
                            tool = m_prefix.group(0)
                if not file_path:
                    m_loc = re.search(r"\((.*?):(\d+):(\d+)\)$", s)
                    if not m_loc:
                        m_loc = re.search(r"\bat\s+(.*?):(\d+):(\d+)$", s)
                    if m_loc:
                        file_path = m_loc.group(1)
                        try:
                            line_no = int(m_loc.group(2))
                        except Exception:
                            line_no = None
                if not tool and not file_path:
                    m_file = re.search(r"/src/([a-z0-9_-]+)\.(?:t|j)s", s, re.IGNORECASE)
                    if m_file:
                        tool = m_file.group(1).lower()
            if origin_file:
                file_path = origin_file
            if origin_line is not None:
                line_no = origin_line
            if not tool and origin_function:
                m_prefix = re.match(r"[a-z]+", origin_function)
                if m_prefix:
                    tool = m_prefix.group(0)

            if tool and tool not in tools_invoked:
                tools_invoked.append(tool)
            if sink:
                oracle_hits.append({
                    "tool": tool,
                    "sink": sink,
                    "line": line_no,
                    "file_path": file_path,
                    "function": business_function,
                    "command_text": command_text,
                    "has_injection_signal": _has_injection_signal(command_text),
                })
    return tools_invoked, oracle_hits, is_hit_for_chain


def _parse_target_call_chain(target_call_chain: str) -> Tuple[str, str, Optional[int]]:
    target_tool = ""
    target_part = ""
    target_line: Optional[int] = None
    if "->" in target_call_chain:
        target_tool = target_call_chain.split("->", 1)[0].strip().lower()
        target_part = target_call_chain.split("->", 1)[1].strip().lower()
    m = re.search(r"@(\d+)", target_part)
    if m:
        try:
            target_line = int(m.group(1))
        except Exception:
            target_line = None
    return target_tool, target_part, target_line


def _merge_ordered_strings(*groups: List[str]) -> List[str]:
    merged: List[str] = []
    for group in groups:
        for item in group:
            text = str(item or "").strip()
            if text and text not in merged:
                merged.append(text)
    return merged


def _dedupe_seed_chains(target_chains: List[str], max_per_group: int = 4) -> List[str]:
    # Keep a few representative chains per (tool + vuln), instead of collapsing to a single line.
    grouped: Dict[str, List[Tuple[int, str]]] = {}
    passthrough: List[str] = []
    for chain in target_chains:
        tool, part, line = _parse_target_call_chain(chain)
        part_no_line = re.sub(r"@\d+$", "", part).strip()
        if not tool or not part_no_line:
            passthrough.append(chain)
            continue
        key = f"{tool}->{part_no_line}"
        if key not in grouped:
            grouped[key] = []
        grouped[key].append((line if line is not None else 10**9, chain))

    out: List[str] = []
    for key in sorted(grouped.keys()):
        entries = sorted(grouped[key], key=lambda x: x[0])
        if len(entries) <= max_per_group:
            out.extend([c for _, c in entries])
            continue
        # pick spread-out representatives across line numbers
        idxs = {0, len(entries) - 1}
        step = max(1, (len(entries) - 1) // (max_per_group - 1))
        i = 0
        while len(idxs) < max_per_group and i < len(entries):
            idxs.add(min(i, len(entries) - 1))
            i += step
        out.extend([entries[i][1] for i in sorted(idxs)][:max_per_group])
    out.extend(passthrough)
    return out


class FuzzEngine:
    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logger(config.logging)
        self.experiment_cfg = config.get("experiment", {}) or {}
        self.ablation_cfg = self.experiment_cfg.get("ablation", {}) or {}
        self.template_selection_mode = str(self.ablation_cfg.get("template_selection") or "score").strip().lower()
        self.disable_anchor = bool(self.ablation_cfg.get("disable_anchor", False))
        self.stop_on_trigger_stage = str(self.ablation_cfg.get("stop_on_trigger_stage") or "").strip()
        self.seed_value = self._resolve_seed_value()
        self.rng = random.Random(self.seed_value) if self.seed_value is not None else random.Random()

        report_dir = Path(config.codeql.get("report_path", "./output"))
        repo_path = config.mcp_server.get("repo_path", "")
        if repo_path:
            repo_name = _get_repo_name(repo_path)
            report_file = report_dir / repo_name / "report.json"
            self.repo_name = repo_name
        else:
            report_file = report_dir / "report.json"
            self.repo_name = ""

        if config.codeql.get("enabled", True) and not self.disable_anchor:
            try:
                anchored_report = ensure_anchored_report(
                    codeql_cfg=config.codeql,
                    mcp_cfg=config.mcp_server,
                    force=False,
                    log=self.logger,
                )
                if anchored_report:
                    report_file = anchored_report
            except Exception as e:
                self.logger.warning("Automatic anchor enrichment before fuzzing failed: %s", e)

        self.codeql_parser: Optional[CodeQLParser] = None
        if config.codeql.get("enabled", True) and report_file.exists():
            self.codeql_parser = CodeQLParser(str(report_file))
            if not self.codeql_parser.load():
                self.logger.warning("CodeQL report not found, continuing without it")

        prompt_llm = create_llm_client(config.prompt_llm, role="prompt_generator")
        self.agent = create_agent_from_config(config)
        hit_judge_llm = prompt_llm
        hit_judge_cfg = config.hit_judge_llm
        if hit_judge_cfg:
            try:
                hit_judge_llm = create_llm_client(hit_judge_cfg, role="hit_judge")
            except Exception as e:
                self.logger.warning("Failed to initialize dedicated hit judge LLM, fallback to prompt LLM: %s", e)

        # Initialize the fuzzing strategy with the static report and LLM backend.
        self.strategy = FuzzStrategy(self.codeql_parser, prompt_llm, rng=self.rng)
        self.analyzer = ResponseAnalyzer()
        self.hit_judge = TargetHitJudge(hit_judge_llm)
        self.static_context_builder = StaticContextBuilder(prompt_llm)
        self.static_context: Dict[str, Any] = {"entries": [], "chain_map": {}, "summary": {}}

        self.fuzz_config = config.fuzz
        self.output_config = config.output
        self.oracle_path = self._resolve_oracle_path()
        self.runtime_monitor = RuntimeMonitor(self.oracle_path)
        self.interaction_monitor = InteractionMonitor(self._resolve_interaction_log_path())
        self.sarif_content: Optional[str] = self._load_sarif_content()

    def _resolve_seed_value(self) -> Optional[int]:
        raw = self.experiment_cfg.get("seed", self.config.get("fuzz.seed", None))
        if raw in (None, "", "none", "null"):
            return None
        try:
            return int(raw)
        except Exception:
            return None

    def _resolve_oracle_path(self) -> Path:
        env_path = os.environ.get("MCP_FUZZER_ORACLE_LOG")
        if env_path:
            return Path(env_path)
        p = self.output_config.get("oracle_path") or self.fuzz_config.get("oracle_path")
        if p:
            return Path(p)
        root = Path(__file__).resolve().parent.parent.parent
        return root / "results" / "oracle.json"

    def _load_sarif_content(self) -> Optional[str]:
        report_dir = Path(self.config.codeql.get("report_path", "./output"))
        if not self.repo_name:
            return None
        sarif_path = report_dir / self.repo_name / "results.sarif"
        if not sarif_path.exists():
            return None
        try:
            return sarif_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    def _resolve_interaction_log_path(self) -> Path:
        env_path = os.environ.get("MCP_FUZZER_INTERACTION_LOG")
        if env_path:
            return Path(env_path)
        configured = self.config.mcp_server.get("interaction_log_path")
        if configured:
            path = Path(configured)
            if path.is_absolute():
                return path
            root = Path(__file__).resolve().parent.parent.parent
            return (root / path).resolve()
        root = Path(__file__).resolve().parent.parent.parent
        return root / "results" / "mcp_interactions.jsonl"

    async def _attack(self, chromosome: Chromosome) -> Chromosome:
        """
        Execute one attack round: clear runtime traces, send the prompt,
        collect oracle evidence, score structure/parameter progress, and
        write all observations back into the chromosome.
        """
        self.runtime_monitor.clear()
        self.interaction_monitor.clear()
        prompt = (chromosome.agent_input_prompt or "").strip()
        if not prompt:
            return chromosome
        response = await self.agent.execute_prompt(prompt)
        runtime_info = self.runtime_monitor.collect()
        interaction_info = self.interaction_monitor.collect()
        oracle_content = runtime_info.get("oracle_content", "")
        interaction_tools = interaction_info.get("requested_tools", [])
        tools_invoked = _merge_ordered_strings(
            runtime_info.get("tools_invoked", []),
            interaction_tools,
        )
        oracle_hits = runtime_info.get("oracle_hits", [])
        is_hit_for_chain = runtime_info.get("is_hit_for_chain", {})

        trace_parts = [
            f"{h.get('tool') or 'unknown'}@{h.get('line') or '?'}:{h.get('sink')}"
            for h in oracle_hits[:8]
        ]
        interaction_trace_parts = [f"{tool}:mcp_request" for tool in interaction_tools[:8]]
        merged_trace_parts = _merge_ordered_strings(trace_parts, interaction_trace_parts)
        chromosome.call_trace = (
            ", ".join(merged_trace_parts)
            if merged_trace_parts
            else ", ".join(interaction_trace_parts)
            if interaction_trace_parts
            else ", ".join(tools_invoked)
            if tools_invoked
            else "no tools called"
        )
        chromosome.tools_invoked = tools_invoked
        chromosome.interaction_tools_invoked = interaction_tools
        chromosome.oracle_hits = oracle_hits
        chromosome.response = response
        chromosome.oracle_content = oracle_content
        chromosome.interaction_content = interaction_info.get("interaction_content", "")
        chromosome.request_packets = interaction_info.get("request_packets", "")
        chromosome.tool_feedbacks = interaction_info.get("tool_feedbacks", [])
        chromosome.call_stack = runtime_info.get("call_stack_text", "")
        chromosome.hit_judge_details = await self.hit_judge.judge(
            target_call_chain=chromosome.target_call_chain,
            target_function_hint=chromosome.target_function_hint,
            prompt=prompt,
            call_trace=chromosome.call_trace,
            tools_invoked=tools_invoked,
            oracle_hits=oracle_hits,
            is_hit_for_chain=is_hit_for_chain,
            oracle_content=oracle_content,
            response=response,
        )
        chromosome.is_successful = bool(chromosome.hit_judge_details.get("is_hit", False))

        (
            structure_score,
            structure_reason,
            parameter_score,
            parameter_reason,
        ) = await self.strategy.score_round(
            chromosome.target_call_chain,
            chromosome.response,
            tools_invoked,
            chromosome.request_packets,
            chromosome.call_trace,
            oracle_hits,
            target_tool_name=chromosome.target_tool_name,
            target_vulnerability_type=chromosome.target_vulnerability_type,
        )
        chromosome.structure_score = structure_score
        chromosome.structure_score_reason = structure_reason
        chromosome.parameter_score = parameter_score
        chromosome.parameter_score_reason = parameter_reason

        analysis = self.analyzer.analyze(response, prompt)
        chromosome.is_anomaly = analysis.get("is_anomaly", False)
        chromosome.anomaly_details = analysis
        self.strategy.record_result(chromosome.is_anomaly, {
            "prompt": prompt,
            "response": response,
            "analysis": analysis,
        })
        return chromosome

    def _template_selection_score(self, chromosome: Chromosome) -> float:
        return float(chromosome.structure_score or 0.0) + float(chromosome.parameter_score or 0.0)

    def _pick_best_template_candidate(self, candidates: List[Chromosome]) -> Optional[Chromosome]:
        if not candidates:
            return None
        if self.template_selection_mode == "random":
            return self.rng.choice(candidates)
        return max(
            candidates,
            key=lambda item: (
                self._template_selection_score(item),
                float(item.structure_score or 0.0),
                float(item.parameter_score or 0.0),
                1 if item.is_successful else 0,
            ),
        )

    def _append_template_round(
        self,
        output_dir: Path,
        phase: str,
        iteration: int,
        target_call_chain: str,
        parent: Optional[Chromosome],
        candidates: List[Chromosome],
        best: Optional[Chromosome],
    ) -> None:
        path = output_dir / "template_rounds.jsonl"
        record = {
            "phase": phase,
            "iteration": iteration,
            "target_call_chain": target_call_chain,
            "parent_template_id": parent.prompt_template_id if parent else "",
            "parent_template_label": parent.prompt_template_label if parent else "",
            "parent_prompt": (parent.agent_input_prompt if parent else "")[:500],
            "best_template_id": best.prompt_template_id if best else "",
            "best_template_label": best.prompt_template_label if best else "",
            "best_selection_score": self._template_selection_score(best) if best else 0.0,
            "candidates": [
                {
                    "template_id": candidate.prompt_template_id,
                    "template_label": candidate.prompt_template_label,
                    "structure_score": candidate.structure_score,
                    "parameter_score": candidate.parameter_score,
                    "selection_score": self._template_selection_score(candidate),
                    "is_successful": candidate.is_successful,
                    "is_anomaly": candidate.is_anomaly,
                    "prompt": candidate.agent_input_prompt,
                }
                for candidate in candidates
            ],
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def _stage_rank(self, stage: str) -> int:
        return _TRIGGER_STAGE_ORDER.get(str(stage or "").strip(), 0)

    def _meets_discovery_threshold(self, chromosome: Chromosome) -> bool:
        threshold = str(self.stop_on_trigger_stage or "").strip()
        if not threshold:
            return bool(chromosome.is_successful)
        current_stage = str((chromosome.hit_judge_details or {}).get("trigger_stage") or "").strip()
        return self._stage_rank(current_stage) >= self._stage_rank(threshold)

    def _meets_result_persist_threshold(self, chromosome: Chromosome) -> bool:
        current_stage = str((chromosome.hit_judge_details or {}).get("trigger_stage") or "").strip()
        return self._stage_rank(current_stage) >= self._stage_rank(_RESULT_PERSIST_MIN_STAGE)

    async def _persist_candidate_outcomes(
        self,
        output_dir: Path,
        iteration: int,
        outer_round: int,
        phase: str,
        candidates: List[Chromosome],
        triggered: List[Dict[str, Any]],
    ) -> bool:
        discovered_any = False
        for idx, candidate in enumerate(candidates):
            discovery_met = self._meets_discovery_threshold(candidate)
            persist_stage_met = self._meets_result_persist_threshold(candidate)
            if discovery_met:
                discovered_any = True
                triggered.append({
                    "outer_round": outer_round,
                    "phase": phase,
                    "candidate_index": idx,
                    "target_call_chain": candidate.target_call_chain,
                    "prompt": candidate.agent_input_prompt,
                    "prompt_template_id": candidate.prompt_template_id,
                    "prompt_template_label": candidate.prompt_template_label,
                    "structure_score": candidate.structure_score,
                    "parameter_score": candidate.parameter_score,
                    "hit_judge": candidate.hit_judge_details,
                })
                self.logger.warning(
                    "Discovery threshold met via template=%s target=%s stage=%s outer_round=%d",
                    candidate.prompt_template_id or candidate.prompt_template_label,
                    candidate.target_call_chain,
                    (candidate.hit_judge_details or {}).get("trigger_stage", ""),
                    outer_round,
                )

            # Keep low-stage candidates available for in-memory scoring/history,
            # but only persist standalone result_*.json artifacts for
            # sink_reached / triggered_but_blocked / effect_observed candidates.
            if not persist_stage_met:
                continue

            should_save = False
            if self.output_config.get("save_exceptions_only", True):
                should_save = persist_stage_met
            elif self.output_config.get("save_all", False):
                should_save = persist_stage_met

            if not should_save:
                continue

            analysis_payload = {
                **candidate.anomaly_details,
                "is_successful": candidate.is_successful,
                "target_call_chain": candidate.target_call_chain,
                "oracle_hits": candidate.oracle_hits,
                "hit_judge": candidate.hit_judge_details,
                "prompt_template_id": candidate.prompt_template_id,
                "prompt_template_label": candidate.prompt_template_label,
                "structure_score": candidate.structure_score,
                "parameter_score": candidate.parameter_score,
                "discovery_threshold_met": discovery_met,
                "result_persist_threshold_met": persist_stage_met,
                "outer_round": outer_round,
                "phase": phase,
                "candidate_index": idx,
            }
            await self._save_result(
                output_dir,
                iteration * 10 + idx,
                outer_round,
                phase,
                idx,
                candidate.agent_input_prompt or "",
                candidate.response or {"success": candidate.is_successful, "response": {}},
                analysis_payload,
            )
        return discovered_any

    async def run(self) -> bool:
        return await self._run_guided_fuzz()

    async def _run_guided_fuzz(self) -> bool:
        """Main loop: target chains -> seed generation -> seed pool -> scheduling -> mutate -> attack."""
        self.logger.info("Starting Viper-MCP (target call chains + structure/parameter mutators)")

        try:
            await self.agent.initialize()
            self.logger.info("Agent initialized successfully")
        except Exception as e:
            self.logger.error("Failed to initialize agent: %s", e)
            return False

        base_output = Path(self.output_config.get("directory", "./results/fuzz_results/"))
        repo_path = self.config.mcp_server.get("repo_path", "")
        output_dir = base_output / _get_repo_name(repo_path) if repo_path else base_output
        output_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info("Fuzz output directory: %s", output_dir)
        self.logger.info("Oracle path: %s", self.oracle_path.resolve())
        if self.disable_anchor:
            self.logger.info("Ablation active: anchor enrichment disabled")
        if self.template_selection_mode == "random":
            if self.seed_value is None:
                self.logger.info("Ablation active: template selection is random (no fixed seed)")
            else:
                self.logger.info("Ablation active: template selection is random (seed=%d)", self.seed_value)
        if self.stop_on_trigger_stage:
            self.logger.info("Early-stop threshold: trigger_stage >= %s", self.stop_on_trigger_stage)

        rounds = max(1, int(self.fuzz_config.get("rounds", 1000)))
        interval = max(0, self.fuzz_config.get("interval", 1.0))
        log_excerpt = 500

        target_chains = self.strategy.get_target_call_chains()
        if not target_chains:
            self.logger.warning("No target call chains from CodeQL; using single generic target.")
            target_chains = ["mcp_tool -> general"]

        deduped_chains = _dedupe_seed_chains(target_chains)
        if len(deduped_chains) < len(target_chains):
            self.logger.info(
                "Seed chains deduped by tool+vuln: %d -> %d",
                len(target_chains),
                len(deduped_chains),
            )
        tools_info = self.agent.tools_cache if hasattr(self.agent, "tools_cache") else []
        self.static_context = await self.static_context_builder.build(
            sarif_content=self.sarif_content,
            tools_info=tools_info,
            target_chains=deduped_chains,
            report_vulnerabilities=self.codeql_parser.vulnerabilities if self.codeql_parser else [],
        )
        static_context_file = output_dir / "static_context.json"
        try:
            with open(static_context_file, "w", encoding="utf-8") as f:
                json.dump(self.static_context, f, indent=2, ensure_ascii=False)
            self.logger.info(
                "Static context built: %d entries, tools=%s -> %s",
                self.static_context.get("summary", {}).get("total_entries", 0),
                ",".join(self.static_context.get("summary", {}).get("tools", [])),
                static_context_file,
            )
        except Exception as e:
            self.logger.warning("Failed to save static context: %s", e)

        prioritized_chains = [
            e.get("target_call_chain")
            for e in self.static_context.get("entries", [])
            if isinstance(e, dict) and e.get("target_call_chain")
        ]
        # Keep the original fallback order if structured entries are missing.
        ordered_chains = prioritized_chains or deduped_chains
        # Append any chains that were not covered by structured entries.
        seen_chain = set(ordered_chains)
        for c in deduped_chains:
            if c not in seen_chain:
                ordered_chains.append(c)
                seen_chain.add(c)
        triggered: List[Dict[str, Any]] = []

        # Generate at most `rounds` seeds so short experiments do not iterate over every chain.
        seed_chains = ordered_chains[:rounds]
        self.logger.info("Seed generation for %d target chain(s)...", len(seed_chains))
        for seed_index, chain in enumerate(seed_chains):
            try:
                seed_candidates = await self.strategy.get_initial_chromosomes(
                    chain,
                    static_hint=(self.static_context.get("chain_map", {}) or {}).get(chain),
                )
                attacked_candidates: List[Chromosome] = []
                for candidate in seed_candidates:
                    attacked_candidates.append(await self._attack(candidate))
                best_candidate = self._pick_best_template_candidate(attacked_candidates)
                self._append_template_round(
                    output_dir,
                    phase="seed_generation",
                    iteration=seed_index,
                    target_call_chain=chain,
                    parent=None,
                    candidates=attacked_candidates,
                    best=best_candidate,
                )
                hit_stop = await self._persist_candidate_outcomes(
                    output_dir,
                    seed_index,
                    seed_index + 1,
                    "seed_generation",
                    attacked_candidates,
                    triggered,
                )
                if best_candidate is None:
                    continue
                self.strategy.seed_pool.append(best_candidate)
                self.logger.info(
                    "Seed chain=%s | winning template=%s score=%.2f | prompt excerpt: %s | success=%s structure=%.2f parameter=%.2f",
                    chain,
                    best_candidate.prompt_template_id or best_candidate.prompt_template_label,
                    self._template_selection_score(best_candidate),
                    (best_candidate.agent_input_prompt or "")[:log_excerpt],
                    best_candidate.is_successful,
                    best_candidate.structure_score,
                    best_candidate.parameter_score,
                )
                if hit_stop:
                    self.logger.info("Stopping fuzz early after discovery in seed round %d", seed_index + 1)
                    break
            except Exception as e:
                self.logger.error("Seed generation failed for %s: %s", chain, e)

        if not self.strategy.seed_pool:
            self.logger.error("No seeds in pool; aborting.")
            await self.agent.close()
            return False

        for iteration in range(max(0, rounds - len(seed_chains))):  # Seed rounds already consumed part of the budget.
            population = self.strategy.seed_scheduling()
            if population is None:
                break

            self.logger.info(
                "Iter %d | chain=%s | prompt excerpt: %s",
                iteration,
                population.target_call_chain,
                (population.agent_input_prompt or "")[:log_excerpt],
            )

            mutator = await self.strategy.mutator_scheduling(population)
            self.logger.info("Mutator: %s", mutator)
            if mutator == "parameter":
                new_candidates = await self.strategy.parameter_mutate_candidates(population)
            else:
                new_candidates = await self.strategy.structure_mutate_candidates(population)
            attacked_candidates = []
            for candidate in new_candidates:
                attacked_candidates.append(await self._attack(candidate))
            best_candidate = self._pick_best_template_candidate(attacked_candidates)
            self._append_template_round(
                output_dir,
                phase=f"{mutator}_mutation",
                iteration=iteration,
                target_call_chain=population.target_call_chain,
                parent=population,
                candidates=attacked_candidates,
                best=best_candidate,
            )
            hit_stop = await self._persist_candidate_outcomes(
                output_dir,
                iteration + len(seed_chains),
                iteration + len(seed_chains) + 1,
                f"{mutator}_mutation",
                attacked_candidates,
                triggered,
            )
            if best_candidate is not None:
                self.logger.info(
                    "Iter %d | winning template=%s score=%.2f structure=%.2f parameter=%.2f prompt=%s",
                    iteration,
                    best_candidate.prompt_template_id or best_candidate.prompt_template_label,
                    self._template_selection_score(best_candidate),
                    best_candidate.structure_score,
                    best_candidate.parameter_score,
                    (best_candidate.agent_input_prompt or "")[:log_excerpt],
                )
                self.strategy.seed_pool.append(best_candidate)
            if hit_stop:
                self.logger.info(
                    "Stopping fuzz early after discovery in outer round %d",
                    iteration + len(seed_chains) + 1,
                )
                break

            await asyncio.sleep(interval)

        triggered_file = output_dir / "triggered_vulnerability_prompts.json"
        if triggered:
            with open(triggered_file, "w", encoding="utf-8") as f:
                json.dump(triggered, f, indent=2, ensure_ascii=False)
            self.logger.info("Saved %d triggered prompt(s) to %s", len(triggered), triggered_file)
        anomalies_file = output_dir / "anomalies.json"
        self.analyzer.save_anomalies(str(anomalies_file))
        self.logger.info("Fuzzing completed. Anomalies: %d", len(self.analyzer.get_anomalies()))
        await self.agent.close()
        return True

    async def _save_result(
        self,
        output_dir: Path,
        round_num: int,
        outer_round: int,
        phase: str,
        candidate_index: int,
        prompt: str,
        response: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> None:
        result_file = output_dir / f"result_{round_num}.json"
        data = {
            "round": round_num,
            "outer_round": outer_round,
            "phase": phase,
            "candidate_index": candidate_index,
            "prompt": prompt,
            "response": response,
            "analysis": analysis,
        }
        with open(result_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
