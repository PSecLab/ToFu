from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Chromosome:
    input_prompt: str = ""
    llm_response: str = ""
    target_call_chain: str = ""
    target_tool_name: str = ""
    target_vulnerability_type: str = ""
    target_function_hint: str = ""
    prompt_template_id: str = ""
    prompt_template_label: str = ""
    parent_prompt_template_id: str = ""
    agent_input_prompt: str = ""
    call_trace: str = ""
    tools_invoked: List[str] = field(default_factory=list)
    interaction_tools_invoked: List[str] = field(default_factory=list)
    oracle_hits: List[Dict[str, Any]] = field(default_factory=list)
    is_successful: bool = False
    structure_score: float = 0.0
    structure_score_reason: str = ""
    parameter_score: float = 0.0
    parameter_score_reason: str = ""
    select_penalty_score: float = 0.0
    callchain_penalty_score: float = 0.0
    final_score: float = 0.0
    is_anomaly: bool = False
    anomaly_details: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    oracle_content: str = ""
    interaction_content: str = ""
    request_packets: str = ""
    tool_feedbacks: List[Dict[str, Any]] = field(default_factory=list)
    call_stack: str = ""
    hit_judge_details: Dict[str, Any] = field(default_factory=dict)

    def copy(self) -> "Chromosome":
        from copy import deepcopy

        return deepcopy(self)
