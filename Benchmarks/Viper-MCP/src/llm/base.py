from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from .usage import append_usage_log


class LLMClient(ABC):
    def __init__(
        self,
        *,
        provider: str,
        model: str,
        usage_log_path: Optional[str] = None,
        usage_role: str = "",
    ):
        self.provider = provider
        self.model = model
        self.usage_log_path = usage_log_path or ""
        self.usage_role = usage_role or ""

    def _log_usage(self, usage: Dict[str, Any], *, component: str = "") -> None:
        append_usage_log(
            self.usage_log_path,
            {
                "provider": self.provider,
                "model": self.model,
                "role": self.usage_role,
                "component": component or self.usage_role,
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
        )

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: Optional[str] = None, 
                      temperature: float = 0.7, max_tokens: int = 2000,
                      json_mode: bool = False) -> str:
        pass
    
    @abstractmethod
    async def generate_stream(self, prompt: str, system_prompt: Optional[str] = None,
                             temperature: float = 0.7, max_tokens: int = 2000):
        pass
