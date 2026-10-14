from typing import Optional
from anthropic import AsyncAnthropic
from .base import LLMClient
from .usage import extract_anthropic_usage


class AnthropicClient(LLMClient):
    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: Optional[str] = None,
        *,
        usage_log_path: Optional[str] = None,
        usage_role: str = "",
    ):
        super().__init__(provider="anthropic", model=model, usage_log_path=usage_log_path, usage_role=usage_role)
        self.client = AsyncAnthropic(
            api_key=api_key,
            base_url=base_url
        )
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None,
                      temperature: float = 0.7, max_tokens: int = 2000,
                      json_mode: bool = False) -> str:
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}]
        )
        self._log_usage(extract_anthropic_usage(response))
        return response.content[0].text
    
    async def generate_stream(self, prompt: str, system_prompt: Optional[str] = None,
                             temperature: float = 0.7, max_tokens: int = 2000):
        stream = await self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}],
            stream=True
        )
        
        async for chunk in stream:
            if chunk.type == "content_block_delta":
                yield chunk.delta.text
