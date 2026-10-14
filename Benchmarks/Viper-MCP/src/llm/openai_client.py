from typing import Optional
from openai import AsyncOpenAI
from .base import LLMClient
from .usage import extract_openai_compatible_usage


class OpenAIClient(LLMClient):
    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: Optional[str] = None,
        *,
        provider: str = "openai",
        usage_log_path: Optional[str] = None,
        usage_role: str = "",
    ):
        super().__init__(provider=provider, model=model, usage_log_path=usage_log_path, usage_role=usage_role)
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url
        )
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None,
                      temperature: float = 0.7, max_tokens: int = 2000,
                      json_mode: bool = False) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {}
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        self._log_usage(extract_openai_compatible_usage(response))
        return response.choices[0].message.content
    
    async def generate_stream(self, prompt: str, system_prompt: Optional[str] = None,
                             temperature: float = 0.7, max_tokens: int = 2000):
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        stream = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True
        )
        
        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content
