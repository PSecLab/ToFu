from .base import LLMClient
from .openai_client import OpenAIClient
from .anthropic_client import AnthropicClient


def create_llm_client(config: dict, role: str = "") -> LLMClient:
    provider = config.get("provider", "openai").lower()
    model = config.get("model", "")
    api_key = config.get("api_key", "")
    base_url = config.get("base_url")
    usage_log_path = config.get("usage_log_path")
    
    if not api_key:
        raise ValueError(f"API key not found for {provider}")
    
    if provider == "openai":
        return OpenAIClient(
            model,
            api_key,
            base_url,
            provider="openai",
            usage_log_path=usage_log_path,
            usage_role=role,
        )
    elif provider == "anthropic":
        return AnthropicClient(
            model,
            api_key,
            base_url,
            usage_log_path=usage_log_path,
            usage_role=role,
        )
    elif provider == "deepseek":
        # DeepSeek uses OpenAI-compatible API
        base_url = base_url or "https://api.deepseek.com/"
        model = model or "deepseek-chat"
        return OpenAIClient(
            model,
            api_key,
            base_url,
            provider="deepseek",
            usage_log_path=usage_log_path,
            usage_role=role,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
