from .base import BaseAgent
from .surrogate_agent import (
    LangChainAgent,
    create_langchain_agent_from_config,
)


def create_agent_from_config(config):
    return create_langchain_agent_from_config(config)


__all__ = [
    "BaseAgent",
    "LangChainAgent",
    "create_langchain_agent_from_config",
    "create_agent_from_config",
]
