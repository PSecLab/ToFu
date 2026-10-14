"""Base agent interface for MCP fuzzing"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseAgent(ABC):
    """Base interface for MCP fuzzing agents"""
    
    @abstractmethod
    async def initialize(self):
        """Initialize the agent"""
        pass
    
    @abstractmethod
    async def execute_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Execute a prompt and return response
        
        Returns:
            Dict with keys:
                - success: bool
                - response: dict with content
                - error: str (if success=False)
                - refusal_info: dict (optional)
        """
        pass
    
    @abstractmethod
    async def close(self):
        """Close connections and cleanup"""
        pass
    
    @property
    @abstractmethod
    def tools_cache(self) -> List[Dict[str, Any]]:
        """Get cached tool list for compatibility"""
        pass
