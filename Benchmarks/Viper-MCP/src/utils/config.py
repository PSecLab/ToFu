import yaml
import os
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self._config: Dict[str, Any] = {}
        self.load()
    
    def load(self):
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self._config = yaml.safe_load(f)
        
        # Load API keys from environment variables when available.
        self._load_api_keys()
    
    def _load_api_keys(self):
        prompt_key = os.getenv("PROMPT_LLM_API_KEY")
        agent_key = os.getenv("AGENT_LLM_API_KEY")
        hit_judge_key = os.getenv("HIT_JUDGE_LLM_API_KEY")
        
        if prompt_key and "llm" in self._config and "prompt_generator" in self._config["llm"]:
            self._config["llm"]["prompt_generator"]["api_key"] = prompt_key
        
        if agent_key and "llm" in self._config and "agent" in self._config["llm"]:
            self._config["llm"]["agent"]["api_key"] = agent_key

        if hit_judge_key and "llm" in self._config and "hit_judge" in self._config["llm"]:
            self._config["llm"]["hit_judge"]["api_key"] = hit_judge_key
    
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    @property
    def mcp_server(self) -> Dict[str, Any]:
        return self.get("mcp_server", {})
    
    @property
    def prompt_llm(self) -> Dict[str, Any]:
        return self.get("llm.prompt_generator", {})
    
    @property
    def agent_llm(self) -> Dict[str, Any]:
        return self.get("llm.agent", {})

    @property
    def hit_judge_llm(self) -> Dict[str, Any]:
        return self.get("llm.hit_judge", {})
    
    @property
    def codeql(self) -> Dict[str, Any]:
        return self.get("codeql", {})
    
    @property
    def fuzz(self) -> Dict[str, Any]:
        return self.get("fuzz", {})
    
    @property
    def logging(self) -> Dict[str, Any]:
        return self.get("logging", {})
    
    @property
    def output(self) -> Dict[str, Any]:
        return self.get("output", {})
