from dataclasses import dataclass, field
from typing import Set, Dict, Any, Optional

@dataclass
class RunnerResult:
    success: bool
    coverage: Set[str]  # e.g., {"server.py:12", "server.py:14"}
    result: Any = None
    error: Optional[str] = None
    execution_time_ms: float = 0.0
    accessed_files: list = field(default_factory=list)

class BaseRunner:
    def __init__(self, command: str, args: list, target_tool: str):
        self.command = command
        self.args = args
        self.target_tool = target_tool

    def start(self):
        """Starts the target server if necessary."""
        pass

    def stop(self):
        """Stops the target server if necessary."""
        pass

    def execute(self, arguments: dict) -> RunnerResult:
        """Executes the target tool with arguments and returns coverage + status."""
        raise NotImplementedError
