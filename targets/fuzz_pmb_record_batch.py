import os
import sys

# Add workspace root to the Python import path to resolve mcp_fuzzer
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import logging
from mcp_fuzzer import MCPDifferentialFuzzer
from mcp_fuzzer.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    os.environ["PMB_TOOL_PROFILE"] = "full"
    # Use venv python executable
    python_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            ".venv",
            "bin",
            "python"
        )
    )

    pmb_server_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "pmb",
            "src",
            "pmb",
            "mcp",
            "server.py"
        )
    )

    config = FuzzerConfig(
        timeout_limit=20.0,
        unexpected_crashes=(
            "TypeError",
            "ValueError",
            "KeyError",
            "IndexError",
            "AttributeError",
            "UnboundLocalError",
            "AssertionError"
        )
    )

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[pmb_server_path],
        target_tool="record_batch",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "items": [
                    {"type": "fact", "content": "User works on PMB project", "importance": 0.8},
                    {"type": "lesson", "content": "Always run pytest before committing", "project": "PMB"},
                    {"type": "goal", "title": "Complete fuzzing framework", "status": "in_progress"}
                ]
            },
            {
                "items": [
                    {"type": "fact_tree", "main": "Database migration on May 2026", "subfacts": ["Upgraded SQLite", "Added indices"], "importance": 0.9},
                    {"type": "activity", "content": "Fuzzed PMB server", "kind": "completed", "actor": "agent"}
                ]
            },
            {
                "items": [
                    {"type": "fact", "content": "' OR '1'='1", "importance": -1.0},
                    {"type": "invalid_type", "content": "../../../etc/passwd"}
                ]
            }
        ]
    )

    # Run fuzzing session for 1800 seconds (30 minutes)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
