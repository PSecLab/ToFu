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

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[pmb_server_path],
        target_tool="overview",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "topic": "memory database configuration",
                "max_events": 20
            },
            {
                "topic": "' OR 1=1 --",
                "max_events": 100
            },
            {
                "topic": "../../../etc/passwd",
                "max_events": -1
            }
        ]
    )

    # Run fuzzing session for 300 seconds (5 minutes)
    fuzzer.run(time_per_iteration=300)

if __name__ == "__main__":
    main()
