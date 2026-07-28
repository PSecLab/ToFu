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

    # Configure the fuzzer to target 'recall' tool of PMB (Personal Memory Brain)
    pmb_tools_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "pmb",
            "src",
            "pmb",
            "mcp",
            "tools.py"
        )
    )

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=["-m", "pmb.mcp.server"],
        target_tool="recall",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "query": "How to configure PMB memory database?",
                "top_k": 5
            },
            {
                "query": "' OR 1=1 --",
                "top_k": 10
            },
            {
                "query": "../../../etc/passwd",
                "top_k": 1
            }
        ]
    )

    # Run fuzzing session for 1800 seconds (30 minutes)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
