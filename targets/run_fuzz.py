import os
import logging
import sys
from mcp_fuzzer import MCPDifferentialFuzzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    from mcp_fuzzer.config import FuzzerConfig
    config = FuzzerConfig(
        timeout_limit=10.0,
        unexpected_crashes=(
            "AttributeError",
            "IndexError",
            "TypeError",
            "KeyError",
            "RecursionError",
            "ZeroDivisionError",
            "NameError",
            "UnboundLocalError",
            "SystemExit",
            "BaseExceptionGroup"
        )
    )
    # Configure fuzzer to target divide in mcp_calculator_server.py
    fuzzer = MCPDifferentialFuzzer(
        command=sys.executable,
        args=[
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "mcp-for-beginners", "03-GettingStarted", "samples", "python", "mcp_calculator_server.py")
        ],
        target_tool="divide", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "a": 10.0,
                "b": 2.0
            }
        ]
    )
    
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()