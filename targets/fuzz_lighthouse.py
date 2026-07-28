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
    # Path to the compiled chrome-devtools-mcp server entrypoint
    server_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "chrome-devtools-mcp",
            "build",
            "src",
            "bin",
            "chrome-devtools-mcp.js"
        )
    )

    config = FuzzerConfig(
        timeout_limit=30.0,  # Lighthouse runs take some time (usually ~10-25 seconds)
        unexpected_crashes=(
            "TypeError",
            "RangeError",
            "ReferenceError",
            "SyntaxError",
            "URIError",
            "unhandledRejection",
            "uncaughtException"
        )
    )

    # Configure the fuzzer to target fuzz_lighthouse_html
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[
            server_path,
            "--no-usage-statistics",
            "--executablePath=/snap/bin/chromium",
            "--isolated"
        ],
        target_tool="fuzz_lighthouse_html",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "htmlContent": "<html><head><title>My Test Page</title></head><body><h1>Welcome</h1><p>This is a test paragraph.</p><button id='btn'>Click</button></body></html>"
            }
        ]
    )

    # Run the fuzzing iteration (Lighthouse is slow, so we set a reasonable execution limit)
    fuzzer.run(time_per_iteration=90)

if __name__ == "__main__":
    main()
