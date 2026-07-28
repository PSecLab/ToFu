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
        timeout_limit=30.0,
        unexpected_crashes=(
            "TypeError",
            "RangeError",
            "ReferenceError",
            "SyntaxError",
            "URIError",
            "unhandledRejection",
            "uncaughtException",
            "AssertionError"
        )
    )

    # Target take_screenshot tool for image encoding crashes, path traversal, & invalid downscaling math
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[
            server_path,
            "--no-usage-statistics",
            "--browserUrl=http://127.0.0.1:9222"
        ],
        target_tool="take_screenshot",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {},
            "check_path_traversal": {},
            "check_directory_jailbreak_write": {},
            "check_unhandled_promise_rejection": {}
        },
        predefined_seeds=[
            # Seed 1: Standard viewport screenshot to file
            {
                "format": "png",
                "quality": 80,
                "fullPage": False,
                "filePath": "screenshot_test.png"
            },
            # Seed 2: WebP format with extreme quality parameter
            {
                "format": "webp",
                "quality": 100,
                "fullPage": True,
                "filePath": "full_page.webp"
            },
            # Seed 3: JPEG format with edge-case quality (0)
            {
                "format": "jpeg",
                "quality": 0,
                "fullPage": False,
                "filePath": "zero_quality.jpg"
            },
            # Seed 4: Path traversal attempt via screenshot save path
            {
                "format": "png",
                "fullPage": False,
                "filePath": "../../../../../tmp/escaped_screenshot.png"
            }
        ]
    )

    # Run fuzzing iteration for 10 minutes
    fuzzer.run(time_per_iteration=600)

if __name__ == "__main__":
    main()
