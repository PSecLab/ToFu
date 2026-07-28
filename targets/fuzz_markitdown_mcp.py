import os
import sys
import logging
import asyncio

# Add workspace root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from mcp_fuzzer import MCPDifferentialFuzzer
from mcp_fuzzer.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    python_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "python")
    )
    dict_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "dictionaries", "markitdown.dict")
    )
    sample_pdf_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_samples", "sample.pdf")
    )

    config = FuzzerConfig(
        timeout_limit=30.0,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    predefined_seeds = [
        {
            "uri": f"file://{sample_pdf_path}"
        },
        {
            "uri": "data:text/html,<html><body><h1>Title</h1><p>Test</p></body></html>"
        },
        {
            "uri": "file:///etc/passwd"
        }
    ]

    logger.info(f"Initializing MarkItDown MCP Fuzzer targeting 'convert_to_markdown' with dict: {dict_path}")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=["-m", "markitdown_mcp.__main__"],
        target_tool="convert_to_markdown",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={"uri": sample_pdf_path},
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=predefined_seeds
    )

    # Run 30-minute campaign (1800 seconds)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
