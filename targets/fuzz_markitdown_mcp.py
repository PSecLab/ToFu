import os
import sys
import logging

# Add workspace root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.fuzzer import MCPDifferentialFuzzer
from src.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    python_path = sys.executable

    # Add markitdown-mcp to python path environment so python -m markitdown_mcp can be resolved
    mcp_pkg_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "markitdown",
            "packages",
            "markitdown-mcp",
            "src"
        )
    )

    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{mcp_pkg_dir}:{existing_pythonpath}" if existing_pythonpath else mcp_pkg_dir

    sample_pdf_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_samples", "sample.pdf")
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party")
    )

    config = FuzzerConfig(
        timeout_limit=15.0,
        allowed_workspace_dir=sandbox_dir,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    predefined_seeds = [
        {"uri": f"file://{sample_pdf_path}"},
        {"uri": "data:text/html,<html><body><h1>Title</h1><p>Test</p></body></html>"},
        {"uri": "file:///etc/passwd"}
    ]

    logger.info("Initializing MarkItDown MCP Fuzzer targeting 'convert_to_markdown' via MCP server for 5 minutes...")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=["-m", "markitdown_mcp"],
        target_tool="convert_to_markdown",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={"uri": sample_pdf_path},
        config=config,
        override_rules={
            "check_file_access": {},
            "check_introspection_path_traversal": {},
            "check_introspection_command_injection": {},
            "check_introspection_ssrf": {},
            "check_untrusted_deserialization": {},
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {},
            "check_unhandled_promise_rejection": {}
        },
        predefined_seeds=predefined_seeds
    )

    # Set PYTHONPATH in the inspector process
    fuzzer.inspector.env = env

    # Run for 15 minutes (900 seconds)
    fuzzer.run(time_per_iteration=900)

if __name__ == "__main__":
    main()
