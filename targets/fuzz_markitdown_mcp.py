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

    markitdown_core_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "markitdown",
            "packages",
            "markitdown",
            "src"
        )
    )

    server_script = os.path.abspath(
        os.path.join(
            mcp_pkg_dir,
            "markitdown_mcp",
            "__main__.py"
        )
    )

    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH", "")
    new_paths = f"{mcp_pkg_dir}:{markitdown_core_dir}"
    env["PYTHONPATH"] = f"{new_paths}:{existing_pythonpath}" if existing_pythonpath else new_paths

    sys.path.insert(0, mcp_pkg_dir)
    sys.path.insert(0, markitdown_core_dir)

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

    logger.info("Initializing MarkItDown MCP Fuzzer targeting 'convert_to_markdown' via MCP server for 20 minutes...")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool="convert_to_markdown",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={"uri": sample_pdf_path},
        config=config,
        override_rules={
            "check_strict_markitdown_security_contract": {},
            "check_markitdown_uri_validation": {},
            "check_markitdown_file_uri_jailbreak": {},
            "check_markitdown_data_uri_security": {},
            "check_markitdown_markdown_output_security": {},
            "check_file_access": {},
            "check_introspection_path_traversal": {},
            "check_introspection_command_injection": {},
            "check_introspection_ssrf": {},
            "check_introspection_data_amplification": {},
            "check_untrusted_deserialization": {},
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {},
            "check_unhandled_promise_rejection": {}
        },
        predefined_seeds=predefined_seeds
    )

    # Set PYTHONPATH in the inspector process
    fuzzer.inspector.env = env

    # Run for 20 minutes (1200 seconds)
    fuzzer.run(time_per_iteration=1200)

if __name__ == "__main__":
    main()
