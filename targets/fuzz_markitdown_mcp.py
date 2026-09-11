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
        dependencies_to_instrument=["markitdown", "markitdown_mcp", "pypdf", "openpyxl", "mammoth", "pptx", "bs4"],
        unexpected_crashes=(
            "TypeError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    predefined_seeds = [
        {"uri": f"file://{sample_pdf_path}"},
        {"uri": "data:text/html,<html><body><h1>Title</h1><p>Test</p></body></html>"},
        {"uri": "data:text/plain,Hello%20world"}
    ]

    logger.info("Initializing MarkItDown MCP Fuzzer targeting 'convert_to_markdown'...")

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_markitdown")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, "corpus_convert_to_markdown")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool="convert_to_markdown",
        corpus_dir=tool_corpus_dir,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
        file_backed_params={},
        config=config,
        override_rules=None,
        predefined_seeds=None
    )

    import argparse
    parser = argparse.ArgumentParser(description="Fuzz MarkItDown MCP")
    parser.add_argument("--time", type=int, default=300, help="Fuzzing duration in seconds (default: 300s / 5min)")
    args = parser.parse_args()

    # Set PYTHONPATH in the inspector process
    fuzzer.inspector.env = env

    logger.info(f"Starting MarkItDown MCP Fuzzing for {args.time} seconds...")
    fuzzer.run(time_per_iteration=args.time)

if __name__ == "__main__":
    main()
