import os
import sys
import logging
import random
import asyncio

# Add workspace root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from mcp_fuzzer import MCPDifferentialFuzzer
from mcp_fuzzer.config import FuzzerConfig
from src.runners.python_runner import PythonRunner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    os.environ["PMB_TOOL_PROFILE"] = "full"
    
    python_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "python")
    )
    pmb_server_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "pmb", "src", "pmb", "mcp", "server.py")
    )
    dict_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "dictionaries", "pmb.dict")
    )
    sample_pdf_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "test_samples", "sample.pdf")
    )

    config = FuzzerConfig(
        timeout_limit=120.0,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    # 1. Discover all tools registered on PMB FastMCP server
    runner = PythonRunner(command=python_path, args=[pmb_server_path], target_tool="recall")
    runner.start()
    
    tools = []
    if runner.fastmcp_instance:
        try:
            loop = asyncio.new_event_loop()
            tools = loop.run_until_complete(runner.fastmcp_instance.list_tools())
        except Exception as e:
            logger.error(f"Failed to list FastMCP tools: {e}")

    tool_names = [getattr(t, "name", None) for t in tools if getattr(t, "name", None)]
    logger.info(f"Discovered {len(tool_names)} PMB tools: {tool_names}")
    runner.stop()

    if not tool_names:
        tool_names = ["recall", "overview", "record_batch", "recall_smart", "record_fact", "remember", "project_structure", "index_pdf"]

    predefined_seeds = [
        # Sequence Seed 1: Batch creation -> Search -> Overview
        {
            "items": [
                {"type": "fact", "content": "Project uses FastMCP python framework", "importance": 0.9},
                {"type": "lesson", "content": "Always validate file paths before opening", "project": "PMB"},
                {"type": "goal", "title": "Achieve 80%+ code coverage in fuzzing", "status": "in_progress"}
            ],
            "query": "FastMCP python framework",
            "path": sample_pdf_path
        },
        # Sequence Seed 2: Edge cases and null bytes
        {
            "items": [
                {"type": "fact", "content": "' OR '1'='1", "importance": -1.0},
                {"type": "invalid_type", "content": "../../../etc/passwd"}
            ],
            "query": "SELECT * FROM memory WHERE 1=1",
            "path": sample_pdf_path
        }
    ]

    logger.info(f"Initializing Stateful Multi-Tool Fuzzer with dictionary: {dict_path}")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[pmb_server_path],
        target_tool="record_batch",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={"path": sample_pdf_path},
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=predefined_seeds
    )

    # Run advanced stateful campaign for 1800 seconds (30 minutes)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
