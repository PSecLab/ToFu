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
        tool_names = ["recall", "overview", "record_batch", "recall_smart", "record_fact", "remember", "project_structure"]

    config = FuzzerConfig(
        timeout_limit=120.0,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    # Pick a random tool to initialize primary schema fuzzer
    initial_tool = random.choice(tool_names)
    logger.info(f"Initializing Multi-Tool Fuzzer with primary target '{initial_tool}' across {len(tool_names)} registered tools.")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[pmb_server_path],
        target_tool=initial_tool,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={},
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        }
    )

    # Run full multi-tool campaign for 1800 seconds (30 minutes)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
