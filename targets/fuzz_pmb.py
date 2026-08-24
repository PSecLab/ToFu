import os
import sys
import logging
import time
import argparse
import subprocess
import datetime

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.fuzzer import MCPDifferentialFuzzer
from src.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "pmb", "src")))

def get_all_pmb_tools():
    try:
        from pmb.mcp.tools import register_all
        class DummyMCP:
            def __init__(self):
                self.tools = []
            def tool(self):
                def decorator(fn):
                    self.tools.append(fn.__name__)
                    return fn
                return decorator
        dummy = DummyMCP()
        register_all(dummy, engine=None)
        return sorted(dummy.tools)
    except Exception as e:
        logger.error(f"Error fetching PMB tools: {e}")
        return []

def run_single_tool(tool_name: str, duration_seconds: int):
    python_path = sys.executable
    server_script = "-m"

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "pmb")
    )

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_pmb")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, f"corpus_{tool_name}")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir,
        dependencies_to_instrument=["pmb", "pmb.mcp", "pmb.engine", "sqlite3"]
    )

    file_backed_params = {
        "path": {
            "extension": ".txt",
            "prefix": "fuzz_pmb_file_"
        }
    }

    override_rules = {
        "check_unexpected_crash": {"on_trigger": "raise_exception"},
        "check_introspection_path_traversal": {"on_trigger": "allow_success_always"},
        "check_file_access": {"on_trigger": "allow_success_always"},
        "check_introspection_command_injection": {"on_trigger": "allow_success_always"},
        "check_unrestricted_file_upload": {"on_trigger": "allow_success_always"},
        "check_introspection_ssrf": {"on_trigger": "allow_success_always"},
        "check_introspection_temp_file_leak": {"on_trigger": "allow_success_always"},
        "check_introspection_log_injection": {"on_trigger": "allow_success_always"},
        "check_introspection_sensitive_data_logging": {"on_trigger": "allow_success_always"}
    }

    logger.info(f"=== Starting Fuzzing Process for PMB Tool [{tool_name}] ({duration_seconds}s) ===")
    
    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=["-m", "pmb.mcp.server"],
        target_tool=tool_name,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        corpus_dir=tool_corpus_dir,
        config=config,
        file_backed_params=file_backed_params,
        override_rules=override_rules
    )

    start_t = time.time()
    try:
        fuzzer.run(time_per_iteration=duration_seconds)
    except SystemExit:
        pass
    except Exception as e:
        logger.error(f"Error during fuzzing of {tool_name}: {e}", exc_info=True)
    elapsed = time.time() - start_t
    logger.info(f"=== Completed PMB Tool [{tool_name}] in {elapsed:.2f}s | Executions: {fuzzer.exec_count} ===")

def main():
    parser = argparse.ArgumentParser(description="Fuzzer pour les outils PMB MCP")
    parser.add_argument("--single-tool", type=str, default=None, help="Mode mono-outil sous processus")
    parser.add_argument("--max-time-per-target-sec", type=int, default=300, help="Durée de fuzzing par outil en secondes")
    args = parser.parse_args()

    if args.single_tool:
        run_single_tool(args.single_tool, args.max_time_per_target_sec)
        return

    tools = get_all_pmb_tools()
    python_path = sys.executable
    script_path = os.path.abspath(__file__)
    time_per_tool = args.max_time_per_target_sec

    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(os.path.dirname(__file__))) + ":" + os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "pmb", "src"))

    for idx, tool in enumerate(tools, 1):
        logger.info(f"▶️  [START TOOL {idx}/{len(tools)}] FUZZING SUR L'OUTIL : ---> '{tool}' <---")
        cmd = [
            python_path, script_path,
            "--single-tool", tool,
            "--max-time-per-target-sec", str(time_per_tool)
        ]
        try:
            subprocess.run(cmd, env=env)
        except Exception as e:
            logger.error(f"Exception sur l'outil '{tool}': {e}")

if __name__ == "__main__":
    main()
