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

ALL_BASIC_MEMORY_TOOLS = [
    "basic_memory_diagnostics",
    "build_context",
    "create_memory_project",
    "delete_note",
    "delete_project",
    "edit_note",
    "fetch",
    "list_directory",
    "list_memory_projects",
    "list_workspaces",
    "move_note",
    "read_content",
    "read_note",
    "recent_activity",
    "schema_diff",
    "schema_infer",
    "schema_validate",
    "search",
    "search_notes",
    "view_note",
    "write_note",
]

def run_single_tool(tool_name: str, duration_seconds: int):
    python_path = sys.executable
    server_script = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "basic_memory_wrapper.py"
        )
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "basic-memory")
    )

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_bm")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, f"corpus_{tool_name}")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir,
        dependencies_to_instrument=["basic_memory", "basic_memory.mcp", "basic_memory.repository"]
    )

    file_backed_params = {
        "path": {
            "extension": ".md",
            "prefix": "fuzz_test_note_"
        },
        "identifier": {
            "extension": ".md",
            "prefix": "fuzz_test_id_"
        }
    }

    override_rules = {
        "check_unexpected_crash": {},
        "check_introspection_path_traversal": {},
        "check_file_access": {},
        "check_unhandled_promise_rejection": {},
        "check_introspection_command_injection": {},
        "check_unrestricted_file_upload": {},
        "check_introspection_ssrf": {},
        "check_introspection_temp_file_leak": {},
        "check_introspection_log_injection": {},
        "check_introspection_sensitive_data_logging": {},
        "check_introspection_ssl_verification": {},
        "check_introspection_sensitive_file_access": {},
        "check_introspection_unrestricted_ip_binding": {},
        "check_introspection_redos": {},
        "check_introspection_type_confusion": {},
        "check_introspection_memory_access_violation": {}
    }

    logger.info(f"=== Starting Fuzzing Process for Tool [{tool_name}] ({duration_seconds}s) ===")
    
    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool=tool_name,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
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
    logger.info(f"=== Completed Tool [{tool_name}] in {elapsed:.2f}s | Executions: {fuzzer.exec_count} ===")

def main():
    parser = argparse.ArgumentParser(description="Fuzzer pour tous les outils basic-memory MCP")
    parser.add_argument("--tool", type=str, default=None, help="Mode mono-outil sous processus")
    parser.add_argument("--time", type=int, default=300, help="Durée de fuzzing par outil en secondes (défaut: 300s = 5 min)")
    args = parser.parse_args()

    if args.tool:
        run_single_tool(args.tool, args.time)
        return

    python_path = sys.executable
    script_path = os.path.abspath(__file__)
    time_per_tool = args.time

    logger.info("\n" + "🚀"*40)
    logger.info(f"  LANCEMENT DU FUZZER BASIC-MEMORY (1 ROUND, {len(ALL_BASIC_MEMORY_TOOLS)} OUTILS)")
    logger.info(f"  ⏱️  Durée par outil  : {time_per_tool // 60} min ({time_per_tool}s)")
    logger.info(f"  🛠️  Nombre d'outils   : {len(ALL_BASIC_MEMORY_TOOLS)}")
    logger.info("🚀"*40 + "\n")

    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

    for idx, tool in enumerate(ALL_BASIC_MEMORY_TOOLS, 1):
        logger.info("\n" + "⚡"*40)
        logger.info(f"▶️  [START TOOL {idx}/{len(ALL_BASIC_MEMORY_TOOLS)}] FUZZING SUR L'OUTIL : ---> '{tool}' <---")
        logger.info(f"⏰ Temps estimé fin : {(datetime.datetime.now() + datetime.timedelta(seconds=time_per_tool)).strftime('%H:%M:%S')}")
        logger.info("⚡"*40 + "\n")

        cmd = [
            python_path, script_path,
            "--tool", tool,
            "--time", str(time_per_tool)
        ]

        try:
            subprocess.run(cmd, env=env)
        except Exception as e:
            logger.error(f"Exception sur l'outil '{tool}': {e}")

        logger.info(f"⏹️  [FIN DE SESSION] Fuzzing terminé pour '{tool}'. Passage au suivant.")

if __name__ == "__main__":
    main()
