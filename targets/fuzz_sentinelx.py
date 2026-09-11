import os
import sys
import logging
import time
import argparse

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.fuzzer import MCPDifferentialFuzzer
from src.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALL_SENTINELX_TOOLS = [
    "sentinelx_ping",
    "sentinelx_capabilities",
    "sentinelx_help",
    "sentinelx_state",
    "sentinelx_exec",
    "sentinelx_service",
    "sentinelx_restart",
    "sentinelx_script_run",
    "sentinelx_edit",
    "sentinelx_edit_upload_init",
    "sentinelx_edit_upload_file",
    "sentinelx_edit_upload_complete",
    "sentinelx_upload_file",
    "sentinelx_upload_init",
    "sentinelx_upload_chunk",
    "sentinelx_upload_complete",
    "sentinelx_file_export_init",
    "sentinelx_file_export_chunk",
    "sentinelx_file_export_complete",
    "sentinelx_read",
    "sentinelx_list",
    "sentinelx_search",
    "sentinelx_project_snapshot",
    "sentinelx_git",
    "sentinelx_read_audit",
    "sentinelx_move",
    "sentinelx_copy",
    "sentinelx_delete",
    "sentinelx_chmod",
    "sentinelx_chown"
]

def run_single_tool(tool_name: str, duration_seconds: int):
    python_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "python")
    )
    if not os.path.exists(python_path):
        python_path = sys.executable

    server_script = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "sentinelx_wrapper.py"
        )
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "sentinelx-cloud-core")
    )

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_sentinelx")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, f"corpus_{tool_name}")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir
    )

    file_backed_params = {
        "path": {
            "extension": ".txt",
            "prefix": "fuzz_sentinelx_file_"
        },
        "query": {
            "extension": ".txt",
            "prefix": "fuzz_sentinelx_query_"
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
    parser = argparse.ArgumentParser(description="Fuzzer pour les outils sentinelx-cloud-core MCP")
    parser.add_argument("--tool", type=str, help="Nom de l'outil sentinelx a fuzzer (ex: sentinelx_search)")
    parser.add_argument("--duration", type=int, default=300, help="Duree de fuzzing en secondes (defaut: 300s / 5min)")
    parser.add_argument("--all", action="store_true", help="Fuzzer tous les outils sentinelx sequentiellement")
    parser.add_argument("--list-tools", action="store_true", help="Lister tous les outils sentinelx disponibles")

    args = parser.parse_args()

    if args.list_tools:
        print("Outils sentinelx disponibles:")
        for t in ALL_SENTINELX_TOOLS:
            print(f" - {t}")
        return

    if args.all:
        logger.info(f"Lancement du fuzzing sur tous les {len(ALL_SENTINELX_TOOLS)} outils sentinelx ({args.duration}s chacun)...")
        for tool in ALL_SENTINELX_TOOLS:
            run_single_tool(tool, args.duration)
    elif args.tool:
        run_single_tool(args.tool, args.duration)
    else:
        print("Veuillez specifier un outil avec --tool <nom> (ex: --tool sentinelx_search) ou utiliser --all / --list-tools")

if __name__ == "__main__":
    main()
