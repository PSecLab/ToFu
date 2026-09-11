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

ALL_MEMO_TOOLS = [
    "memo_ask",
    "memo_attention_ack",
    "memo_attention_add",
    "memo_conflict_open",
    "memo_conflict_resolve",
    "memo_context",
    "memo_delete",
    "memo_evidence_pack",
    "memo_federation_preview",
    "memo_focus_clear",
    "memo_focus_set",
    "memo_get",
    "memo_graph",
    "memo_handoff_consume",
    "memo_handoff_create",
    "memo_history",
    "memo_idle_capture",
    "memo_invalidate",
    "memo_journal_verify",
    "memo_mark_reviewed",
    "memo_offload",
    "memo_operational_state",
    "memo_outcome_record",
    "memo_pop_notification",
    "memo_procedure_candidates",
    "memo_procedure_promote",
    "memo_profile",
    "memo_rename",
    "memo_review_due",
    "memo_save",
    "memo_save_text",
    "memo_search",
    "memo_signal_list",
    "memo_signal_remember",
    "memo_start_session",
    "memo_supersede",
    "memo_terminal_list",
    "memo_unified_briefing",
    "memo_update",
    "memo_version",
    "memo_write_queue_status",
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
            "memo_wrapper.py"
        )
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "memo")
    )

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_memo")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, f"corpus_{tool_name}")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir,
        dependencies_to_instrument=["memo", "memo.server", "memo.memory"]
    )

    file_backed_params = {
        "path": {
            "extension": ".md",
            "prefix": "fuzz_memo_note_"
        },
        "file_path": {
            "extension": ".txt",
            "prefix": "fuzz_memo_file_"
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
    
    dict_path = None
    if tool_name == "memo_get":
        candidate = os.path.abspath(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "fuzzing", "dicts", "memo_get.dict")
        )
        if os.path.exists(candidate):
            dict_path = candidate
            logger.info(f"Using dictionary: {dict_path}")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool=tool_name,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
        corpus_dir=tool_corpus_dir,
        config=config,
        file_backed_params=file_backed_params,
        override_rules=override_rules,
        dict_file=dict_path
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
    parser = argparse.ArgumentParser(description="Fuzzer pour les outils jagoff/memo MCP")
    parser.add_argument("--tool", type=str, help="Nom de l'outil memo a fuzzer")
    parser.add_argument("--duration", type=int, default=30, help="Duree de fuzzing en secondes par outil (defaut: 30s)")
    parser.add_argument("--all", action="store_true", help="Fuzzer tous les outils memo sequentiellement")
    parser.add_argument("--list-tools", action="store_true", help="Lister tous les outils memo disponibles")

    args = parser.parse_args()

    if args.list_tools:
        print("Outils memo disponibles:")
        for t in ALL_MEMO_TOOLS:
            print(f" - {t}")
        return

    if args.all:
        logger.info(f"Lancement du fuzzing sur tous les {len(ALL_MEMO_TOOLS)} outils memo ({args.duration}s chacun)...")
        for tool in ALL_MEMO_TOOLS:
            run_single_tool(tool, args.duration)
    elif args.tool:
        run_single_tool(args.tool, args.duration)
    else:
        print("Veuillez specifier un outil avec --tool <nom> ou utiliser --all ou --list-tools")

if __name__ == "__main__":
    main()
