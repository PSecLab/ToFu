import os
import sys
import logging

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.fuzzer import MCPDifferentialFuzzer
from src.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    python_path = sys.executable
    server_script = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "serena_read_file_wrapper.py"
        )
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "serena")
    )

    config = FuzzerConfig(
        timeout_limit=5.0,
        allowed_workspace_dir=sandbox_dir
    )

    # Enable file_backed_params to dynamically generate file contents on disk
    # and pass the created file's relative path to relative_path parameter of read_file tool.
    file_backed_params = {
        "relative_path": {
            "extension": ".py",
            "prefix": "fuzz_test_file_"
        }
    }

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool="read_file",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
        config=config,
        file_backed_params=file_backed_params,
        override_rules={
            "check_unexpected_crash": {},
            "check_introspection_sensitive_error_leak": {},
            "check_introspection_redos": {},
            "check_introspection_type_confusion": {},
            "check_introspection_memory_access_violation": {}
        }
    )

    logger.info("Starting long fuzzing session (10 minutes) on serena 'read_file' with dynamic file-backed content generation...")
    fuzzer.run(time_per_iteration=600)

if __name__ == "__main__":
    main()
