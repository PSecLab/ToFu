import os
import sys


def _should_enable_hook() -> bool:
    return (
        os.environ.get("MCP_FUZZER_ENABLE_PYTHON_HOOK") == "1"
        or bool(os.environ.get("MCP_FUZZER_ORACLE_LOG"))
    )


if _should_enable_hook():
    try:
        import mcp_fuzzer_hook

        mcp_fuzzer_hook.install()
    except Exception as exc:
        sys.stderr.write(f"[PY_HOOK ERROR] Failed to install Python hook: {exc}\n")
