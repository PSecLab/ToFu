import os
import sys

# Add workspace root to import path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import anyio
import mcp.types as types
from mcp.shared.message import SessionMessage
from mcp_fuzzer.runners.js_runner import JSRunner

def main():
    server_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "chrome-devtools-mcp",
            "build",
            "src",
            "bin",
            "chrome-devtools-mcp.js"
        )
    )

    runner = JSRunner(
        command="node",
        args=[
            server_path, 
            "--memoryDebugging=true",
            "--no-usage-statistics",
            "--executablePath=/snap/bin/chromium",
            "--isolated"
        ],
        target_tool="get_network_request"
    )

    runner.start()
    try:
        # Call the tool with an invalid reqid
        res = runner.execute({"reqid": 999999})
        print("Success:", res.success)
        print("Result:", res.result)
        print("Error details:", res.error)
    finally:
        runner.stop()

if __name__ == "__main__":
    main()
