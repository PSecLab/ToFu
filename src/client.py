from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import json
import os
import signal
import subprocess
import threading

class MCPInspector:
    def __init__(self, command: str, args: list, env: dict = None):
        self.command = command
        self.args = args
        self.env = env or os.environ.copy()

    def _query_server(self, target_tool: str = None):
        """Speak MCP over stdio and return the server's tools/list.

        BOUNDED by TOFU_STARTUP_TIMEOUT (default 25s). The two readline() calls
        below block forever when the target never answers its handshake -- and
        many corpus servers hang on startup (they wait on a backend/daemon).
        Before this bound, every such config sat until the run_eval hard kill
        (~120s) doing nothing. The whole exchange runs in a worker thread; if it
        does not finish in time we SIGKILL the server's process group and give
        up, so the config is recorded as a fast start-failure instead.
        """
        cmd = [self.command] + self.args
        env = os.environ.copy()
        env.update(self.env)
        timeout = float(os.environ.get("TOFU_STARTUP_TIMEOUT", "25"))

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
            start_new_session=True,   # own process group -> killpg reaches children
        )

        result = {"tools": []}

        def work():
            try:
                # 1. initialize
                proc.stdin.write(json.dumps({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                               "clientInfo": {"name": "fuzzer_inspector", "version": "1.0"}}
                }) + "\n")
                proc.stdin.flush()
                proc.stdout.readline()

                # 2. initialized notification
                proc.stdin.write(json.dumps({
                    "jsonrpc": "2.0", "method": "notifications/initialized"
                }) + "\n")
                proc.stdin.flush()

                # 3. tools/list
                proc.stdin.write(json.dumps({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/list"
                }) + "\n")
                proc.stdin.flush()

                while True:
                    resp_line = proc.stdout.readline()
                    if not resp_line:
                        return
                    try:
                        data = json.loads(resp_line)
                    except Exception:
                        continue
                    if data.get("id") == 2 and "result" in data:
                        result["tools"] = data.get("result", {}).get("tools", [])
                        return
            except Exception:
                return

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            # Server never completed the handshake within the deadline. Kill hard
            # (the readline then hits EOF and the daemon thread exits) and give up.
            self._kill(proc)
            return []

        self._kill(proc)
        return result["tools"]

    @staticmethod
    def _kill(proc):
        try:
            proc.terminate()
            proc.wait(timeout=1.0)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    async def fetch_all_tools(self) -> list:
        """Fetches the complete list of available tools from the server."""
        tools = self._query_server()
        return [t.get("name") for t in tools if t.get("name")]

    async def fetch_tool_metadata(self, tool_name: str) -> tuple:
        """Briefly connects to the server to extract tool metadata (name, description, schema)."""
        tools = self._query_server(tool_name)
        target = next((t for t in tools if t.get("name") == tool_name), None)
        if not target:
            raise ValueError(f"Tool '{tool_name}' not found on this MCP server.")
        return target.get("name"), target.get("description", ""), target.get("inputSchema", {})
