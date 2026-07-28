import json
import subprocess
import time
import os
import sys
from .base import BaseRunner, RunnerResult

# Generate fake_coverage.py if it doesn't exist to allow Atheris to instrument JS coverage
fake_cov_path = os.path.join(os.path.dirname(__file__), "fake_coverage.py")
if not os.path.exists(fake_cov_path):
    with open(fake_cov_path, "w") as f:
        f.write("# Generated for Atheris coverage mapping\n")
        f.write("def trigger(idx):\n")
        for i in range(2000):
            f.write(f"    if idx == {i}: return {i}\n")
        f.write("    return -1\n")

import socket
import uuid

class JSRunner(BaseRunner):
    """
    A runner for Node.js/JavaScript MCP servers that uses a Unix domain socket
    for zero-latency IPC and V8 coverage extraction.
    """
    def __init__(self, command: str, args: list, target_tool: str, custom_env: dict = None):
        super().__init__(command, args, target_tool)
        self.process = None
        self.sock = None
        self.sock_path = f"/tmp/mcp_fuzz_{uuid.uuid4().hex[:8]}.sock"
        self.request_id = 1
        self.cov_map = {}
        self.next_cov_idx = 0
        self.already_covered = set()
        self.custom_env = custom_env or {}

    def start(self):
        try:
            from . import fake_coverage
        except ImportError:
            pass

        if self.command.endswith(".js"):
            target_script = self.command
            target_args = self.args
        else:
            target_script = None
            target_args = []
            for idx, arg in enumerate(self.args):
                if arg.endswith(".js"):
                    target_script = arg
                    target_args = self.args[:idx] + self.args[idx+1:]
                    break
            if not target_script:
                target_script = self.command
                target_args = self.args

        target_script = os.path.abspath(target_script)
        wrapper_path = os.path.join(os.path.dirname(__file__), "coverage_wrapper.js")

        cmd = ["node", wrapper_path, target_script] + target_args
        env = os.environ.copy()
        env.update(self.custom_env)
        env["FUZZER_SOCKET_PATH"] = self.sock_path

        # Clean up stale socket file if exists
        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except Exception:
                pass

        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=env
        )
        
        # Wait for socket ready signal on stdout
        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            if "SOCKET_READY:" in line:
                break

        # Connect socket with retries
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        
        connected = False
        for _ in range(20):
            try:
                self.sock.connect(self.sock_path)
                connected = True
                break
            except Exception:
                time.sleep(0.1)
                
        if not connected:
            raise ConnectionError(f"Failed to connect to JS runner Unix socket at {self.sock_path}")
            
        self.sock_file = self.sock.makefile('r')

    def stop(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except Exception:
                pass

    def execute(self, arguments: dict) -> RunnerResult:
        if not self.process or self.process.poll() is not None or not self.sock:
            try:
                self.start()
            except Exception as e:
                return RunnerResult(success=False, coverage=set(), error=f"JS runner process is not running and failed to restart: {e}")

        start_time = time.perf_counter()
        
        req = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": self.target_tool,
                "arguments": arguments
            },
            "id": self.request_id
        }
        
        try:
            self.sock.sendall((json.dumps(req) + "\n").encode('utf-8'))
            response_line = self.sock_file.readline()
        except Exception as e:
            print(f"[JSRunner] Socket Communication Error: {e}", file=sys.stderr)
            return RunnerResult(success=False, coverage=set(), error=f"Socket error: {e}")

        response_obj = None
        coverage_set = set()

        if response_line:
            try:
                payload = json.loads(response_line.strip())
                cov_data = payload.get("coverage", [])
                coverage_set.update(cov_data)
                
                resp_str = payload.get("response", "")
                if resp_str.startswith("{"):
                    response_obj = json.loads(resp_str)
            except Exception:
                pass

        try:
            from . import fake_coverage
        except ImportError:
            fake_coverage = None

        if fake_coverage:
            for cov_item in coverage_set:
                if cov_item not in self.cov_map:
                    self.cov_map[cov_item] = self.next_cov_idx
                    self.next_cov_idx = (self.next_cov_idx + 1) % 10000
                fake_coverage.trigger(self.cov_map[cov_item])

        end_time = time.perf_counter()
        execution_time_ms = (end_time - start_time) * 1000.0
        self.request_id += 1

        if not response_obj:
            stderr_msg = ""
            if self.process.poll() is not None:
                try:
                    stderr_msg = self.process.stderr.read().strip()
                except Exception:
                    pass
            err_detail = "Did not receive a matching response from JS process"
            if stderr_msg:
                err_detail += f". Stderr: {stderr_msg}"
            print(f"[JSRunner] JS Process Exception/Crash: {err_detail}", file=sys.stderr)
            return RunnerResult(
                success=False,
                coverage=coverage_set,
                error=err_detail,
                execution_time_ms=execution_time_ms
            )

        # Check for JSON-RPC error or tool execution success
        success = True
        error_msg = None
        result_val = None
        
        if "error" in response_obj:
            success = False
            error_msg = response_obj["error"].get("message", "JSON-RPC error")
        elif "result" in response_obj:
            res_data = response_obj["result"]
            if isinstance(res_data, dict) and res_data.get("isError"):
                success = False
                error_msg = str(res_data.get("content", "Tool reported error"))
            else:
                result_val = res_data

        return RunnerResult(
            success=success,
            coverage=coverage_set,
            result=result_val,
            error=error_msg,
            execution_time_ms=execution_time_ms
        )
