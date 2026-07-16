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

class JSRunner(BaseRunner):
    """
    A runner for Node.js/JavaScript MCP servers that uses a coverage wrapper
    to collect line-by-line coverage via the V8 inspector and feed it back to Atheris.
    """
    def __init__(self, command: str, args: list, target_tool: str):
        super().__init__(command, args, target_tool)
        self.process = None
        self.request_id = 1
        self.cov_map = {}
        self.next_cov_idx = 0
        self.already_covered = set()

    def start(self):
        # Import fake_coverage under the active instrument_imports context manager
        try:
            from . import fake_coverage
        except ImportError:
            pass

        # Resolve target script and arguments
        if self.command.endswith(".js"):
            target_script = self.command
            target_args = self.args
        else:
            # Find the first .js file in self.args
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

        # Resolve the absolute path of target_script
        target_script = os.path.abspath(target_script)

        # Path to coverage_wrapper.js
        wrapper_path = os.path.join(os.path.dirname(__file__), "coverage_wrapper.js")

        cmd = ["node", wrapper_path, target_script] + target_args
        
        # Start the Node.js subprocess
        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        
        # Let the server initialize (e.g. database connections)
        time.sleep(1.0)

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def execute(self, arguments: dict) -> RunnerResult:
        if not self.process or self.process.poll() is not None:
            try:
                self.start()
            except Exception as e:
                return RunnerResult(success=False, coverage=set(), error=f"JS runner process is not running and failed to restart: {e}")

        start_time = time.perf_counter()
        
        # Send JSON-RPC request to the stdin of the wrapper
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
            self.process.stdin.write(json.dumps(req) + "\n")
            self.process.stdin.flush()
        except (IOError, BrokenPipeError) as e:
            return RunnerResult(success=False, coverage=set(), error=f"Failed to write to JS process: {e}")

        response_obj = None
        coverage_set = set()
        
        # Read lines from stdout until we get the coverage report
        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            line = line.strip()
            
            if line.startswith("COV: "):
                try:
                    cov_data = json.loads(line[5:])
                    coverage_set = set(cov_data)
                except Exception:
                    pass
                break
            
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    if obj.get("id") == self.request_id:
                        response_obj = obj
                except Exception:
                    pass

         # Trigger fake coverage in Python so Atheris can track it
        try:
            from . import fake_coverage
        except ImportError:
            fake_coverage = None

        if fake_coverage:
            for cov_item in coverage_set:
                if cov_item not in self.already_covered:
                    self.already_covered.add(cov_item)
                    if cov_item not in self.cov_map:
                        self.cov_map[cov_item] = self.next_cov_idx
                        self.next_cov_idx = (self.next_cov_idx + 1) % 2000
                    fake_coverage.trigger(self.cov_map[cov_item])

        end_time = time.perf_counter()
        execution_time_ms = (end_time - start_time) * 1000.0

        self.request_id += 1

        if not response_obj:
            return RunnerResult(
                success=False,
                coverage=coverage_set,
                error="Did not receive a matching response from JS process",
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
