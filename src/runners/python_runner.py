import sys
import os
import importlib.util
import inspect
import time
from typing import Callable, Dict, Any
from .base import BaseRunner, RunnerResult

class PythonRunner(BaseRunner):
    def __init__(self, command: str, args: list, target_tool: str):
        super().__init__(command, args, target_tool)
        self.target_func: Callable = None
        self.module_name = ""
        self.fastmcp_instance = None
        self.mcp_server = None

    def start(self):
        """Locates and imports the python module to find the tool function."""
        # Find python file in args
        py_file = None
        for arg in self.args:
            if arg.endswith(".py"):
                py_file = os.path.abspath(arg)
                break

        if not py_file:
            # Fallback if no .py file in args, try to import the command or args directly
            if self.args:
                self.module_name = self.args[-1]
            else:
                self.module_name = self.command

            try:
                module = importlib.import_module(self.module_name)
            except Exception as e:
                raise ImportError(f"Could not import module {self.module_name}: {e}")
        else:
            # Load the file as a module
            base_name = os.path.splitext(os.path.basename(py_file))[0]
            self.module_name = "mcp_target_module" if base_name == "__main__" else base_name
            spec = importlib.util.spec_from_file_location(self.module_name, py_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not load spec for {py_file}")
            module = importlib.util.module_from_spec(spec)
            module.__name__ = self.module_name
            sys.modules[self.module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as e:
                raise ImportError(f"Error executing module {py_file}: {e}")

        # Find the target tool function and server instances
        self.target_func = None
        self.fastmcp_instance = None
        self.mcp_server = None
        
        # 1. Search in FastMCP and Server instances registered in the module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if attr.__class__.__name__ == "FastMCP":
                self.fastmcp_instance = attr
                self.mcp_server = attr._mcp_server
                # Try to find the tool in _tools or similar structure
                for tool in getattr(attr, "_tools", {}).values():
                    if getattr(tool, "name", None) == self.target_tool:
                        self.target_func = getattr(tool, "fn", None)
                        break
            elif attr.__class__.__name__ == "Server" and attr.__class__.__module__.startswith("mcp."):
                self.mcp_server = attr

        # 2. Fallback to global function in the module matching target_tool name
        if not self.target_func:
            if hasattr(module, self.target_tool):
                candidate = getattr(module, self.target_tool)
                if callable(candidate):
                    self.target_func = candidate

        if not self.target_func:
            raise AttributeError(f"Could not find callable tool/function '{self.target_tool}' in module '{self.module_name}'")

    def execute(self, arguments: dict) -> RunnerResult:
        if not self.target_func:
            return RunnerResult(success=False, coverage=set(), error="Runner not started or function not found")

        covered_lines = set()
        
        def trace_lines(frame, event, arg):
            if event == 'line':
                code = frame.f_code
                filename = code.co_filename
                # Only track the target module file
                if self.module_name in filename or (hasattr(self.target_func, '__code__') and filename == self.target_func.__code__.co_filename):
                    covered_lines.add(f"{os.path.basename(filename)}:{frame.f_lineno}")
            return trace_lines

        success = True
        error_msg = None
        start_time = time.perf_counter()

        val = None
        # Save previous trace function
        old_trace = sys.gettrace()
        sys.settrace(trace_lines)
        try:
            if self.mcp_server:
                # Use JSON-RPC stdio emulator in-process to run the full server pipeline
                import anyio
                import mcp.types as types
                from mcp.shared.message import SessionMessage

                async def run_test():
                    read_stream_writer, read_stream = anyio.create_memory_object_stream(10)
                    write_stream, write_stream_reader = anyio.create_memory_object_stream(10)

                    async with anyio.create_task_group() as tg:
                        tg.start_soon(
                            self.mcp_server.run,
                            read_stream,
                            write_stream,
                            self.mcp_server.create_initialization_options()
                        )

                        # 1. Initialize Handshake
                        init_req = types.JSONRPCMessage.model_validate({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": "2024-11-05",
                                "capabilities": {},
                                "clientInfo": {"name": "fuzzer", "version": "1.0"}
                            }
                        })
                        await read_stream_writer.send(SessionMessage(init_req))
                        await write_stream_reader.receive()

                        # 2. Initialized Notification
                        initialized_notif = types.JSONRPCMessage.model_validate({
                            "jsonrpc": "2.0",
                            "method": "notifications/initialized"
                        })
                        await read_stream_writer.send(SessionMessage(initialized_notif))

                        # 3. Call Tool Request
                        call_req = types.JSONRPCMessage.model_validate({
                            "jsonrpc": "2.0",
                            "id": 2,
                            "method": "tools/call",
                            "params": {
                                "name": self.target_tool,
                                "arguments": arguments
                            }
                        })
                        await read_stream_writer.send(SessionMessage(call_req))
                        call_resp = await write_stream_reader.receive()

                        # Clean up server by closing the streams
                        await read_stream_writer.aclose()
                        await write_stream.aclose()

                        return call_resp

                rpc_resp = anyio.run(run_test)
                if hasattr(rpc_resp, 'message'):
                    msg = rpc_resp.message
                    if hasattr(msg, "root"):
                        msg = msg.root
                    if isinstance(msg, types.JSONRPCError):
                        success = False
                        error_msg = msg.error.message
                    elif isinstance(msg, types.JSONRPCResponse):
                        res_data = msg.result
                        if isinstance(res_data, dict) and res_data.get("isError"):
                            success = False
                            error_msg = str(res_data.get("content", "Tool reported error"))
                        else:
                            success = True
                            content = res_data.get("content", []) if isinstance(res_data, dict) else []
                            if isinstance(content, list):
                                text_contents = []
                                for block in content:
                                    if isinstance(block, dict) and block.get("type") == "text":
                                        text_contents.append(block.get("text", ""))
                                    elif hasattr(block, "text"):
                                        text_contents.append(block.text)
                                val = "\n".join(text_contents)
                            else:
                                val = str(res_data)
            else:
                # Direct invocation fallback (if not an MCP server)
                sig = inspect.signature(self.target_func)
                has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                if has_kwargs:
                    val = self.target_func(**arguments)
                else:
                    filtered_args = {k: v for k, v in arguments.items() if k in sig.parameters}
                    val = self.target_func(**filtered_args)
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            success = False
            error_msg = f"{type(e).__name__}: {str(e)}"
        finally:
            sys.settrace(old_trace)

        end_time = time.perf_counter()
        execution_time_ms = (end_time - start_time) * 1000.0

        return RunnerResult(
            success=success,
            coverage=covered_lines,
            result=val,
            error=error_msg,
            execution_time_ms=execution_time_ms
        )
