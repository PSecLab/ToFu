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
            self.module_name = os.path.splitext(os.path.basename(py_file))[0]
            spec = importlib.util.spec_from_file_location(self.module_name, py_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not load spec for {py_file}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[self.module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as e:
                raise ImportError(f"Error executing module {py_file}: {e}")

        # Find the target tool function
        # We look for a function with the target name, or check inside FastMCP instance if present
        self.target_func = None
        
        # 1. Search in FastMCP instances registered in the module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if attr.__class__.__name__ == "FastMCP":
                # FastMCP registers tools in its registry
                # Let's try to find the tool in _tools or similar structure
                for tool in getattr(attr, "_tools", {}).values():
                    if getattr(tool, "name", None) == self.target_tool:
                        self.target_func = getattr(tool, "fn", None)
                        break

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
            # Bind arguments if necessary, or just call the function
            sig = inspect.signature(self.target_func)
            # Filter arguments to match the signature if target_func doesn't accept **kwargs
            has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
            if has_kwargs:
                val = self.target_func(**arguments)
            else:
                filtered_args = {k: v for k, v in arguments.items() if k in sig.parameters}
                val = self.target_func(**filtered_args)
        except Exception as e:
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
