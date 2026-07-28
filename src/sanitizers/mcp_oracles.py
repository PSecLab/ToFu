"""
Sanitizers specifically designed for MCP servers and async JS execution.
"""
import re
import os
try:
    import psutil
except ImportError:
    psutil = None


def check_unhandled_promise_rejection(result: any) -> tuple[bool, str]:
    """
    Checks if the MCP tool response contains unhandled promise rejections,
    uncaught exceptions, or internal server error stack traces.
    """
    if result is None:
        return False, ""
    
    # Check if result is a dict with isError or error fields
    res_str = str(result)
    
    # Patterns indicating uncaught JS or Python exceptions inside tool execution
    error_patterns = [
        r"UnhandledPromiseRejection",
        r"TypeError: Cannot read propert",
        r"ReferenceError:",
        r"SyntaxError:",
        r"InternalServerError",
        r"Unhandled exception",
        r"Traceback \(most recent call last\):"
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, res_str, re.IGNORECASE):
            return True, f"Detected unhandled rejection/exception in MCP tool output: {pattern}"
            
    return False, ""

def check_process_and_fd_leaks(leaked_pids: set[int]) -> tuple[bool, str]:
    """
    Monitors if zombie background processes or orphaned sub-processes are left running.
    """
    if leaked_pids:
        return True, f"Leaked background subprocess PIDs detected after execution: {leaked_pids}"
    return False, ""
