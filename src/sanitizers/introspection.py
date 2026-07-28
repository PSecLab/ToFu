"""
Introspection Sanitizers / Behavior Monitors for MCP targets.
Rather than analyzing input strings before/after execution, these sanitizers inspect
system/runtime behavior (file access, process creation, syscalls, internal hooks)
during or after execution.
"""

import os
from typing import List, Tuple, Callable, Any

def check_file_access(accessed_files: List[str], restricted_patterns: List[str] = None) -> Tuple[bool, str]:
    """
    Checks if any file accessed during tool execution touches restricted system files
    or sensitive paths (e.g. /etc/passwd, /etc/shadow, /proc, /sys).
    
    :param accessed_files: List of file paths accessed/opened during execution.
    :param restricted_patterns: List of sensitive file path substrings or patterns to guard.
    """
    if restricted_patterns is None:
        restricted_patterns = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/master.passwd",
            "/etc/sudoers",
            "/proc/",
            "/sys/",
            "C:\\Windows\\System32"
        ]
    
    if not accessed_files:
        return False, ""

    for file_path in accessed_files:
        try:
            norm_path = os.path.abspath(file_path)
        except Exception:
            norm_path = str(file_path)

        for pattern in restricted_patterns:
            if pattern in norm_path or pattern in str(file_path):
                return True, f"Introspection alert: Access to restricted system file detected: '{file_path}' matching pattern '{pattern}'"

    return False, ""


class FileAccessTracer:
    """
    Context manager / wrapper to trace file opens (via builtins.open hook or sys trace/audit hook)
    during tool execution.
    """
    def __init__(self):
        self.accessed_files = []
        self._orig_open = None

    def __enter__(self):
        import builtins
        self.accessed_files = []
        self._orig_open = builtins.open
        
        def tracer_open(file, *args, **kwargs):
            if isinstance(file, (str, bytes, os.PathLike)):
                self.accessed_files.append(str(file))
            return self._orig_open(file, *args, **kwargs)
        
        builtins.open = tracer_open
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import builtins
        if self._orig_open:
            builtins.open = self._orig_open
