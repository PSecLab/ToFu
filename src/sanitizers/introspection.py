"""
Introspection Sanitizers / Behavior Monitors for MCP targets.
Rather than analyzing input strings before/after execution, these sanitizers inspect
system/runtime behavior (file access, process creation, syscalls, internal hooks)
during or after execution.
"""

import os
import re
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


def check_introspection_path_traversal(accessed_files: List[str], allowed_base_dir: str = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Path Traversal.
    Checks if any file read/written during tool execution escapes the dedicated allowed base directory.
    
    :param accessed_files: List of file paths accessed during execution (captured via Python introspection).
    :param allowed_base_dir: Absolute path of the dedicated directory. Access outside this path is flagged.
    """
    if not accessed_files:
        return False, ""

    if allowed_base_dir is None:
        # Default fallback to current working directory
        allowed_base_dir = os.getcwd()

    canonical_base = os.path.realpath(allowed_base_dir)

    for file_path in accessed_files:
        try:
            canonical_path = os.path.realpath(file_path)
            # Check if canonical_path is inside canonical_base
            relative = os.path.relpath(canonical_path, canonical_base)
            if relative.startswith("..") or os.path.isabs(relative) and not canonical_path.startswith(canonical_base):
                return True, (
                    f"Introspection Path Traversal Alert: Access to file outside dedicated directory '{canonical_base}' "
                    f"detected: '{file_path}' (canonical: '{canonical_path}')"
                )
        except Exception as e:
            # If path resolution fails, flag as suspicious
            return True, f"Introspection Path Traversal Alert: Error resolving path '{file_path}': {e}"

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


def check_untrusted_deserialization(deserialization_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Untrusted Deserialization (CWE-502).
    Monitors execution for unsafe deserialization operations (pickle.loads, yaml.unsafe_load, marshal.loads, etc.).
    
    :param deserialization_calls: List of records captured during tool execution.
    """
    if not deserialization_calls:
        return False, ""

    for call in deserialization_calls:
        module_name = call.get("module", "")
        func_name = call.get("function", "")
        detail = call.get("detail", "")
        return True, (
            f"Introspection Deserialization Alert (CWE-502): Unsafe deserialization detected! "
            f"Invoked '{module_name}.{func_name}' ({detail})."
        )

    return False, ""


class DeserializationTracer:
    """
    Traces invocation of unsafe deserialization primitives (pickle.loads, pickle.load, marshal.loads, etc.)
    during Python MCP tool execution.
    """
    def __init__(self):
        self.deserialization_calls = []
        self._orig_pickle_loads = None
        self._orig_pickle_load = None
        self._orig_marshal_loads = None

    def __enter__(self):
        self.deserialization_calls = []
        try:
            import pickle
            self._orig_pickle_loads = pickle.loads
            self._orig_pickle_load = pickle.load

            def traced_pickle_loads(data, *args, **kwargs):
                self.deserialization_calls.append({
                    "module": "pickle",
                    "function": "loads",
                    "detail": f"payload_size={len(data) if hasattr(data, '__len__') else 'unknown'}"
                })
                return self._orig_pickle_loads(data, *args, **kwargs)

            def traced_pickle_load(file_obj, *args, **kwargs):
                self.deserialization_calls.append({
                    "module": "pickle",
                    "function": "load",
                    "detail": "file stream"
                })
                return self._orig_pickle_load(file_obj, *args, **kwargs)

            pickle.loads = traced_pickle_loads
            pickle.load = traced_pickle_load
        except ImportError:
            pass

        # Note: marshal.loads is used by Python internal loader/importlib when loading compiled modules (.pyc).
        # We focus deserialization tracing on pickle (CWE-502) to avoid false positives on standard library module imports.
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            import pickle
            if self._orig_pickle_loads:
                pickle.loads = self._orig_pickle_loads
            if self._orig_pickle_load:
                pickle.load = self._orig_pickle_load
        except ImportError:
            pass

        try:
            import marshal
            if self._orig_marshal_loads:
                marshal.loads = self._orig_marshal_loads
        except ImportError:
            pass

def check_introspection_command_injection(executed_commands: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Command Injection (CWE-77 / CWE-78).
    Monitors execution for command invocations (os.system, os.popen, os.exec*, subprocess.Popen, etc.)
    and detects injection of unneutralized special elements.
    
    :param executed_commands: List of command records captured during tool execution.
    """
    if not executed_commands:
        return False, ""

    shell_injection_chars = [";", "&&", "||", "|", "`", "$(", ">", "<"]

    for cmd_info in executed_commands:
        if isinstance(cmd_info, dict):
            cmd_str = cmd_info.get("command", "")
            func_name = cmd_info.get("function", "")
            shell = cmd_info.get("shell", False)
        else:
            cmd_str = str(cmd_info)
            func_name = "unknown"
            shell = False
        
        has_injection_metachar = any(char in cmd_str for char in shell_injection_chars)
        cwe_code = "CWE-77/CWE-78" if has_injection_metachar else "CWE-78"

        return True, (
            f"Introspection Command Injection Alert ({cwe_code}): Command execution detected! "
            f"Invoked via '{func_name}' (shell={shell}): '{cmd_str}'."
        )

    return False, ""


class CommandExecutionTracer:
    """
    Traces invocation of system command execution primitives (os.system, os.popen, subprocess.Popen/run/call)
    during Python MCP tool execution.
    """
    def __init__(self):
        self.executed_commands = []
        self._orig_os_system = None
        self._orig_os_popen = None
        self._orig_subprocess_popen = None

    def __enter__(self):
        self.executed_commands = []
        import os
        import subprocess

        self._orig_os_system = os.system
        self._orig_os_popen = os.popen
        self._orig_subprocess_popen = subprocess.Popen

        def traced_os_system(cmd):
            self.executed_commands.append({
                "function": "os.system",
                "command": str(cmd),
                "shell": True
            })
            return self._orig_os_system(cmd)

        def traced_os_popen(cmd, *args, **kwargs):
            self.executed_commands.append({
                "function": "os.popen",
                "command": str(cmd),
                "shell": True
            })
            return self._orig_os_popen(cmd, *args, **kwargs)

        orig_popen = self._orig_subprocess_popen
        def traced_subprocess_popen(cmd, *args, **kwargs):
            shell_val = kwargs.get("shell", False)
            cmd_repr = str(cmd)
            self.executed_commands.append({
                "function": "subprocess.Popen",
                "command": cmd_repr,
                "shell": shell_val
            })
            return orig_popen(cmd, *args, **kwargs)

        os.system = traced_os_system
        os.popen = traced_os_popen
        subprocess.Popen = traced_subprocess_popen
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import os
        import subprocess

        if self._orig_os_system:
            os.system = self._orig_os_system
        if self._orig_os_popen:
            os.popen = self._orig_os_popen
        if self._orig_subprocess_popen:
            subprocess.Popen = self._orig_subprocess_popen


def check_introspection_sql_injection(sql_queries: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for SQL Injection (CWE-89).
    Monitors execution for raw or unparameterized SQL queries executed against DB engines (e.g. sqlite3 Cursor.execute).
    
    :param sql_queries: List of query records captured during tool execution.
    """
    if not sql_queries:
        return False, ""

    sql_injection_patterns = [
        "' or ", '" or ', " or 1=1", " union select ", "--", "; drop table ", "; delete from "
    ]

    for q_info in sql_queries:
        query_str = q_info.get("query", "")
        driver = q_info.get("driver", "sqlite3")
        params = q_info.get("params", None)

        lower_query = query_str.lower()
        has_suspicious_pattern = any(pat in lower_query for pat in sql_injection_patterns)
        is_unparameterized = params is None or len(params) == 0

        if has_suspicious_pattern or (is_unparameterized and any(kw in lower_query for kw in ["select", "insert", "update", "delete"])):
            return True, (
                f"Introspection SQL Injection Alert (CWE-89): Suspicious/unparameterized SQL query executed via '{driver}'! "
                f"Query: '{query_str}'."
            )

    return False, ""


class SQLExecutionTracer:
    """
    Traces execution of SQL queries (e.g. sqlite3.connect cursor calls)
    during Python MCP tool execution.
    """
    def __init__(self):
        self.sql_queries = []
        self._orig_connect = None

    def __enter__(self):
        self.sql_queries = []
        try:
            import sqlite3
            self._orig_connect = sqlite3.connect
            orig_connect = self._orig_connect
            tracer_self = self

            class TracedConnection:
                def __init__(self, real_conn):
                    self._conn = real_conn

                def __enter__(self):
                    self._conn.__enter__()
                    return self

                def __exit__(self, exc_type, exc_val, exc_tb):
                    return self._conn.__exit__(exc_type, exc_val, exc_tb)

                def execute(self, sql, parameters=(), *args, **kwargs):
                    tracer_self.sql_queries.append({
                        "driver": "sqlite3",
                        "query": str(sql),
                        "params": parameters
                    })
                    return self._conn.execute(sql, parameters, *args, **kwargs)

                def cursor(self, *args, **kwargs):
                    real_cursor = self._conn.cursor(*args, **kwargs)
                    
                    class TracedCursor:
                        def __init__(self, c):
                            self._c = c

                        def execute(self, sql, parameters=(), *e_args, **e_kwargs):
                            tracer_self.sql_queries.append({
                                "driver": "sqlite3",
                                "query": str(sql),
                                "params": parameters
                            })
                            return self._c.execute(sql, parameters, *e_args, **e_kwargs)

                        def fetchall(self):
                            return self._c.fetchall()

                        def fetchone(self):
                            return self._c.fetchone()

                        def __getattr__(self, name):
                            return getattr(self._c, name)

                    return TracedCursor(real_cursor)

                def __getattr__(self, name):
                    return getattr(self._conn, name)

            def traced_connect(*args, **kwargs):
                conn = orig_connect(*args, **kwargs)
                return TracedConnection(conn)

            sqlite3.connect = traced_connect
        except Exception:
            pass

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            import sqlite3
            if self._orig_connect:
                sqlite3.connect = self._orig_connect
        except Exception:
            pass


def check_unrestricted_file_upload(written_files: List[dict], dangerous_extensions: List[str] = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Unrestricted File Upload (CWE-434).
    Monitors file creation/write operations to detect writing of executable or dangerous file types
    (e.g., .py, .sh, .exe, .php, .jsp, .so, .dll, .bash).
    
    :param written_files: List of file write records captured during tool execution.
    :param dangerous_extensions: Optional list of extensions to flag as dangerous.
    """
    if not written_files:
        return False, ""

    if dangerous_extensions is None:
        dangerous_extensions = [
            ".py", ".sh", ".bash", ".exe", ".php", ".jsp", ".asp", ".aspx", 
            ".so", ".dll", ".bat", ".cmd", ".vbs", ".pl", ".cgi"
        ]

    for record in written_files:
        if isinstance(record, dict):
            file_path = record.get("path", "")
            mode = record.get("mode", "")
        else:
            file_path = str(record)
            mode = ""
        
        _, ext = os.path.splitext(file_path)
        ext_lower = ext.lower()

        if ext_lower in dangerous_extensions:
            return True, (
                f"Introspection File Upload Alert (CWE-434): Creation/write of dangerous file type detected! "
                f"File: '{file_path}' (extension: '{ext_lower}', mode: '{mode}')."
            )

    return False, ""


class FileWriteTracer:
    """
    Traces file write/creation operations (open with 'w', 'a', 'wb', 'w+', etc.)
    during Python MCP tool execution.
    """
    def __init__(self):
        self.written_files = []
        self._orig_open = None

    def __enter__(self):
        import builtins
        self.written_files = []
        self._orig_open = builtins.open
        tracer_self = self

        def traced_open(file, mode='r', *args, **kwargs):
            mode_str = str(mode)
            if any(w_flag in mode_str for w_flag in ['w', 'a', 'x', '+']):
                if isinstance(file, (str, bytes, os.PathLike)):
                    tracer_self.written_files.append({
                        "path": str(file),
                        "mode": mode_str
                    })
            return tracer_self._orig_open(file, mode, *args, **kwargs)

        builtins.open = traced_open
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import builtins
        if self._orig_open:
            builtins.open = self._orig_open


def check_introspection_code_injection(evaluated_code_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Code Injection (CWE-94).
    Monitors execution for dynamic code evaluation operations (builtins.eval, builtins.exec, compile).
    
    :param evaluated_code_calls: List of code evaluation records captured during tool execution.
    """
    if not evaluated_code_calls:
        return False, ""

    for record in evaluated_code_calls:
        func_name = record.get("function", "")
        expression = record.get("expression", "")
        return True, (
            f"Introspection Code Injection Alert (CWE-94): Dynamic code evaluation detected! "
            f"Invoked via '{func_name}': '{expression}'."
        )

    return False, ""


class CodeExecutionTracer:
    """
    Traces dynamic code execution primitives (builtins.eval, builtins.exec)
    during Python MCP tool execution.
    """
    def __init__(self):
        self.evaluated_code_calls = []
        self._orig_eval = None
        self._orig_exec = None

    def __enter__(self):
        import builtins
        self.evaluated_code_calls = []
        self._orig_eval = builtins.eval
        self._orig_exec = builtins.exec
        tracer_self = self

        def traced_eval(source, globals=None, locals=None):
            expr_str = str(source)[:100]
            if not any(ign in expr_str for ign in ["<code object", "importlib", "site-packages", "__dataclass_", "def __create_fn__"]):
                tracer_self.evaluated_code_calls.append({
                    "function": "eval",
                    "expression": expr_str
                })
            if globals is None and locals is None:
                return tracer_self._orig_eval(source)
            elif locals is None:
                return tracer_self._orig_eval(source, globals)
            else:
                return tracer_self._orig_eval(source, globals, locals)

        def traced_exec(source, globals=None, locals=None):
            expr_str = str(source)[:100]
            if not any(ign in expr_str for ign in ["<code object", "importlib", "site-packages", "__dataclass_", "def __create_fn__"]):
                tracer_self.evaluated_code_calls.append({
                    "function": "exec",
                    "expression": expr_str
                })
            if globals is None and locals is None:
                return tracer_self._orig_exec(source)
            elif locals is None:
                return tracer_self._orig_exec(source, globals)
            else:
                return tracer_self._orig_exec(source, globals, locals)

        builtins.eval = traced_eval
        builtins.exec = traced_exec
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import builtins
        if self._orig_eval:
            builtins.eval = self._orig_eval
        if self._orig_exec:
            builtins.exec = self._orig_exec


def check_introspection_ssrf(network_connections: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Server-Side Request Forgery / SSRF (CWE-918).
    Monitors execution for outgoing network socket connections to private, internal, or loopback IP ranges
    (127.0.0.1, localhost, 169.254.169.254 metadata API, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    
    :param network_connections: List of network connection records captured during tool execution.
    """
    if not network_connections:
        return False, ""

    internal_host_patterns = [
        "127.0.0.1", "localhost", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal",
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.30.", "172.31."
    ]

    for conn in network_connections:
        if isinstance(conn, dict):
            host = str(conn.get("host", ""))
            port = conn.get("port", None)
        else:
            host = str(conn)
            port = None
        
        for pattern in internal_host_patterns:
            if host == pattern or host.startswith(pattern):
                return True, (
                    f"Introspection SSRF Alert (CWE-918): Outgoing connection to internal/private network target detected! "
                    f"Target host: '{host}' (port: {port})."
                )

    return False, ""


class NetworkExecutionTracer:
    """
    Traces outgoing socket connection attempts (socket.socket.connect, socket.create_connection)
    during Python MCP tool execution.
    """
    def __init__(self):
        self.network_connections = []
        self._orig_socket_connect = None

    def __enter__(self):
        import socket
        self.network_connections = []
        self._orig_socket_connect = socket.socket.connect
        orig_connect = self._orig_socket_connect
        tracer_self = self

        def traced_connect(sock_self, address):
            try:
                if isinstance(address, tuple) and len(address) >= 2:
                    host, port = address[0], address[1]
                else:
                    host, port = str(address), None
                tracer_self.network_connections.append({
                    "host": str(host),
                    "port": port
                })
            except Exception:
                pass
            return orig_connect(sock_self, address)

        socket.socket.connect = traced_connect
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import socket
        if self._orig_socket_connect:
            socket.socket.connect = self._orig_socket_connect


def check_introspection_temp_file_leak(leaked_temp_files: List[str]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Temporary File Leak / Information Exposure in Temp Folder (CWE-533).
    Monitors execution for orphan or uncleaned temporary files created in /tmp or temp directory
    during tool execution.
    
    :param leaked_temp_files: List of file paths remaining in temporary directories after tool call.
    """
    if not leaked_temp_files:
        return False, ""

    return True, (
        f"Introspection Temp File Leak Alert (CWE-533): Uncleaned temporary file(s) remaining in temp folder! "
        f"Leaked files: {leaked_temp_files}."
    )


class TempFileLeakTracer:
    """
    Traces temporary file creation and detects orphan files remaining in /tmp or temp directory
    after Python MCP tool execution.
    """
    def __init__(self, temp_dir: str = None):
        import tempfile
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.before_files = set()
        self.leaked_temp_files = []

    def __enter__(self):
        import glob
        try:
            self.before_files = set(glob.glob(os.path.join(self.temp_dir, "*")))
        except Exception:
            self.before_files = set()
        self.leaked_temp_files = []
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import glob
        try:
            after_files = set(glob.glob(os.path.join(self.temp_dir, "*")))
        except Exception:
            after_files = set()
        
        diff = after_files - self.before_files
        # Filter out systemd, GNOME desktop thumbnailers, snap, and profiler temporary files/directories
        system_ignore_patterns = [
            ".cpuprofile", ".cpuprofile.json",
            "systemd-private-", "gnome-desktop-thumbnailer-",
            "snap.", "tmp.mcp_", "/tmp/mcp_",
            "tracker-extract-files-", "gdbus-nonce-file-", ".org.chromium.Chromium",
            "bigfix", "BigFix", "ca-certificates", "apt-dpkg-install"
        ]
        filtered_diff = [
            f for f in diff 
            if not any(pattern in f for pattern in system_ignore_patterns)
        ]
        self.leaked_temp_files = filtered_diff



# ---------------------------------------------------------------------------
# CWE-117: Log Injection / Output Neutralization for Logs
# ---------------------------------------------------------------------------

def check_introspection_log_injection(logged_messages: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Log Injection / Output Neutralization for Logs (CWE-117).
    Monitors log outputs (logging module, stderr, stdout) during tool execution for unneutralized
    CRLF / newline characters ('\\n', '\\r') or ANSI escape sequences injected from user inputs.
    
    :param logged_messages: List of log records captured during tool execution.
    """
    if not logged_messages:
        return False, ""

    for record in logged_messages:
        if isinstance(record, dict):
            msg = record.get("message", "")
            source = record.get("source", "logger")
        else:
            msg = str(record)
            source = "logger"
        
        # Check for unescaped CRLF injections that forge log entries
        if "\n" in msg or "\r" in msg:
            # Replace newlines with visual escape for diagnostic representation
            vis_msg = msg.replace("\n", "\\n").replace("\r", "\\r")
            return True, (
                f"Introspection Log Injection Alert (CWE-117): Unneutralized CRLF newline character detected in log output ({source})! "
                f"Logged content: '{vis_msg}'."
            )
            
        # Check for dangerous ANSI escape sequences (terminal injection)
        if "\x1b[" in msg or "\033[" in msg:
            return True, (
                f"Introspection Log Injection Alert (CWE-117): ANSI escape sequence detected in log output ({source})! "
                f"Logged content: '{msg}'."
            )

    return False, ""


class LogInjectionTracer:
    """
    Traces Python logging module calls and stderr/stdout writes during tool execution
    to capture unneutralized log injection attempts.
    """
    def __init__(self):
        self.logged_messages = []
        self._orig_log = None

    def __enter__(self):
        import logging
        self.logged_messages = []
        self._orig_log = logging.Logger._log
        orig_log = self._orig_log
        tracer_self = self

        def traced_log(logger_self, level, msg, args, exc_info=None, extra=None, stack_info=False, stacklevel=1):
            try:
                formatted_msg = msg % args if args else str(msg)
                tracer_self.logged_messages.append({
                    "source": f"logger:{logger_self.name}",
                    "message": str(formatted_msg),
                    "level": logging.getLevelName(level)
                })
            except Exception:
                tracer_self.logged_messages.append({
                    "source": f"logger:{logger_self.name}",
                    "message": str(msg),
                    "level": logging.getLevelName(level)
                })
            return orig_log(logger_self, level, msg, args, exc_info=exc_info, extra=extra, stack_info=stack_info, stacklevel=stacklevel)

        logging.Logger._log = traced_log
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import logging
        if self._orig_log:
            logging.Logger._log = self._orig_log


# ---------------------------------------------------------------------------
# CWE-779: Logging of Excessive / Sensitive Data
# ---------------------------------------------------------------------------

def check_introspection_sensitive_data_logging(logged_messages: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Logging of Sensitive Data (CWE-779).
    Monitors log outputs for exposure of unredacted credentials, API tokens, secret keys, or passwords.
    
    :param logged_messages: List of log records captured during tool execution.
    """
    if not logged_messages:
        return False, ""

    sensitive_patterns = [
        "sk-proj-", "bearer ", "password=", "secret=", "api_key=", 
        "PRIVATE KEY-----", "access_token=", "token="
    ]

    for record in logged_messages:
        if isinstance(record, dict):
            msg = record.get("message", "").lower()
            source = record.get("source", "logger")
        else:
            msg = str(record).lower()
            source = "logger"
        
        for pattern in sensitive_patterns:
            if pattern in msg:
                return True, (
                    f"Introspection Sensitive Data Logging Alert (CWE-779): Unredacted sensitive token/credential detected in log output ({source})! "
                    f"Matched pattern: '{pattern}' in log message."
                )

    return False, ""


class SensitiveDataLoggingTracer:
    """
    Traces log outputs to detect exposure of sensitive data/tokens in cleartext.
    Reuses the captured log records from logging.
    """
    def __init__(self, log_tracer: LogInjectionTracer = None):
        self.log_tracer = log_tracer

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# CWE-295: Improper Certificate Validation / Disabled SSL Verification
# ---------------------------------------------------------------------------

def check_introspection_ssl_verification(unverified_ssl_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Improper Certificate Validation (CWE-295).
    Monitors outgoing SSL/TLS connections during tool execution to flag disabled certificate validation
    (e.g., verify=False in requests, ssl.CERT_NONE, or ssl._create_unverified_context).
    
    :param unverified_ssl_calls: List of unverified SSL connection records captured during tool execution.
    """
    if not unverified_ssl_calls:
        return False, ""

    for record in unverified_ssl_calls:
        func = record.get("function", "")
        reason = record.get("reason", "")
        return True, (
            f"Introspection Improper Certificate Validation Alert (CWE-295): Outgoing SSL/TLS connection initiated with disabled certificate verification! "
            f"Invoked via '{func}': {reason}."
        )

    return False, ""


class SSLCertificateValidationTracer:
    """
    Traces SSL/TLS context creation and socket wrapping to detect disabled certificate verification (CERT_NONE).
    """
    def __init__(self):
        self.unverified_ssl_calls = []
        self._orig_create_unverified_context = None

    def __enter__(self):
        import ssl
        self.unverified_ssl_calls = []
        tracer_self = self

        if hasattr(ssl, "_create_unverified_context"):
            self._orig_create_unverified_context = ssl._create_unverified_context
            orig_func = self._orig_create_unverified_context

            def traced_create_unverified_context(*args, **kwargs):
                tracer_self.unverified_ssl_calls.append({
                    "function": "ssl._create_unverified_context",
                    "reason": "Created unverified SSL context bypassing CA certificate verification."
                })
                return orig_func(*args, **kwargs)

            ssl._create_unverified_context = traced_create_unverified_context

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import ssl
        if self._orig_create_unverified_context:
            ssl._create_unverified_context = self._orig_create_unverified_context


# ---------------------------------------------------------------------------
# CWE-552: Files or Directories Accessible to External Parties (Sensitive Files Access)
# ---------------------------------------------------------------------------

SENSITIVE_FILE_PATTERNS = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts",
    ".env", ".git/config", ".aws/credentials", ".ssh/id_rsa",
    ".ssh/id_ed25519", "id_rsa", "config.json", ".kube/config"
]

def check_introspection_sensitive_file_access(accessed_files: List[str]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Sensitive Files/Directories Access (CWE-552).
    Monitors file read/write operations during tool execution and alerts if sensitive system,
    credential, or configuration files are accessed.
    
    :param accessed_files: List of file paths accessed during tool execution.
    """
    if not accessed_files:
        return False, ""

    for file_path in accessed_files:
        norm_path = os.path.normpath(file_path).lower()
        for sensitive_pattern in SENSITIVE_FILE_PATTERNS:
            if sensitive_pattern in norm_path or norm_path.endswith(sensitive_pattern):
                return True, (
                    f"Introspection Sensitive File Access Alert (CWE-552): Access to sensitive file or credential resource detected! "
                    f"Accessed path: '{file_path}' (Matched pattern: '{sensitive_pattern}')."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-1327: Binding to an Unrestricted IP Address
# ---------------------------------------------------------------------------

def check_introspection_unrestricted_ip_binding(bound_addresses: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Binding to an Unrestricted IP Address (CWE-1327).
    Monitors socket bind operations during tool execution and flags socket servers bound
    to unrestricted wildcards ('0.0.0.0', '::', '') exposing services to the entire local network/internet.
    
    :param bound_addresses: List of socket bind event dicts.
    """
    if not bound_addresses:
        return False, ""

    for record in bound_addresses:
        host = str(record.get("host", ""))
        port = record.get("port", 0)
        
        if host in ["0.0.0.0", "::", "", "0"]:
            return True, (
                f"Introspection Unrestricted IP Binding Alert (CWE-1327): Network socket bound to unrestricted IP interface '{host}:{port}'! "
                f"Tool server is exposed to all network interfaces instead of loopback (127.0.0.1)."
            )

    return False, ""


class UnrestrictedIPBindingTracer:
    """
    Traces socket.bind invocations to detect unrestricted interface binding (0.0.0.0 / ::).
    """
    def __init__(self):
        self.bound_addresses = []
        self._orig_bind = None

    def __enter__(self):
        import socket
        self.bound_addresses = []
        self._orig_bind = socket.socket.bind
        orig_bind = self._orig_bind
        tracer_self = self

        def traced_bind(socket_self, address):
            try:
                if isinstance(address, tuple) and len(address) >= 2:
                    host, port = address[0], address[1]
                    tracer_self.bound_addresses.append({
                        "host": str(host),
                        "port": port
                    })
            except Exception:
                pass
            return orig_bind(socket_self, address)

        socket.socket.bind = traced_bind
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import socket
        if self._orig_bind:
            socket.socket.bind = self._orig_bind


# ---------------------------------------------------------------------------
# CWE-1333: Inefficient Regular Expression Complexity (ReDoS)
# ---------------------------------------------------------------------------

def check_introspection_redos(slow_regex_calls: List[dict], threshold_ms: float = 200.0) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Inefficient Regular Expression Complexity / ReDoS (CWE-1333).
    Monitors execution time of regular expression evaluations (re.search, re.match, re.findall, re.sub)
    and alerts if a regex execution exceeds the duration threshold due to catastrophic backtracking.
    
    :param slow_regex_calls: List of regex execution timing records.
    :param threshold_ms: Time threshold in milliseconds to flag catastrophic backtracking.
    """
    if not slow_regex_calls:
        return False, ""

    for record in slow_regex_calls:
        pattern = record.get("pattern", "")
        duration_ms = record.get("duration_ms", 0.0)
        func = record.get("function", "re")
        
        if duration_ms >= threshold_ms:
            return True, (
                f"Introspection ReDoS Alert (CWE-1333): Catastrophic backtracking / excessive ReDoS execution time detected in '{func}'! "
                f"Pattern: '{pattern}', Duration: {duration_ms:.2f} ms (Threshold: {threshold_ms} ms)."
            )

    return False, ""


class ReDoSTracer:
    """
    Traces Python re module functions (re.search, re.match, re.findall, re.finditer, re.sub)
    and measures execution time of each regex evaluation to catch ReDoS vulnerabilities.
    """
    def __init__(self, threshold_ms: float = 200.0):
        self.slow_regex_calls = []
        self.threshold_ms = threshold_ms
        self._orig_search = None
        self._orig_match = None
        self._orig_findall = None
        self._orig_sub = None

    def __enter__(self):
        import re
        import time
        self.slow_regex_calls = []
        tracer_self = self

        self._orig_search = re.search
        self._orig_match = re.match
        self._orig_findall = re.findall
        self._orig_sub = re.sub

        orig_search = self._orig_search
        orig_match = self._orig_match
        orig_findall = self._orig_findall
        orig_sub = self._orig_sub

        def make_traced_func(orig_func, name):
            def traced_fn(pattern, string, *args, **kwargs):
                start = time.perf_counter()
                try:
                    return orig_func(pattern, string, *args, **kwargs)
                finally:
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    pat_str = str(pattern.pattern if hasattr(pattern, "pattern") else pattern)
                    if elapsed_ms >= tracer_self.threshold_ms:
                        tracer_self.slow_regex_calls.append({
                            "function": f"re.{name}",
                            "pattern": pat_str,
                            "duration_ms": elapsed_ms
                        })
            return traced_fn

        re.search = make_traced_func(orig_search, "search")
        re.match = make_traced_func(orig_match, "match")
        re.findall = make_traced_func(orig_findall, "findall")
        re.sub = make_traced_func(orig_sub, "sub")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import re
        if self._orig_search:
            re.search = self._orig_search
        if self._orig_match:
            re.match = self._orig_match
        if self._orig_findall:
            re.findall = self._orig_findall
        if self._orig_sub:
            re.sub = self._orig_sub


# ---------------------------------------------------------------------------
# CWE-1322: Use of Blocking Code in Single-threaded, Non-blocking Context
# ---------------------------------------------------------------------------

def check_introspection_blocking_event_loop_call(blocking_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Blocking Code in Single-threaded Context (CWE-1322).
    Monitors synchronous blocking calls (e.g. time.sleep, requests.get) executed inside an
    asyncio event loop context during tool execution, which causes event loop freezes/DoS.
    
    :param blocking_calls: List of blocking call event records.
    """
    if not blocking_calls:
        return False, ""

    for record in blocking_calls:
        func_name = record.get("function", "blocking_op")
        details = record.get("details", "")
        return True, (
            f"Introspection Blocking Call Alert (CWE-1322): Synchronous blocking operation '{func_name}' executed inside an active Event Loop context! "
            f"Details: {details}. This blocks the single-threaded event loop and freezes the MCP server."
        )

    return False, ""


class BlockingEventLoopCallTracer:
    """
    Traces synchronous blocking functions (time.sleep) executed within an active asyncio event loop context.
    """
    def __init__(self):
        self.blocking_calls = []
        self._orig_sleep = None

    def __enter__(self):
        import time
        import asyncio
        self.blocking_calls = []
        self._orig_sleep = time.sleep
        orig_sleep = self._orig_sleep
        tracer_self = self

        def traced_sleep(seconds):
            try:
                # Check if an asyncio event loop is running in the current thread
                try:
                    loop = asyncio.get_running_loop()
                    if loop and loop.is_running():
                        tracer_self.blocking_calls.append({
                            "function": "time.sleep",
                            "details": f"time.sleep({seconds}) called inside running asyncio loop"
                        })
                except RuntimeError:
                    # No running loop in this thread
                    pass
            except Exception:
                pass
            return orig_sleep(seconds)

        time.sleep = traced_sleep
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        if self._orig_sleep:
            time.sleep = self._orig_sleep


# ---------------------------------------------------------------------------
# CWE-798: Use of Hard-coded Credentials
# ---------------------------------------------------------------------------

HARDCODED_SECRET_PATTERNS = [
    r"sk-(?:proj-)?[a-zA-Z0-9]{16,}", # OpenAI / Generic Secret Key
    r"ghp_[a-zA-Z0-9]{30,}",          # GitHub Personal Access Token
    r"AKIA[0-9A-Z]{16}",              # AWS Access Key ID
    r"AIzaSy[a-zA-Z0-9_-]{33}",       # Google API Key
    r"bearer\s+[a-zA-Z0-9_\-\.]{20,}" # Bearer Token
]

def check_introspection_hardcoded_credentials(executed_strings: List[str]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Use of Hard-coded Credentials (CWE-798).
    Monitors string constants, network parameters, and logs executed during tool runtime
    to detect embedded hard-coded API keys, tokens, or credential secrets.
    
    :param executed_strings: List of runtime strings captured during tool execution.
    """
    if not executed_strings:
        return False, ""

    import re
    for text in executed_strings:
        if not text or not isinstance(text, str):
            continue
        for pattern in HARDCODED_SECRET_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                secret_snippet = match.group(0)
                # Mask secret snippet for output safety
                masked = secret_snippet[:4] + "..." + secret_snippet[-4:] if len(secret_snippet) > 8 else "***"
                return True, (
                    f"Introspection Hard-coded Credentials Alert (CWE-798): Hard-coded API key or credential secret detected in runtime execution! "
                    f"Secret pattern matched: '{pattern}' (Sample: '{masked}')."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-328: Use of Weak Hash
# ---------------------------------------------------------------------------

def check_introspection_weak_hash(weak_hash_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Use of Weak Hash Algorithm (CWE-328).
    Monitors hashlib operations during tool execution and flags uses of broken/deprecated
    hashing algorithms like MD5 or SHA-1.
    
    :param weak_hash_calls: List of weak hash call event dicts.
    """
    if not weak_hash_calls:
        return False, ""

    for record in weak_hash_calls:
        algo = record.get("algorithm", "unknown")
        return True, (
            f"Introspection Weak Hash Alert (CWE-328): Cryptographically broken or deprecated hash algorithm '{algo.upper()}' used during tool execution! "
            f"Migrate to SHA-256, SHA-512, or Argon2/bcrypt for credential hashing."
        )

    return False, ""


class WeakHashTracer:
    """
    Traces hashlib invocations (hashlib.md5, hashlib.sha1, hashlib.new) to catch weak hash usage.
    """
    def __init__(self):
        self.weak_hash_calls = []
        self._orig_md5 = None
        self._orig_sha1 = None
        self._orig_new = None

    def __enter__(self):
        import hashlib
        self.weak_hash_calls = []
        tracer_self = self

        self._orig_md5 = hashlib.md5
        self._orig_sha1 = hashlib.sha1
        self._orig_new = hashlib.new

        orig_md5 = self._orig_md5
        orig_sha1 = self._orig_sha1
        orig_new = self._orig_new

        def traced_md5(*args, **kwargs):
            tracer_self.weak_hash_calls.append({"algorithm": "md5"})
            return orig_md5(*args, **kwargs)

        def traced_sha1(*args, **kwargs):
            tracer_self.weak_hash_calls.append({"algorithm": "sha1"})
            return orig_sha1(*args, **kwargs)

        def traced_new(name, *args, **kwargs):
            algo_name = str(name).lower()
            if algo_name in ["md5", "sha1"]:
                tracer_self.weak_hash_calls.append({"algorithm": algo_name})
            return orig_new(name, *args, **kwargs)

        hashlib.md5 = traced_md5
        hashlib.sha1 = traced_sha1
        hashlib.new = traced_new
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import hashlib
        if self._orig_md5:
            hashlib.md5 = self._orig_md5
        if self._orig_sha1:
            hashlib.sha1 = self._orig_sha1
        if self._orig_new:
            hashlib.new = self._orig_new


# ---------------------------------------------------------------------------
# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
# ---------------------------------------------------------------------------

def check_introspection_weak_prng(weak_prng_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Use of Weak PRNG (CWE-338).
    Monitors pseudo-random generation during tool execution and flags uses of non-cryptographic
    PRNGs (random module) when generating security tokens or secrets.
    
    :param weak_prng_calls: List of weak PRNG call event dicts.
    """
    if not weak_prng_calls:
        return False, ""

    for record in weak_prng_calls:
        func_name = record.get("function", "random")
        return True, (
            f"Introspection Weak PRNG Alert (CWE-338): Cryptographically insecure pseudo-random number generator 'random.{func_name}' used! "
            f"Use the 'secrets' or 'os.urandom()' module for security tokens, passwords, and cryptographic keys."
        )

    return False, ""


class WeakPRNGTracer:
    """
    Traces random module invocations (randint, choice, random, randbytes) during tool execution.
    """
    def __init__(self):
        self.weak_prng_calls = []
        self._orig_randint = None
        self._orig_choice = None

    def __enter__(self):
        import random
        self.weak_prng_calls = []
        tracer_self = self

        self._orig_randint = random.randint
        self._orig_choice = random.choice

        orig_randint = self._orig_randint
        orig_choice = self._orig_choice

        def traced_randint(*args, **kwargs):
            tracer_self.weak_prng_calls.append({"function": "randint"})
            return orig_randint(*args, **kwargs)

        def traced_choice(*args, **kwargs):
            tracer_self.weak_prng_calls.append({"function": "choice"})
            return orig_choice(*args, **kwargs)

        random.randint = traced_randint
        random.choice = traced_choice
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import random
        if self._orig_randint:
            random.randint = self._orig_randint
        if self._orig_choice:
            random.choice = self._orig_choice


# ---------------------------------------------------------------------------
# CWE-323: Reusing a Nonce, Key Pair in Encryption
# ---------------------------------------------------------------------------

def check_introspection_nonce_reuse(reused_nonces: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Reusing a Nonce/IV in Encryption (CWE-323).
    Monitors cryptographic Nonces / Initialization Vectors (IVs) used during tool execution
    and alerts if a static/duplicate Nonce is reused across encryption operations.
    
    :param reused_nonces: List of reused Nonce event records.
    """
    if not reused_nonces:
        return False, ""

    for record in reused_nonces:
        nonce_val = record.get("nonce", "")
        return True, (
            f"Introspection Nonce Reuse Alert (CWE-323): Cryptographic Nonce/IV reuse detected! "
            f"Static/duplicate Nonce value '{nonce_val}' was reused across multiple cipher operations, ruining encryption security."
        )

    return False, ""


class NonceReuseTracer:
    """
    Traces Nonce/IV usage in cryptographic operations to catch static or duplicate Nonce reuse.
    """
    def __init__(self):
        self.seen_nonces = set()
        self.reused_nonces = []

    def record_nonce(self, nonce_bytes: bytes):
        if not nonce_bytes:
            return
        hex_nonce = nonce_bytes.hex() if isinstance(nonce_bytes, (bytes, bytearray)) else str(nonce_bytes)
        if hex_nonce in self.seen_nonces:
            self.reused_nonces.append({"nonce": hex_nonce})
        else:
            self.seen_nonces.add(hex_nonce)

    def __enter__(self):
        self.seen_nonces = set()
        self.reused_nonces = []
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# CWE-494: Download of Code Without Integrity Check
# ---------------------------------------------------------------------------

CODE_FILE_EXTENSIONS = [".py", ".sh", ".bash", ".bin", ".elf", ".so", ".whl", ".exe", ".dll", ".js"]

def check_introspection_unverified_code_download(unverified_downloads: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Download of Code Without Integrity Check (CWE-494).
    Monitors remote code/executable file downloads during tool execution and flags instances
    where code/executable files are downloaded and written to disk without cryptographic hash/signature verification.
    
    :param unverified_downloads: List of unverified code download event records.
    """
    if not unverified_downloads:
        return False, ""

    for record in unverified_downloads:
        url = record.get("url", "")
        dest = record.get("destination", "")
        return True, (
            f"Introspection Unverified Code Download Alert (CWE-494): Executable code/script downloaded from '{url}' "
            f"and saved to '{dest}' without cryptographic integrity verification (SHA-256 / signature)! Risk of Remote Code Execution."
        )

    return False, ""


class UnverifiedCodeDownloadTracer:
    """
    Traces file writes and network downloads to catch unverified code file downloads.
    """
    def __init__(self):
        self.unverified_downloads = []

    def record_download(self, url: str, destination: str):
        if not url or not destination:
            return
        dest_lower = destination.lower()
        if any(dest_lower.endswith(ext) for ext in CODE_FILE_EXTENSIONS):
            self.unverified_downloads.append({
                "url": url,
                "destination": destination
            })

    def __enter__(self):
        self.unverified_downloads = []
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# CWE-611 / CWE-776: XML External Entity (XXE) & XML Entity Expansion
# ---------------------------------------------------------------------------

def check_introspection_xxe(xxe_calls: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for XML External Entity (XXE) & Entity Expansion (CWE-611 / CWE-776).
    Monitors XML parsing operations during tool execution and flags resolution of external entities
    or recursive entity expansions accessing local files or remote URLs.
    
    :param xxe_calls: List of XXE event records.
    """
    if not xxe_calls:
        return False, ""

    for record in xxe_calls:
        target = record.get("target", "")
        return True, (
            f"Introspection XXE Alert (CWE-611/CWE-776): XML External Entity or Entity Expansion detected during XML parsing! "
            f"Accessed resource: '{target}'. Risk of Arbitrary File Read / Denial of Service."
        )

    return False, ""


class XXETracer:
    """
    Traces XML parsing functions (xml.etree.ElementTree, minidom) during tool execution.
    """
    def __init__(self):
        self.xxe_calls = []

    def record_xxe(self, target_resource: str):
        if target_resource:
            self.xxe_calls.append({"target": str(target_resource)})

    def __enter__(self):
        self.xxe_calls = []
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# CWE-409: Data Amplification / Zip Bomb / Decompression Bomb
# ---------------------------------------------------------------------------

def check_introspection_data_amplification(amplification_calls: List[dict], max_ratio: float = 100.0) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Data Amplification / Zip Bomb (CWE-409).
    Monitors decompression operations (zipfile, gzip, zlib, bz2) during tool execution
    and alerts if uncompressed output size is massively amplified compared to compressed input size.
    
    :param amplification_calls: List of decompression event records.
    :param max_ratio: Maximum allowed ratio of uncompressed vs compressed size.
    """
    if not amplification_calls:
        return False, ""

    for record in amplification_calls:
        comp_size = record.get("compressed_size", 1)
        decomp_size = record.get("decompressed_size", 0)
        ratio = decomp_size / max(comp_size, 1)
        
        if ratio >= max_ratio or decomp_size > 100 * 1024 * 1024:  # > 100 MB decompressed
            return True, (
                f"Introspection Data Amplification / Zip Bomb Alert (CWE-409): Excessive decompression ratio ({ratio:.1f}x) detected! "
                f"Compressed input: {comp_size} bytes -> Decompressed output: {decomp_size} bytes. Risk of Memory Exhaustion DoS."
            )

    return False, ""


class DataAmplificationTracer:
    """
    Traces decompression functions (zlib.decompress, gzip.decompress, zipfile.ZipFile.read) to catch Zip Bombs.
    """
    def __init__(self):
        self.amplification_calls = []

    def record_decompression(self, compressed_bytes: int, decompressed_bytes: int):
        self.amplification_calls.append({
            "compressed_size": compressed_bytes,
            "decompressed_size": decompressed_bytes
        })

    def __enter__(self):
        self.amplification_calls = []
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# CWE-88: Argument Injection (Option / Flag Injection in Commands)
# ---------------------------------------------------------------------------

DANGEROUS_CLI_FLAGS = ["--config", "--upload-pack", "--output", "-o", "--use-askpass", "-e", "--eval"]

def check_introspection_argument_injection(executed_commands: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Argument Injection / Flag Injection (CWE-88).
    Monitors process execution arguments and alerts if unneutralized user input injects CLI options/flags
    (e.g., --config, --upload-pack, -o) into external command-line tools.
    
    :param executed_commands: List of executed command event records.
    """
    if not executed_commands:
        return False, ""

    for cmd_record in executed_commands:
        cmd_str = cmd_record.get("command", "")
        # Check if command string or arguments contain injected flags in positional slots
        for flag in DANGEROUS_CLI_FLAGS:
            if f" {flag}=" in cmd_str or f" {flag} " in cmd_str or cmd_str.endswith(f" {flag}"):
                return True, (
                    f"Introspection Argument Injection Alert (CWE-88): Dangerous CLI option/flag injection '{flag}' detected in executed command! "
                    f"Command: '{cmd_str}'."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-1236: Improper Neutralization of Formula Elements in a CSV File (CSV Injection)
# ---------------------------------------------------------------------------

FORMULA_PREFIXES = ("=", "+", "-", "@", "|", "\t", "\r")

def check_introspection_csv_formula_injection(written_files: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for CSV Formula Injection (CWE-1236).
    Monitors file writes to .csv and .tsv files during tool execution and alerts if any cell value
    begins with formula execution characters (=, +, -, @, |).
    
    :param written_files: List of written file event records.
    """
    if not written_files:
        return False, ""

    for record in written_files:
        path = record.get("path", "") if isinstance(record, dict) else str(record)
        content = record.get("content", "") if isinstance(record, dict) else ""
        
        # If content wasn't stored in record dict, check if file exists and read it
        if path.lower().endswith((".csv", ".tsv")):
            if not content and os.path.exists(path):
                try:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    pass

            if isinstance(content, (bytes, bytearray)):
                content = content.decode("utf-8", errors="ignore")

            lines = content.splitlines() if isinstance(content, str) else []
            for line in lines:
                cells = line.split(",") if path.endswith(".csv") else line.split("\t")
                for cell in cells:
                    cell_clean = cell.strip("'\" ")
                    if cell_clean.startswith(FORMULA_PREFIXES):
                        return True, (
                            f"Introspection CSV Formula Injection Alert (CWE-1236): Unneutralized formula element '{cell_clean[:10]}' "
                            f"written to spreadsheet file '{path}'! Risk of client-side macro execution."
                        )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-59: Improper Link Resolution Before File Access ('Link Following')
# ---------------------------------------------------------------------------

def check_introspection_symlink_following(accessed_files: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Link Following / Symlink Traversal (CWE-59).
    Monitors file system accesses and alerts if the tool accesses a symbolic link (symlink)
    pointing to sensitive target files outside allowed directories.
    
    :param accessed_files: List of accessed file event records.
    """
    if not accessed_files:
        return False, ""

    for record in accessed_files:
        path = record.get("path", "") if isinstance(record, dict) else str(record)
        if path and os.path.islink(path):
            real_target = os.path.realpath(path)
            return True, (
                f"Introspection Symlink Following Alert (CWE-59): Tool followed a symbolic link '{path}' "
                f"pointing to real target '{real_target}'! Risk of arbitrary file disclosure or corruption via Symlink Traversal."
            )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-378 / CWE-379: Creation of Temporary File With Insecure Permissions
# ---------------------------------------------------------------------------

def check_introspection_insecure_temp_permissions(written_files: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Creation of Temporary File With Insecure Permissions (CWE-378/379).
    Monitors temporary files created during tool execution and alerts if permissions are world-readable/writable.
    
    :param written_files: List of written file event records.
    """
    if not written_files:
        return False, ""

    for record in written_files:
        path = record.get("path", "") if isinstance(record, dict) else str(record)
        if path and ("/tmp/" in path or "/var/tmp/" in path):
            try:
                st = os.stat(path)
                mode = st.st_mode
                # Check if world-readable (0o004) or world-writable (0o002)
                if (mode & 0o004) or (mode & 0o002) or (mode & 0o077 == 0o077):
                    octal_permissions = oct(mode & 0o777)
                    return True, (
                        f"Introspection Insecure Temp File Permissions Alert (CWE-378/379): Temporary file '{path}' "
                        f"was created with overly permissive file permissions ({octal_permissions})! Risk of local data leakage or tampering."
                    )
            except Exception:
                pass

    return False, ""


# ---------------------------------------------------------------------------
# CWE-209: Generation of Error Message Containing Sensitive Information
# ---------------------------------------------------------------------------

SENSITIVE_ERROR_PATTERNS = [
    (r"sk-proj-[a-zA-Z0-9_\-]{20,}", "OpenAI API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"AIzaSy[a-zA-Z0-9_\-]{33}", "Google API Key"),
    (r"/home/[a-zA-Z0-9_\-]+/\.ssh/id_[a-zA-Z0-9_]+", "Private SSH Key File Path"),
    (r"mysql://[a-zA-Z0-9_]+:[^@]+@", "MySQL Database Credentials"),
    (r"postgres://[a-zA-Z0-9_]+:[^@]+@", "PostgreSQL Database Credentials"),
]

def check_introspection_sensitive_error_leak(error_text: str) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Sensitive Information Leak in Error Messages (CWE-209).
    Monitors error responses, exception messages, and stack traces returned by tool execution
    and alerts if unredacted sensitive keys, internal file paths, or credentials are disclosed.
    
    :param error_text: Error message or stack trace text.
    """
    if not error_text or not isinstance(error_text, str):
        return False, ""

    for pattern, label in SENSITIVE_ERROR_PATTERNS:
        match = re.search(pattern, error_text)
        if match:
            leaked_val = match.group(0)
            return True, (
                f"Introspection Sensitive Error Leak Alert (CWE-209): Tool error output/stack trace disclosed {label}! "
                f"Leaked Pattern: '{leaked_val[:12]}...'. Risk of Information Disclosure."
            )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-617: Reachable Assertion (Assertion Failure DoS)
# ---------------------------------------------------------------------------

def check_introspection_reachable_assertion(error_text: str) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Reachable Assertion (CWE-617).
    Monitors tool execution errors and alerts if an untrusted fuzzed input triggers an unhandled
    AssertionError in production code causing Denial of Service.
    
    :param error_text: Exception/error message string.
    """
    if not error_text or not isinstance(error_text, str):
        return False, ""

    if "AssertionError" in error_text or "assert " in error_text:
        return True, (
            f"Introspection Reachable Assertion Alert (CWE-617): Fuzzed input triggered a production AssertionError! "
            f"Error details: '{error_text[:100]}'. Risk of Denial of Service (DoS)."
        )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-312 / CWE-538: Cleartext Storage of Sensitive Information
# ---------------------------------------------------------------------------

def check_introspection_cleartext_sensitive_storage(written_files: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Cleartext Storage of Sensitive Information (CWE-312 / CWE-538).
    Monitors files written during tool execution and alerts if sensitive credentials, API keys, or tokens
    are written to disk in plain text without encryption.
    
    :param written_files: List of written file event records.
    """
    if not written_files:
        return False, ""

    for record in written_files:
        path = record.get("path", "") if isinstance(record, dict) else str(record)
        content = record.get("content", "") if isinstance(record, dict) else ""
        if not content and os.path.exists(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    content = f.read()
            except Exception:
                pass

        if isinstance(content, str) and content:
            for pattern, label in SENSITIVE_ERROR_PATTERNS:
                match = re.search(pattern, content)
                if match:
                    return True, (
                        f"Introspection Cleartext Storage Alert (CWE-312/538): Tool saved unencrypted {label} "
                        f"in cleartext to file '{path}'! Leaked pattern: '{match.group(0)[:12]}...'."
                    )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-319: Cleartext Transmission of Sensitive Information
# ---------------------------------------------------------------------------

def check_introspection_cleartext_sensitive_transmission(network_connections: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Cleartext Transmission of Sensitive Information (CWE-319).
    Monitors outgoing network connections and requests to detect sensitive tokens or credentials
    transmitted over unencrypted HTTP channels (http://).
    
    :param network_connections: List of network connection event records.
    """
    if not network_connections:
        return False, ""

    for conn in network_connections:
        url = conn.get("url", "") if isinstance(conn, dict) else str(conn)
        if url.startswith("http://") and not url.startswith("http://localhost") and not url.startswith("http://127.0.0.1"):
            # Check if URL contains sensitive query parameters (token=, key=, secret=)
            if any(p in url.lower() for p in ["token=", "key=", "secret=", "password=", "api_key="]):
                return True, (
                    f"Introspection Cleartext Transmission Alert (CWE-319): Sensitive credential/token "
                    f"transmitted in cleartext over unencrypted channel '{url}'! Risk of Man-in-the-Middle (MitM) interception."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-455: Non-exit on Failed Initialization
# ---------------------------------------------------------------------------

INIT_FAILURE_KEYWORDS = [
    "initialization failed",
    "failed to initialize",
    "failed to load security config",
    "failed to authenticate init",
    "ssl init error",
    "auth failed during startup",
    "init error swallowed"
]

def check_introspection_failed_init_non_exit(tool_success: bool, logged_messages: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Non-exit on Failed Initialization (CWE-455).
    Monitors execution logs and tool status to detect if an initialization error occurred,
    yet execution continued and completed with success=True without exiting/aborting safely.
    
    :param tool_success: Boolean indicating if the tool call returned success.
    :param logged_messages: List of logged message records during execution.
    """
    if not tool_success or not logged_messages:
        return False, ""

    for record in logged_messages:
        msg = record.get("message", "") if isinstance(record, dict) else str(record)
        msg_lower = msg.lower()
        for kw in INIT_FAILURE_KEYWORDS:
            if kw in msg_lower:
                return True, (
                    f"Introspection Non-exit on Failed Init Alert (CWE-455): Initialization error '{msg}' occurred "
                    f"during execution, but tool continued and returned success=True without failing safely!"
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-459: Incomplete Cleanup / Resource Leak
# ---------------------------------------------------------------------------

def check_introspection_incomplete_cleanup(leaked_temp_files: List[str]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Incomplete Cleanup (CWE-459).
    Monitors leftover temporary files, open file descriptors, or zombie resources left behind after tool execution.
    
    :param leaked_temp_files: List of leaked temporary files/resources detected.
    """
    if not leaked_temp_files:
        return False, ""

    return True, (
        f"Introspection Incomplete Cleanup Alert (CWE-459): Tool execution finished but left {len(leaked_temp_files)} "
        f"uncleaned temporary resource(s) on disk: {leaked_temp_files[:3]}! Risk of resource exhaustion / disk leakage."
    )


# ---------------------------------------------------------------------------
# CWE-606: Unchecked Input for Loop Condition
# ---------------------------------------------------------------------------

def check_introspection_unchecked_loop_condition(loop_iterations: int, max_iterations: int = 100000) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Unchecked Input for Loop Condition (CWE-606).
    Monitors loop iteration counts during tool execution and alerts if an unchecked fuzzed input
    causes an excessively high loop count, threatening Denial of Service / CPU exhaustion.
    
    :param loop_iterations: Total number of loop iterations recorded.
    :param max_iterations: Maximum allowed safe iterations threshold.
    """
    if loop_iterations and loop_iterations >= max_iterations:
        return True, (
            f"Introspection Unchecked Loop Condition Alert (CWE-606): Unchecked user input caused "
            f"excessive loop iterations ({loop_iterations} >= {max_iterations})! Risk of CPU Exhaustion / Denial of Service."
        )

    return False, ""


class LoopConditionTracer:
    """
    Traces loop iterations during Python tool execution.
    """
    def __init__(self):
        self.loop_count = 0

    def increment(self, count: int = 1):
        self.loop_count += count

    def __enter__(self):
        self.loop_count = 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# CWE-120 / CWE-787 / CWE-125: Memory Access Violation / Buffer Overflow
# ---------------------------------------------------------------------------

MEMORY_CRASH_SIGNALS = [
    "segmentation fault",
    "sigsegv",
    "sigbus",
    "bus error",
    "memoryerror",
    "buffererror",
    "pointer error",
    "fatal memory corruption"
]

def check_introspection_memory_access_violation(exit_code: int = 0, error_text: str = "") -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Buffer Overflow / Memory Access Violation (CWE-120 / CWE-787 / CWE-125).
    Monitors process exit codes and process error streams for native memory corruption signals
    (Segmentation fault, SIGSEGV, SIGBUS, MemoryError) caused by fuzzed inputs.
    
    :param exit_code: Process exit code returned by execution.
    :param error_text: Error output or stderr text from tool execution.
    """
    # Check negative exit codes (killed by signal in Unix, e.g., -11 for SIGSEGV, -7 for SIGBUS)
    if exit_code in (-11, -7, 139, 135):
        signal_name = "SIGSEGV (Segmentation Fault)" if exit_code in (-11, 139) else "SIGBUS (Bus Error)"
        return True, (
            f"Introspection Memory Access Violation Alert (CWE-120/787): Fuzzed input killed process with "
            f"native signal {exit_code} [{signal_name}]! Memory corruption / buffer overflow detected."
        )

    if error_text and isinstance(error_text, str):
        err_lower = error_text.lower()
        for pattern in MEMORY_CRASH_SIGNALS:
            if pattern in err_lower:
                return True, (
                    f"Introspection Memory Access Violation Alert (CWE-120/787): Fuzzed input caused memory error "
                    f"'{pattern}' in output: '{error_text[:100]}'. Risk of Buffer Overflow / Out-of-Bounds Access."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-369: Divide By Zero
# ---------------------------------------------------------------------------

def check_introspection_divide_by_zero(error_text: str = "") -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Divide By Zero (CWE-369).
    Monitors process exception messages and error output for unhandled ZeroDivisionError
    crashes caused by fuzzed inputs setting a denominator to 0.
    
    :param error_text: Exception/error message string.
    """
    if not error_text or not isinstance(error_text, str):
        return False, ""

    err_lower = error_text.lower()
    if "zerodivisionerror" in err_lower or "division by zero" in err_lower or "divisionbyzero" in err_lower:
        return True, (
            f"Introspection Divide By Zero Alert (CWE-369): Fuzzed input triggered unhandled "
            f"ZeroDivisionError! Error details: '{error_text[:100]}'. Risk of Denial of Service (DoS)."
        )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-276 / CWE-279: Incorrect Default / Excessive File Permissions
# ---------------------------------------------------------------------------

def check_introspection_insecure_file_permissions(written_files: List[dict]) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Incorrect Default Permissions (CWE-276 / CWE-279).
    Monitors all files or directories created/modified during tool execution and alerts if
    permissions are overly permissive (world-writable or world-readable, e.g., 0o777, 0o666, 0o775).
    
    :param written_files: List of written file event records.
    """
    if not written_files:
        return False, ""

    for record in written_files:
        path = record.get("path", "") if isinstance(record, dict) else str(record)
        mode = record.get("mode", None) if isinstance(record, dict) else None
        
        if not isinstance(mode, int) and path and os.path.exists(path):
            try:
                mode = os.stat(path).st_mode
            except Exception:
                mode = None

        if isinstance(mode, int):
            # Mask out file type bits to get permissions
            perms = mode & 0o777
            # Alert if world-writable (o+w / 0o002) or world-readable (o+r / 0o004) or 0o777/0o666
            if perms in (0o777, 0o666, 0o775, 0o664) or (perms & 0o002) != 0:
                return True, (
                    f"Introspection Insecure File Permissions Alert (CWE-276/279): Tool created/modified file "
                    f"'{path}' with insecure permissive mode octal '{oct(perms)}'! Risk of Unauthorized Data Access / Modification."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-250 / CWE-272: Execution with Unnecessary Privileges / Least Privilege Violation
# ---------------------------------------------------------------------------

ELEVATED_CMD_PREFIXES = ["sudo ", "su ", "doas ", "pkexec "]

def check_introspection_unnecessary_root_privileges(executed_commands: List[str] = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Execution with Unnecessary Privileges (CWE-250 / CWE-272).
    Monitors process effective UID / EUID and executed sub-commands to detect if a tool MCP
    runs with superuser (root) privileges or attempts to escalate privileges via sudo/su/doas.
    
    :param executed_commands: List of shell commands executed during tool run.
    """
    # Check process Effective User ID (EUID) on Unix systems
    if hasattr(os, "geteuid"):
        try:
            if os.geteuid() == 0:
                return True, (
                    f"Introspection Unnecessary Privileges Alert (CWE-250/272): Tool process is running "
                    f"with Effective EUID=0 (root)! Violation of Least Privilege principle."
                )
        except Exception:
            pass

    if executed_commands:
        for cmd in executed_commands:
            cmd_str = cmd.get("cmd", "") if isinstance(cmd, dict) else str(cmd)
            cmd_lower = cmd_str.lower().strip()
            for prefix in ELEVATED_CMD_PREFIXES:
                if cmd_lower.startswith(prefix) or f" {prefix}" in cmd_lower:
                    return True, (
                        f"Introspection Unnecessary Privileges Alert (CWE-250/272): Tool attempted privilege escalation "
                        f"by invoking elevated command '{cmd_str[:60]}...'! Risk of System Compromise."
                    )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-833: Deadlock / Thread Lock Hang
# ---------------------------------------------------------------------------

def check_introspection_deadlock(is_timed_out: bool = False, active_locks_count: int = 0) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Deadlock (CWE-833).
    Monitors thread lock states and execution timeouts to detect if concurrent locks/mutexes
    caused a deadlock condition during tool execution.
    
    :param is_timed_out: Boolean indicating if tool execution timed out / hung.
    :param active_locks_count: Number of unreleased/held locks detected at timeout.
    """
    if is_timed_out and active_locks_count > 0:
        return True, (
            f"Introspection Deadlock Alert (CWE-833): Tool execution timed out with {active_locks_count} "
            f"unreleased thread lock(s) held! Risk of Deadlock / Thread Lock Hang DoS."
        )
    elif is_timed_out:
        return True, (
            f"Introspection Deadlock Alert (CWE-833): Tool execution hung / timed out due to unhandled "
            f"blocking operation or deadlock! Risk of Denial of Service."
        )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-403 / CWE-910: File Descriptor Leak / Use of Expired FD
# ---------------------------------------------------------------------------

def check_introspection_file_descriptor_leak(open_fds_count: int = 0, leaked_fds: List[int] = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for File Descriptor Leak (CWE-403 / CWE-910).
    Monitors open file descriptors before and after tool execution to alert if files, sockets,
    or pipes were opened and not properly closed.
    
    :param open_fds_count: Number of leaked file descriptors.
    :param leaked_fds: List of leaked FD integers/paths.
    """
    if open_fds_count > 0 or leaked_fds:
        count = open_fds_count or len(leaked_fds)
        return True, (
            f"Introspection File Descriptor Leak Alert (CWE-403/910): Tool execution finished but leaked "
            f"{count} open file descriptor(s) [FDs: {leaked_fds[:3] if leaked_fds else 'N/A'}]! "
            f"Risk of FD Exhaustion / EMFILE crash."
        )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-915: Prototype Pollution / Object Attribute Injection
# ---------------------------------------------------------------------------

POLLUTION_KEYS = ["__proto__", "constructor.prototype", "prototype", "__class__", "__base__", "__subclasses__"]

def check_introspection_prototype_pollution(input_payload: Any = None, modified_objects: List[str] = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Prototype Pollution / Dynamic Attribute Modification (CWE-915).
    Monitors input payloads and object mutation events to detect attempts to pollute object prototypes
    or inject dangerous class attributes.
    
    :param input_payload: Target input payload or object dictionary.
    :param modified_objects: List of modified attribute names or paths.
    """
    payload_str = str(input_payload) if input_payload is not None else ""
    
    for key in POLLUTION_KEYS:
        if key in payload_str:
            return True, (
                f"Introspection Prototype Pollution Alert (CWE-915): Input payload contains reserved object "
                f"attribute key '{key}'! Risk of Prototype Pollution / Remote Code Execution."
            )

    if modified_objects:
        for obj_path in modified_objects:
            if any(k in str(obj_path) for k in POLLUTION_KEYS):
                return True, (
                    f"Introspection Prototype Pollution Alert (CWE-915): Dynamically modified object "
                    f"attribute path '{obj_path}' targets prototype / class internals!"
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-15: External Control of System or Configuration Setting
# ---------------------------------------------------------------------------

CRITICAL_ENV_VARS = [
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME",
    "NODE_OPTIONS", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "SUDO_COMMAND", "SHELL", "IFS"
]

def check_introspection_external_config_control(modified_env_vars: List[dict] = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for External Control of System Configuration (CWE-15).
    Monitors process environment variable modifications (os.environ) during tool execution and alerts if
    untrusted inputs alter critical system environment variables or runtime configurations.
    
    :param modified_env_vars: List of modified environment variable records (e.g. [{"var": "PATH", "val": "..."}]).
    """
    if not modified_env_vars:
        return False, ""

    for record in modified_env_vars:
        var_name = record.get("var", "") if isinstance(record, dict) else str(record)
        var_val = record.get("val", "") if isinstance(record, dict) else ""
        
        var_upper = var_name.upper()
        if var_upper in CRITICAL_ENV_VARS:
            return True, (
                f"Introspection System Config Control Alert (CWE-15): Tool execution altered critical system "
                f"environment variable '{var_name}' to value '{str(var_val)[:50]}'! Risk of Arbitrary Code Execution / Hijacking."
            )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-134: Use of Externally-Controlled Format String
# ---------------------------------------------------------------------------

FORMAT_STRING_ERRORS = [
    "unsupported format character", "format specifier", "ValueError: unsupported format",
    "KeyError:", "IndexError: Replacement index", "not enough arguments for format string",
    "Unknown format code"
]

def check_introspection_format_string(error_message: str = "", logged_messages: List[str] = None) -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Format String Vulnerability (CWE-134).
    Monitors error output and log streams during tool execution to detect format specifier crashes
    or unsafe format string injections (%s, %x, %n, {0.__class__}).
    
    :param error_message: Execution exception / error string.
    :param logged_messages: List of log messages recorded during tool execution.
    """
    if error_message:
        err_lower = error_message.lower()
        for kw in FORMAT_STRING_ERRORS:
            if kw.lower() in err_lower:
                return True, (
                    f"Introspection Format String Alert (CWE-134): Tool failed with format specifier error "
                    f"'{error_message[:100]}'! Risk of Externally-Controlled Format String / Information Disclosure."
                )

    if logged_messages:
        for record in logged_messages:
            msg = record.get("message", "") if isinstance(record, dict) else str(record)
            if "%x" in msg or "%p" in msg or "%n" in msg:
                return True, (
                    f"Introspection Format String Alert (CWE-134): Unsanitized format specifiers (%x/%p/%n) "
                    f"detected in tool output log: '{msg[:80]}'! Risk of Memory Leak / Format String Injection."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')
# ---------------------------------------------------------------------------

TYPE_CONFUSION_ERRORS = [
    "TypeError:", "ClassCastException", "has no attribute",
    "object is not subscriptable", "object is not callable",
    "unsupported operand type"
]

def check_introspection_type_confusion(error_message: str = "") -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Type Confusion / Incompatible Type Access (CWE-843).
    Monitors execution exception tracebacks to detect unhandled type confusion errors caused by
    fuzzed inputs with incompatible data types.
    
    :param error_message: Execution exception / error string.
    """
    if error_message:
        err_lower = error_message.lower()
        for kw in TYPE_CONFUSION_ERRORS:
            if kw.lower() in err_lower:
                return True, (
                    f"Introspection Type Confusion Alert (CWE-843): Tool crashed due to incompatible "
                    f"type access error '{error_message[:100]}'! Risk of Type Confusion / Unhandled Exception DoS."
                )

    return False, ""


# ---------------------------------------------------------------------------
# CWE-488: Exposure of Data Element to Wrong Session
# ---------------------------------------------------------------------------

def check_introspection_cross_session_data_leak(session_a_data: str = "", session_b_output: str = "") -> Tuple[bool, str]:
    """
    Introspection Sanitizer for Exposure of Data Element to Wrong Session (CWE-488).
    Monitors global variables and shared session states between consecutive tool executions to detect
    if sensitive data from a previous session leaks into a subsequent independent tool execution.
    
    :param session_a_data: Unique token/data injected in Session A.
    :param session_b_output: Output or state recorded in Session B.
    """
    if session_a_data and session_b_output and len(session_a_data) >= 4:
        if session_a_data in session_b_output:
            return True, (
                f"Introspection Cross-Session Data Exposure Alert (CWE-488): Session B tool output "
                f"leaked private session data '{session_a_data[:30]}' from previous Session A! "
                f"Risk of Cross-Session Data Contamination / Information Leakage."
            )

    return False, ""




































