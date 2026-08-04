#!/usr/bin/env python3
import sys
import json
import os
from typing import Any

def read_file(path: str, allowed_dir: str = None) -> str:
    with open(path, "r") as f:
        return f.read()

def load_state(data: str) -> Any:
    import pickle, base64
    decoded = base64.b64decode(data) if isinstance(data, str) else data
    return pickle.loads(decoded)

def execute_command(cmd: str) -> str:
    return os.popen(cmd).read()

def query_db(username: str) -> list:
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, name TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin')")
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    rows = cursor.fetchall()
    conn.close()
    return rows

def upload_file(filename: str, content: str) -> str:
    with open(filename, "w") as f:
        f.write(content)
    return filename

def eval_expr(expression: str) -> Any:
    return eval(expression)

def log_user_action(user_input: str) -> str:
    import logging
    logger = logging.getLogger("mcp_server")
    logger.setLevel(logging.INFO)
    logger.info(f"User Action: {user_input}")
    return user_input

def log_api_key(api_key: str) -> str:
    import logging
    logger = logging.getLogger("mcp_server")
    logger.setLevel(logging.INFO)
    logger.info(f"Configured API Key credential: {api_key}")
    return api_key

def fetch_insecure_https(target_url: str) -> str:
    import ssl
    unverified_ctx = ssl._create_unverified_context()
    return "unverified"

def read_config_secret(config_file: str) -> str:
    with open(config_file, "r") as f:
        return f.read()

def start_debug_server(bind_port: int = 9999) -> str:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Vulnerable implementation: binds to 0.0.0.0 (CWE-1327)
    try:
        s.bind(("0.0.0.0", bind_port))
    except Exception:
        pass
    s.close()
    return "Bound server"

def parse_regex_input(text: str) -> bool:
    import re
    # Vulnerable implementation: ReDoS pattern (a+)+$ (CWE-1333)
    pattern = r"(a+)+$"
    match = re.search(pattern, text)
    return bool(match)

def perform_sync_sleep(seconds: float = 0.1) -> str:
    import time
    # Vulnerable implementation: synchronous blocking sleep inside event loop (CWE-1322)
    time.sleep(seconds)
    return f"Slept for {seconds}s"

def authenticate_user(token: str) -> str:
    # Vulnerable implementation: hardcoded API key (CWE-798)
    HARDCODED_KEY = "sk-proj-998877665544332211223344"
    if token == HARDCODED_KEY:
        return f"Authenticated with hardcoded key {HARDCODED_KEY}"
    return "Failed authentication"

def hash_password(password: str) -> str:
    import hashlib
    # Vulnerable implementation: MD5 weak hash (CWE-328)
    return hashlib.md5(password.encode()).hexdigest()

def generate_session_token(length: int = 16) -> str:
    import random
    # Vulnerable implementation: random.choice weak PRNG (CWE-338)
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))

# Global static IV for demonstrating Nonce reuse (CWE-323)
STATIC_IV = b"1234567890123456"

def encrypt_data_static_nonce(plaintext: str) -> str:
    # Vulnerable implementation: static Nonce/IV reuse (CWE-323)
    from src.sanitizers.introspection import NonceReuseTracer
    # Simulate recording static IV reuse
    tracker = NonceReuseTracer()
    tracker.record_nonce(STATIC_IV)
    tracker.record_nonce(STATIC_IV)  # Duplicate call triggers CWE-323 alert
    return "encrypted_payload"

def download_plugin_script(url: str, save_path: str = "/tmp/plugin.py") -> str:
    # Vulnerable implementation: download executable script without SHA-256 verification (CWE-494)
    from src.sanitizers.introspection import UnverifiedCodeDownloadTracer
    tracer = UnverifiedCodeDownloadTracer()
    tracer.record_download(url, save_path)
    return f"Downloaded script from {url} to {save_path}"

def parse_xml_payload(xml_content: str) -> str:
    # Vulnerable implementation: XXE external entity resolution (CWE-611/776)
    from src.sanitizers.introspection import XXETracer
    tracer = XXETracer()
    if "SYSTEM" in xml_content or "<!ENTITY" in xml_content:
        tracer.record_xxe("/etc/passwd")
    return "Parsed XML"

def decompress_zip_archive(compressed_bytes_count: int, decompressed_bytes_count: int) -> str:
    # Vulnerable implementation: Zip Bomb data amplification (CWE-409)
    from src.sanitizers.introspection import DataAmplificationTracer
    tracer = DataAmplificationTracer()
    tracer.record_decompression(compressed_bytes_count, decompressed_bytes_count)
    return f"Decompressed {decompressed_bytes_count} bytes"

def clone_git_repo(repo_url: str) -> str:
    # Vulnerable implementation: Argument / Flag Injection in subprocess (CWE-88)
    import subprocess
    cmd = f"git clone {repo_url} /tmp/repo"
    # Execute through shell
    return f"Cloned repo with command: {cmd}"

def export_user_report(username: str, filepath: str = "/tmp/report.csv") -> str:
    # Vulnerable implementation: CSV Formula Injection (CWE-1236)
    content = f"Name,Role\n{username},User\n"
    with open(filepath, "w") as f:
        f.write(content)
    return f"Exported report to {filepath}"

def read_user_symlink(link_path: str = "/tmp/user_symlink.txt") -> str:
    # Vulnerable implementation: Link Following / Symlink Traversal (CWE-59)
    if not os.path.exists(link_path) and not os.path.islink(link_path):
        os.symlink("/etc/passwd", link_path)
    with open(link_path, "r") as f:
        data = f.read(100)
    return f"Read symlink: {data[:20]}"

def create_insecure_temp_file(filename: str = "world_writable_temp.txt") -> str:
    # Vulnerable implementation: Insecure Temp File Permissions 0o777 (CWE-378/379)
    path = os.path.join("/tmp", filename)
    with open(path, "w") as f:
        f.write("sensitive_temp_data")
    os.chmod(path, 0o777)
    return f"Created temp file at {path}"

def trigger_sensitive_error(action: str) -> str:
    # Vulnerable implementation: Sensitive Error Leakage (CWE-209)
    raise ValueError(f"Failed action '{action}' using API key sk-proj-998877665544332211223344 at /home/admin/.ssh/id_rsa")

def trigger_production_assertion(count: int) -> str:
    # Vulnerable implementation: Reachable Assertion DoS (CWE-617)
    assert count > 0, "Count must be positive in production"
    return f"Count: {count}"

def save_plaintext_credentials(filepath: str = "/tmp/credentials.txt") -> str:
    # Vulnerable implementation: Cleartext Storage of Sensitive Information (CWE-312/538)
    with open(filepath, "w") as f:
        f.write("OpenAI API Key: sk-proj-998877665544332211223344")
    return f"Saved credentials to {filepath}"

def transmit_unencrypted_token(api_url: str = "http://api.external.com/auth?token=sk-proj-998877665544332211223344") -> str:
    # Vulnerable implementation: Cleartext Transmission of Sensitive Info (CWE-319)
    from src.sanitizers.introspection import NetworkExecutionTracer
    tracer = NetworkExecutionTracer()
    tracer.record_connection(api_url, 80)
    return f"Transmitted token to {api_url}"

def execute_swallowed_init_error(feature: str) -> str:
    # Vulnerable implementation: Non-exit on Failed Initialization (CWE-455)
    import logging
    logging.warning("Initialization failed for auth module, continuing in degraded mode...")
    return f"Executed feature {feature} without auth"

def leak_uncleaned_temp_file(prefix: str = "leak_") -> str:
    # Vulnerable implementation: Incomplete Cleanup / Resource Leak (CWE-459)
    import tempfile
    f = tempfile.NamedTemporaryFile(prefix=prefix, delete=False)
    f.write(b"leaked_data")
    f.close()
    return f"Leaked file {f.name}"

def process_unbounded_items(count: int) -> str:
    # Vulnerable implementation: Unchecked Input for Loop Condition (CWE-606)
    from src.sanitizers.introspection import LoopConditionTracer
    tracer = LoopConditionTracer()
    tracer.increment(count)
    return f"Processed {count} items"

def trigger_buffer_overflow_crash(data: str) -> str:
    # Vulnerable implementation: Classic Buffer Overflow / Segmentation Fault (CWE-120/787)
    if len(data) > 100:
        raise MemoryError("Fatal memory corruption: SIGSEGV Segmentation fault in native C module")
    return f"Processed data len {len(data)}"

def calculate_ratio_unhandled_zero(value: int, denominator: int) -> str:
    # Vulnerable implementation: Divide By Zero (CWE-369)
    res = value / denominator
    return f"Ratio: {res}"

def create_world_writable_file(filepath: str = "/tmp/insecure_config.json") -> str:
    # Vulnerable implementation: Incorrect Default Permissions (CWE-276/279)
    with open(filepath, "w") as f:
        f.write('{"debug": true}')
    os.chmod(filepath, 0o666)
    return f"Created config at {filepath}"

def run_privileged_sudo_command(cmd: str = "id") -> str:
    # Vulnerable implementation: Execution with Unnecessary Privileges (CWE-250/272)
    from src.sanitizers.introspection import CommandExecutionTracer
    tracer = CommandExecutionTracer()
    tracer.executed_commands.append(f"sudo {cmd}")
    return f"Executed sudo {cmd}"

def trigger_deadlock_lock_hang(resource_id: str) -> str:
    # Vulnerable implementation: Deadlock (CWE-833)
    import threading
    lock_a = threading.Lock()
    lock_a.acquire()
    # Simulated hang / deadlock holding lock_a
    return f"Acquired lock on {resource_id}"

def leak_open_file_descriptor(filepath: str = "/tmp/leak_fd.txt") -> str:
    # Vulnerable implementation: File Descriptor Leak (CWE-403/910)
    f = open(filepath, "w")
    f.write("leaked fd without close")
    # File descriptor remains open intentionally
    return f"Opened file {filepath} (FD leaked)"

def process_prototype_polluted_payload(payload: dict) -> str:
    # Vulnerable implementation: Prototype Pollution (CWE-915)
    return f"Processed payload keys: {list(payload.keys())}"

def set_system_environment_variable(var_name: str, var_val: str) -> str:
    # Vulnerable implementation: External Control of System Config (CWE-15)
    os.environ[var_name] = var_val
    return f"Set env {var_name}={var_val}"

def format_user_provided_string(user_fmt: str, data: str = "test") -> str:
    # Vulnerable implementation: Format String (CWE-134)
    # Unsafe format string injection
    return user_fmt % data

GLOBAL_SESSION_CACHE = {}

def store_user_session_in_global_state(session_token: str, user_data: str) -> str:
    # Vulnerable implementation: Exposure of Data Element to Wrong Session (CWE-488)
    GLOBAL_SESSION_CACHE["latest_token"] = session_token
    GLOBAL_SESSION_CACHE["latest_data"] = user_data
    return f"Stored session data for {session_token}"

def get_global_session_state() -> str:
    # Vulnerable implementation: Exposes previous session data to next caller
    return f"Shared state: {GLOBAL_SESSION_CACHE.get('latest_data', '')}"

def trigger_type_confusion_unhandled_error(val: Any) -> str:
    # Vulnerable implementation: Type Confusion (CWE-843)
    return val.upper()  # Raises TypeError / AttributeError if val is dict/list/int

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        
        line = line.strip()
        if not line:
            continue
            
        try:
            req = json.loads(line)
        except Exception:
            continue
            
        req_id = req.get("id")
        method = req.get("method")
        
        if method == "initialize":
            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "vulnerable-file-server", "version": "1.0.0"}
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "tools/list":
            res = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Reads contents of a file. Accepts allowed_dir but ignores it.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string", "description": "Path to file"},
                                    "allowed_dir": {"type": "string", "description": "Allowed workspace directory"}
                                },
                                "required": ["path"]
                            }
                        },
                        {
                            "name": "load_state",
                            "description": "Loads and deserializes pickled state data (CWE-502).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "data": {"type": "string", "description": "Base64 or hex serialized payload"}
                                },
                                "required": ["data"]
                            }
                        },
                        {
                            "name": "execute_command",
                            "description": "Executes shell commands (CWE-78 Command Injection vulnerability).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "cmd": {"type": "string", "description": "Command string to execute"}
                                },
                                "required": ["cmd"]
                            }
                        },
                        {
                            "name": "query_db",
                            "description": "Queries an in-memory SQLite database using string concatenation (CWE-89 SQL Injection vulnerability).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string", "description": "Username search string"}
                                },
                                "required": ["username"]
                            }
                        },
                        {
                            "name": "upload_file",
                            "description": "Saves an uploaded file to disk without checking dangerous extensions (CWE-434 Unrestricted File Upload).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filename": {"type": "string", "description": "Destination file name/path"},
                                    "content": {"type": "string", "description": "File payload string"}
                                },
                                "required": ["filename", "content"]
                            }
                        },
                        {
                            "name": "eval_expr",
                            "description": "Evaluates dynamic Python expressions (CWE-94 Code Injection vulnerability).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "expression": {"type": "string", "description": "Python expression string"}
                                },
                                "required": ["expression"]
                            }
                        },
                        {
                            "name": "log_user_action",
                            "description": "Logs user activity without escaping newlines (CWE-117 Log Injection).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "user_input": {"type": "string", "description": "User activity message"}
                                },
                                "required": ["user_input"]
                            }
                        },
                        {
                            "name": "log_api_key",
                            "description": "Logs API key credential in cleartext (CWE-779 Sensitive Data Logging).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "api_key": {"type": "string", "description": "API key token string"}
                                },
                                "required": ["api_key"]
                            }
                        },
                        {
                            "name": "fetch_insecure_https",
                            "description": "Disables SSL certificate verification (CWE-295 Improper Certificate Validation).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "target_url": {"type": "string", "description": "Target HTTPS URL"}
                                },
                                "required": ["target_url"]
                            }
                        },
                        {
                            "name": "read_config_secret",
                            "description": "Reads configuration or credential files (CWE-552 Sensitive File Access).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "config_file": {"type": "string", "description": "Target config file path"}
                                },
                                "required": ["config_file"]
                            }
                        }
                    ]
                }
            }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "read_file")
            args = params.get("arguments", {})
            
            if tool_name == "fetch_url":
                import urllib.request
                target_url = args.get("url", "http://127.0.0.1:8080")
                try:
                    req_obj = urllib.request.Request(target_url, headers={"User-Agent": "MCP/1.0"})
                    with urllib.request.urlopen(req_obj, timeout=2.0) as resp:
                        content_data = resp.read().decode("utf-8", errors="ignore")
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": content_data[:200]}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Fetch error: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "eval_expr":
                expr = args.get("expression", "1+1")
                try:
                    res_val = eval(expr)
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Result: {res_val}"}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Eval error: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "upload_file":
                filename = args.get("filename", "/tmp/uploaded_script.sh")
                content = args.get("content", "#!/bin/bash\necho PWNED\n")
                try:
                    with open(filename, "w") as f:
                        f.write(content)
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Saved file: {filename}"}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Upload error: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "query_db":
                import sqlite3
                username = args.get("username", "admin")
                try:
                    conn = sqlite3.connect(":memory:")
                    cursor = conn.cursor()
                    cursor.execute("CREATE TABLE users (id INT, name TEXT)")
                    cursor.execute("INSERT INTO users VALUES (1, 'admin')")
                    
                    # Vulnerable unparameterized SQL query execution
                    raw_sql = f"SELECT * FROM users WHERE name = '{username}'"
                    cursor.execute(raw_sql)
                    rows = cursor.fetchall()
                    conn.close()
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Found: {rows}"}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Database error: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "execute_command":
                cmd = args.get("cmd", "whoami")
                try:
                    out = os.popen(cmd).read()
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Output: {out}"}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Execution error: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "load_state":
                import pickle
                import base64
                raw_data = args.get("data", "")
                try:
                    decoded = base64.b64decode(raw_data) if isinstance(raw_data, str) else raw_data
                    obj = pickle.loads(decoded)
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Loaded object: {type(obj)}"}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Deserialization error: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue

            elif tool_name == "log_user_action":
                import logging
                user_msg = args.get("user_input", "")
                # Vulnerable implementation: logs raw user input without stripping newlines (CWE-117)
                logger = logging.getLogger("mcp_server")
                logger.info(f"User Action: {user_msg}")
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Logged action: {user_msg}"}]
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "log_api_key":
                import logging
                api_key_val = args.get("api_key", "sk-proj-default")
                # Vulnerable implementation: logs sensitive API key in cleartext (CWE-779)
                logger = logging.getLogger("mcp_server")
                logger.info(f"Configured API Key credential: {api_key_val}")
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "API Key registered successfully"}]
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "fetch_insecure_https":
                import ssl
                # Vulnerable implementation: disables SSL certificate verification (CWE-295)
                unverified_ctx = ssl._create_unverified_context()
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": "Created unverified SSL context"}]
                    }
                }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue
            elif tool_name == "read_config_secret":
                cfg_path = args.get("config_file", ".env")
                # Vulnerable implementation: reads sensitive file directly (CWE-552)
                try:
                    with open(cfg_path, "r") as f:
                        data = f.read()
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Read sensitive config: {data}"}]
                        }
                    }
                except Exception as e:
                    res = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"Error reading config file: {e}"}]
                        }
                    }
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
                continue

            path = args.get("path", "")
            
            # Vulnerable implementation: ignores allowed_dir and reads file directly
            try:
                with open(path, "r") as f:
                    content = f.read()
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": content}]
                    }
                }
            except Exception as e:
                res = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Error reading file: {e}"}]
                    }
                }
            sys.stdout.write(json.dumps(res) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
