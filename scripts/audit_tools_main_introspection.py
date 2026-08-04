import os
import sys
import glob
import json
import traceback
import importlib.util
import tempfile
import time

# Ensure project root is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.sanitizers import (
    check_file_access, check_introspection_path_traversal, check_untrusted_deserialization,
    check_introspection_command_injection, check_introspection_sql_injection,
    check_unrestricted_file_upload, check_introspection_code_injection, check_introspection_ssrf,
    check_introspection_temp_file_leak, check_introspection_log_injection, check_introspection_sensitive_data_logging,
    check_introspection_ssl_verification, check_introspection_sensitive_file_access,
    check_introspection_unrestricted_ip_binding, check_introspection_redos,
    check_introspection_blocking_event_loop_call, check_introspection_hardcoded_credentials,
    check_introspection_weak_hash, check_introspection_weak_prng, check_introspection_nonce_reuse,
    check_introspection_unverified_code_download, check_introspection_xxe, check_introspection_data_amplification,
    check_introspection_argument_injection, check_introspection_csv_formula_injection,
    check_introspection_symlink_following, check_introspection_insecure_temp_permissions,
    check_introspection_sensitive_error_leak, check_introspection_reachable_assertion,
    check_introspection_cleartext_sensitive_storage, check_introspection_cleartext_sensitive_transmission,
    check_introspection_failed_init_non_exit, check_introspection_incomplete_cleanup,
    check_introspection_unchecked_loop_condition, check_introspection_memory_access_violation,
    check_introspection_divide_by_zero, check_introspection_insecure_file_permissions,
    check_introspection_deadlock, check_introspection_file_descriptor_leak,
    check_introspection_prototype_pollution, check_introspection_external_config_control,
    check_introspection_format_string, check_introspection_type_confusion,
    check_introspection_cross_session_data_leak
)
from src.sanitizers.introspection import (
    FileAccessTracer, DeserializationTracer, CommandExecutionTracer, SQLExecutionTracer,
    FileWriteTracer, CodeExecutionTracer, NetworkExecutionTracer, TempFileLeakTracer,
    LogInjectionTracer, SensitiveDataLoggingTracer, SSLCertificateValidationTracer
)

PYTHON_TOOLS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "third_party", "tools-main", "python"))

# Mutation seeds & generator for fuzzing inputs
FUZZ_INPUTS = [
    "",
    " ",
    "http://127.0.0.1",
    "http://localhost:8000",
    "https://example.com",
    "file:///etc/passwd",
    "../" * 10 + "etc/passwd",
    "/etc/passwd\x00",
    "'; DROP TABLE users; --",
    "https://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "https://0.0.0.0/",
    "gASVIQAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbGSIlCmAflEudnE=",
    "https://www.google.com\r\nSet-Cookie: session=injected\r\n",
    "AKIAIOSFODNN7EXAMPLE",
    "sk_live_51M000000000000000000000000",
    "password=supersecretpass123",
    "eval('import os; os.system(\"id\")')",
    "%s%s%s%s%s%s%s%s%s%s",
    "A" * 10000,
    "http://" + "A" * 5000 + ".com",
    "file://" + "/tmp/" + "A" * 300,
    "https://user:pass@example.com/api?key=12345#ref",
    "-o /tmp/evil.sh",
    "--config=/etc/shadow",
    "| id",
    "; cat /etc/passwd",
    "`id`",
    "$(id)",
    "https://s3.amazonaws.com/mybucket/file.txt",
    "https://storage.googleapis.com/mybucket/file.txt",
]

def run_tool_function(func, sample_input):
    """Executes a target tool function under active introspection tracers."""
    import inspect
    sig = inspect.signature(func)
    params = sig.parameters
    
    kwargs = {}
    for p_name, param in params.items():
        if param.annotation == int:
            kwargs[p_name] = 8000
        elif param.annotation == bool:
            kwargs[p_name] = True
        elif param.annotation == list:
            kwargs[p_name] = [sample_input]
        else:
            kwargs[p_name] = sample_input

    # Active tracers
    file_access_tracer = FileAccessTracer()
    deser_tracer = DeserializationTracer()
    cmd_tracer = CommandExecutionTracer()
    sql_tracer = SQLExecutionTracer()
    write_tracer = FileWriteTracer()
    code_tracer = CodeExecutionTracer()
    net_tracer = NetworkExecutionTracer()
    ssl_tracer = SSLCertificateValidationTracer()

    result = None
    error_str = ""
    logs = []
    
    with file_access_tracer, deser_tracer, cmd_tracer, sql_tracer, write_tracer, code_tracer, net_tracer, ssl_tracer:
        try:
            result = func(**kwargs)
        except Exception as e:
            error_str = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"

    return {
        "result": result,
        "error": error_str,
        "accessed_files": list(file_access_tracer.accessed_files),
        "deserialization_calls": deser_tracer.deserialization_calls,
        "executed_commands": cmd_tracer.executed_commands,
        "sql_queries": sql_tracer.sql_queries,
        "written_files": list(write_tracer.written_files),
        "code_executions": code_tracer.evaluated_code_calls,
        "network_connections": net_tracer.network_connections,
        "ssl_unverified": ssl_tracer.unverified_ssl_calls,
        "input": kwargs
    }

def analyze_tool(py_path):
    tool_name = os.path.basename(py_path)
    module_name = tool_name.replace(".py", "").replace("-", "_")
    
    try:
        spec = importlib.util.spec_from_file_location(module_name, py_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)
    except Exception as e:
        return {tool_name: {"error": f"Failed to import tool module: {e}"}}

    # Find main entry points or tool functions
    candidate_funcs = []
    for name, obj in mod.__dict__.items():
        if callable(obj) and not name.startswith("_") and obj.__module__ == module_name:
            if name in ["main", "cli", "run", "parse_args"]:
                continue
            candidate_funcs.append((name, obj))

    if not candidate_funcs:
        # Fallback to main if no other callable found
        if hasattr(mod, "main") and callable(mod.main):
            candidate_funcs.append(("main", mod.main))

    tool_vulns = {}

    for func_name, func in candidate_funcs:
        # Skip interactive select or CLI menu functions that prompt for stdin or termios
        if func_name in ["interactive_select", "get_char", "input", "get_key", "print_file_list"]:
            continue

        triggered_sanitizers = set()
        vulnerability_details = []

        for inp in FUZZ_INPUTS:
            try:
                res = run_tool_function(func, inp)
            except (SystemExit, Exception):
                continue


            
            # 1. Path Traversal & File Access
            allowed_dir = os.path.abspath(PYTHON_TOOLS_DIR)
            pt_triggered, pt_err = check_introspection_path_traversal(res["accessed_files"], allowed_base_dir=allowed_dir)
            if pt_triggered and "check_introspection_path_traversal" not in triggered_sanitizers:
                triggered_sanitizers.add("check_introspection_path_traversal")
                vulnerability_details.append({
                    "sanitizer": "check_introspection_path_traversal",
                    "cwe": "CWE-22 (Path Traversal / Arbitrary File Access)",
                    "details": pt_err.strip(),
                    "trigger_input": res["input"]
                })

            # 2. Command Injection
            if res["executed_commands"]:
                cmd_trig, cmd_err = check_introspection_command_injection(res["executed_commands"])
                if cmd_trig and "check_introspection_command_injection" not in triggered_sanitizers:
                    triggered_sanitizers.add("check_introspection_command_injection")
                    vulnerability_details.append({
                        "sanitizer": "check_introspection_command_injection",
                        "cwe": "CWE-78 (OS Command Injection)",
                        "details": cmd_err.strip(),
                        "trigger_input": res["input"]
                    })

            # 3. Untrusted Deserialization
            if res["deserialization_calls"]:
                des_trig, des_err = check_untrusted_deserialization(res["deserialization_calls"])
                if des_trig and "check_untrusted_deserialization" not in triggered_sanitizers:
                    triggered_sanitizers.add("check_untrusted_deserialization")
                    vulnerability_details.append({
                        "sanitizer": "check_untrusted_deserialization",
                        "cwe": "CWE-502 (Deserialization of Untrusted Data)",
                        "details": des_err.strip(),
                        "trigger_input": res["input"]
                    })

            # 4. SSRF
            if res["network_connections"]:
                ssrf_trig, ssrf_err = check_introspection_ssrf(res["network_connections"])
                if ssrf_trig and "check_introspection_ssrf" not in triggered_sanitizers:
                    triggered_sanitizers.add("check_introspection_ssrf")
                    vulnerability_details.append({
                        "sanitizer": "check_introspection_ssrf",
                        "cwe": "CWE-918 (Server-Side Request Forgery)",
                        "details": ssrf_err.strip(),
                        "trigger_input": res["input"]
                    })

            # 5. SSL Verification Disabled
            if res["ssl_unverified"]:
                ssl_trig, ssl_err = check_introspection_ssl_verification(True)
                if ssl_trig and "check_introspection_ssl_verification" not in triggered_sanitizers:
                    triggered_sanitizers.add("check_introspection_ssl_verification")
                    vulnerability_details.append({
                        "sanitizer": "check_introspection_ssl_verification",
                        "cwe": "CWE-295 (Improper Certificate Validation)",
                        "details": ssl_err.strip(),
                        "trigger_input": res["input"]
                    })

            # 6. Sensitive Data Leak / Error Disclosures
            if res["error"]:
                err_trig, err_leak = check_introspection_sensitive_error_leak(res["error"])
                if err_trig and "check_introspection_sensitive_error_leak" not in triggered_sanitizers:
                    triggered_sanitizers.add("check_introspection_sensitive_error_leak")
                    vulnerability_details.append({
                        "sanitizer": "check_introspection_sensitive_error_leak",
                        "cwe": "CWE-209 (Sensitive Information Disclosure in Error Message)",
                        "details": err_leak.strip(),
                        "trigger_input": res["input"]
                    })

            # 7. Unexpected Crash
            if "URLError" in res["error"] or "ValueError" in res["error"] or "TypeError" in res["error"] or "AttributeError" in res["error"]:
                if "check_unexpected_crash" not in triggered_sanitizers:
                    triggered_sanitizers.add("check_unexpected_crash")
                    vulnerability_details.append({
                        "sanitizer": "check_unexpected_crash",
                        "cwe": "CWE-248 (Uncaught Exception / Unhandled Crash)",
                        "details": res["error"].splitlines()[0] if res["error"] else "",
                        "trigger_input": res["input"]
                    })

        if vulnerability_details:
            tool_vulns[func_name] = vulnerability_details

    return {tool_name: tool_vulns}

def main():
    py_files = sorted(glob.glob(os.path.join(PYTHON_TOOLS_DIR, "*.py")))
    print(f"[*] Auditing {len(py_files)} Python tools in tools-main with active introspection sanitizers...\n")
    
    results = {}
    for py_file in py_files:
        tool_name = os.path.basename(py_file)
        print(f"[*] Analyzing {tool_name}...")
        res = analyze_tool(py_file)
        results.update(res)

    report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools_main_introspection_audit.json"))
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Audit complete! Detailed report written to {report_path}")

if __name__ == "__main__":
    main()
