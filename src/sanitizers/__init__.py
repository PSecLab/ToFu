from .base import (
    check_path_traversal,
    check_command_injection,
    check_invalid_json,
    check_log_injection,
    check_temp_file_leak,
    check_resource_exhaustion,
    check_blocked_command_bypass,
    check_directory_jailbreak_write
)
from .mcp_oracles import (
    check_unhandled_promise_rejection,
    check_process_and_fd_leaks
)
from .introspection import (
    check_file_access,
    check_introspection_path_traversal,
    check_untrusted_deserialization,
    check_introspection_command_injection,
    check_introspection_sql_injection,
    check_unrestricted_file_upload,
    check_introspection_code_injection,
    check_introspection_ssrf,
    check_introspection_temp_file_leak,
    check_introspection_log_injection,
    check_introspection_sensitive_data_logging,
    check_introspection_ssl_verification,
    check_introspection_sensitive_file_access,
    check_introspection_unrestricted_ip_binding,
    check_introspection_redos,
    check_introspection_blocking_event_loop_call,
    check_introspection_hardcoded_credentials,
    check_introspection_weak_hash,
    check_introspection_weak_prng,
    check_introspection_nonce_reuse,
    check_introspection_unverified_code_download,
    check_introspection_xxe,
    check_introspection_data_amplification,
    check_introspection_argument_injection,
    check_introspection_csv_formula_injection,
    check_introspection_symlink_following,
    check_introspection_insecure_temp_permissions,
    check_introspection_sensitive_error_leak,
    check_introspection_reachable_assertion,
    check_introspection_cleartext_sensitive_storage,
    check_introspection_cleartext_sensitive_transmission,
    check_introspection_failed_init_non_exit,
    check_introspection_incomplete_cleanup,
    check_introspection_unchecked_loop_condition,
    check_introspection_memory_access_violation,
    check_introspection_divide_by_zero,
    check_introspection_insecure_file_permissions,
    check_introspection_unnecessary_root_privileges,
    check_introspection_deadlock,
    check_introspection_file_descriptor_leak,
    check_introspection_prototype_pollution,
    check_introspection_external_config_control,
    check_introspection_format_string,
    check_introspection_type_confusion,
    check_introspection_cross_session_data_leak,
    FileAccessTracer,
    DeserializationTracer,
    CommandExecutionTracer,
    SQLExecutionTracer,
    FileWriteTracer,
    CodeExecutionTracer,
    NetworkExecutionTracer,
    TempFileLeakTracer,
    LogInjectionTracer,
    SensitiveDataLoggingTracer,
    SSLCertificateValidationTracer,
    UnrestrictedIPBindingTracer,
    ReDoSTracer,
    BlockingEventLoopCallTracer,
    WeakHashTracer,
    WeakPRNGTracer,
    NonceReuseTracer,
    UnverifiedCodeDownloadTracer,
    XXETracer,
    DataAmplificationTracer,
    LoopConditionTracer
)

from .url_sanitizers import (
    check_strict_url_security_contract,
    check_url_raw_input_validation,
    check_url_structure_and_parsing,
    check_url_hostname_canonicalization,
    check_url_alternative_ip_representations,
    check_url_ssrf_ip_ranges,
    is_input_rejected
)

from .har_sanitizers import (
    check_strict_har_security_contract,
    check_harzip_integrity,
    check_har_path_traversal,
    check_har_url_path_security,
    check_har_mimetype_security
)

from .markitdown_sanitizers import (
    check_strict_markitdown_security_contract,
    check_markitdown_uri_validation,
    check_markitdown_file_uri_jailbreak,
    check_markitdown_data_uri_security,
    check_markitdown_markdown_output_security
)

AVAILABLE_SANITIZERS = {
    "check_strict_markitdown_security_contract": "Master specification sanitizer for MarkItDown & document converters: Validates 50-point checklist (URI scheme whitelist, SSRF, file:// LFI, data: URI, markdown output injection) and verifies rejection.",
    "check_markitdown_uri_validation": "Sanitizer: Enforces strict scheme whitelist (http, https, file, data) and rejects dangerous schemes (gopher, ftp, smb, nfs, ssh).",
    "check_markitdown_file_uri_jailbreak": "Sanitizer: Guards file:// URIs against Local File Inclusion (LFI) of sensitive system files (/etc/passwd, .env, .ssh) and jailbreaks.",
    "check_markitdown_data_uri_security": "Sanitizer: Guards data: URIs against excessive size (>2MB) and Base64 payload expansion amplification.",
    "check_markitdown_markdown_output_security": "Sanitizer: Inspects generated Markdown output for HTML script tags, file:// path leaks, or indirect prompt injection patterns.",

    "check_strict_har_security_contract": "Master specification sanitizer for HAR/ZIP archive tools: Validates 10-section security checklist (harzip integrity, path traversal, Zip Slip, URL paths, MIME types) and verifies rejection.",
    "check_harzip_integrity": "Sanitizer: Validates harzip file path, null bytes, length limit, and regular file integrity.",
    "check_har_path_traversal": "Sanitizer: Guards output directory and ZIP extraction against path traversal, UNC, and Windows drive escapes.",
    "check_har_url_path_security": "Sanitizer: Guards URL path conversion (--paths flag) against traversal sequences and null byte injection.",
    "check_har_mimetype_security": "Sanitizer: Validates mimetypes argument against control characters, null bytes, ReDoS patterns, and dangerous extensions.",

    "check_strict_url_security_contract": "Master specification sanitizer for HTTP/URL tools: Enforces strict input validation, parsing, canonicalization, alternative IP detection, SSRF protection, and verifies rejection of invalid inputs.",

    "check_url_raw_input_validation": "Sanitizer: Validates URL type, length, control characters, spaces, and ambiguous Unicode lookalikes.",
    "check_url_structure_and_parsing": "Sanitizer: Enforces absolute URL structure, scheme whitelist (http/https), userinfo rejection, port validation, and fragment removal.",
    "check_url_hostname_canonicalization": "Sanitizer: Enforces trailing dot stripping, IDNA Punycode conversion, label checks, and homoglyph / mixed-script detection.",
    "check_url_alternative_ip_representations": "Sanitizer: Detects non-canonical IPv4 (octal, hex, int, short form), IPv6 scope IDs (%eth0), and IPv4-mapped IPv6.",
    "check_url_ssrf_ip_ranges": "Sanitizer: Blocks loopback, RFC 1918 private, link-local, CGNAT, cloud metadata, and internal hostnames.",

    "check_introspection_cross_session_data_leak": "Introspection sanitizer: Detects exposure of private session data to subsequent independent sessions (CWE-488).",
    "check_introspection_type_confusion": "Introspection sanitizer: Detects unhandled TypeError and incompatible type access crashes (CWE-843).",
    "check_introspection_format_string": "Introspection sanitizer: Detects externally-controlled format string specifiers and crashes (CWE-134).",
    "check_introspection_external_config_control": "Introspection sanitizer: Detects tool execution modifying critical system env vars like PATH or LD_PRELOAD (CWE-15).",
    "check_introspection_prototype_pollution": "Introspection sanitizer: Detects prototype pollution keys like __proto__ or __class__ in inputs (CWE-915).",
    "check_introspection_file_descriptor_leak": "Introspection sanitizer: Detects open file descriptors leackes during tool execution (CWE-403/910).",
    "check_introspection_deadlock": "Introspection sanitizer: Detects execution timeouts and thread lock hangs caused by deadlocks (CWE-833).",
    "check_introspection_unnecessary_root_privileges": "Introspection sanitizer: Detects tool execution under root (EUID=0) or privilege escalation via sudo/su (CWE-250/272).",
    "check_introspection_insecure_file_permissions": "Introspection sanitizer: Monitors created/modified files for insecure permissive octal modes like 0o777 or 0o666 (CWE-276/279).",
    "check_introspection_divide_by_zero": "Introspection sanitizer: Detects unhandled ZeroDivisionError crashes caused by fuzzed zero denominators (CWE-369).",
    "check_introspection_memory_access_violation": "Introspection sanitizer: Detects SIGSEGV, SIGBUS, or native memory corruption crashes caused by buffer overflows (CWE-120/787).",
    "check_introspection_unchecked_loop_condition": "Introspection sanitizer: Monitors loop iterations for CPU exhaustion caused by unchecked fuzzed loop conditions (CWE-606).",
    "check_introspection_incomplete_cleanup": "Introspection sanitizer: Monitors uncleaned temporary files or leaked file descriptors post-execution (CWE-459).",
    "check_introspection_failed_init_non_exit": "Introspection sanitizer: Detects tool execution continuing with success=True after critical init errors (CWE-455).",
    "check_introspection_cleartext_sensitive_transmission": "Introspection sanitizer: Monitors network requests to detect cleartext HTTP transmission of tokens/credentials (CWE-319).",
    "check_introspection_cleartext_sensitive_storage": "Introspection sanitizer: Monitors file writes to detect plain text storage of unencrypted keys/credentials (CWE-312/538).",
    "check_introspection_reachable_assertion": "Introspection sanitizer: Monitors tool execution for unhandled production AssertionError DoS crashes (CWE-617).",
    "check_introspection_sensitive_error_leak": "Introspection sanitizer: Monitors error messages and stack traces for exposure of sensitive keys/credentials (CWE-209).",
    "check_introspection_insecure_temp_permissions": "Introspection sanitizer: Monitors created temporary files for overly permissive world-readable/writable permissions (CWE-378/379).",
    "check_introspection_symlink_following": "Introspection sanitizer: Monitors file accesses to detect untrusted symbolic link following (CWE-59).",
    "check_introspection_csv_formula_injection": "Introspection sanitizer: Monitors file writes to CSV/TSV spreadsheets for unneutralized formula injection (CWE-1236).",
    "check_introspection_argument_injection": "Introspection sanitizer: Monitors executed CLI command arguments for dangerous option/flag injections (CWE-88).",
    "check_introspection_data_amplification": "Introspection sanitizer: Monitors decompression operations to detect Zip Bombs / Data Amplification DoS (CWE-409).",
    "check_introspection_xxe": "Introspection sanitizer: Monitors XML parsing for XML External Entity (XXE) and entity expansion vulnerabilities (CWE-611/776).",
    "check_introspection_unverified_code_download": "Introspection sanitizer: Monitors remote code downloads to detect executable files saved without integrity verification (CWE-494).",
    "check_introspection_nonce_reuse": "Introspection sanitizer: Monitors cryptographic Nonces/IVs to detect static or duplicate Nonce reuse (CWE-323).",
    "check_introspection_weak_prng": "Introspection sanitizer: Monitors random generation for cryptographically weak PRNG usage (CWE-338).",
    "check_introspection_weak_hash": "Introspection sanitizer: Monitors hash functions for broken/deprecated MD5/SHA-1 usage (CWE-328).",
    "check_introspection_hardcoded_credentials": "Introspection sanitizer: Monitors runtime execution for hard-coded API keys, tokens or secrets (CWE-798).",
    "check_introspection_blocking_event_loop_call": "Introspection sanitizer: Monitors synchronous blocking calls (e.g. time.sleep) inside active event loops (CWE-1322).",
    "check_introspection_redos": "Introspection sanitizer: Monitors regular expression execution time for catastrophic backtracking / ReDoS (CWE-1333).",
    "check_introspection_unrestricted_ip_binding": "Introspection sanitizer: Monitors socket bind operations to detect unrestricted wildcard interface binding 0.0.0.0 (CWE-1327).",
    "check_introspection_sensitive_file_access": "Introspection sanitizer: Monitors file system accesses to detect reads/writes to sensitive system/credential files (CWE-552).",
    "check_introspection_ssl_verification": "Introspection sanitizer: Monitors outgoing SSL/TLS connections for disabled certificate validation (CWE-295).",
    "check_introspection_sensitive_data_logging": "Introspection sanitizer: Monitors log outputs for exposure of unredacted credentials/tokens (CWE-779).",
    "check_introspection_log_injection": "Introspection sanitizer: Monitors log outputs for unneutralized CRLF characters or ANSI escape sequences (CWE-117).",
    "check_introspection_temp_file_leak": "Introspection sanitizer: Monitors /tmp directory for uncleaned temporary files leaked during tool execution (CWE-533).",
    "check_introspection_ssrf": "Introspection sanitizer: Monitors tool execution for outgoing network requests to internal/private IP addresses (CWE-918).",
    "check_introspection_code_injection": "Introspection sanitizer: Monitors tool execution for dynamic code evaluation (builtins.eval, builtins.exec).",
    "check_unrestricted_file_upload": "Introspection sanitizer: Monitors file creation/writes to detect dangerous or executable file extensions (e.g. .sh, .py, .php).",
    "check_introspection_sql_injection": "Introspection sanitizer: Monitors tool execution for unparameterized/malicious SQL queries (e.g. sqlite3).",
    "check_introspection_command_injection": "Introspection sanitizer: Monitors tool execution for Command Injection and OS Command Injection (CWE-77 / CWE-78).",
    "check_untrusted_deserialization": "Introspection sanitizer: Monitors execution for unsafe deserialization operations (e.g. pickle.loads).",
    "check_file_access": "Introspection sanitizer: Monitors file system access during tool execution to detect reads/writes to sensitive files like /etc/passwd.",
    "check_introspection_path_traversal": "Introspection sanitizer: Monitors file system access during tool execution and flags any read/write escaping a dedicated workspace directory.",
    "check_unhandled_promise_rejection": "Detects unhandled promise rejections or unhandled exceptions in MCP server tool responses.",
    "check_process_and_fd_leaks": "Detects leaked background subprocesses or orphaned child processes after tool execution.",
    "check_path_traversal": "Used for tools that manipulate, read, or write files on the file system.",
    "check_command_injection": "Used for tools that invoke system commands or underlying shells.",
    "check_invalid_json": "Used for tools that parse, extract or manipulate JSON structured strings.",
    "check_log_injection": "Used for tools that perform logging of user inputs to detect CRLF/log forging injections.",
    "check_temp_file_leak": "Used to monitor if temporary files are leaked in /tmp or temp directory after tool execution.",
    "check_resource_exhaustion": "Used to detect excessive execution time or hangs during tool execution.",
    "check_blocked_command_bypass": "Used for command execution tools to detect bypasses of blocked command lists.",
    "check_directory_jailbreak_write": "Used for file write tools to ensure paths do not escape allowed directory roots."
}

SECURITY_PROFILES = {
    "base": {
        "check_file_access": {},
        "check_introspection_path_traversal": {},
        "check_unexpected_crash": {},
        "check_resource_exhaustion": {}
    },
    "controlled_rw": {
        "check_file_access": {},
        "check_introspection_path_traversal": {},
        "check_directory_jailbreak_write": {},
        "check_introspection_command_injection": {},
        "check_unexpected_crash": {}
    },
    "read_only": {
        "check_file_access": {},
        "check_introspection_path_traversal": {},
        "check_directory_jailbreak_write": {},
        "check_introspection_command_injection": {},
        "check_introspection_code_injection": {},
        "check_unexpected_crash": {}
    }
}

# Base mandatory sanitizers that are ALWAYS enforced for every tool (Layer 1)
BASE_MANDATORY_SANITIZERS = [
    "check_unexpected_crash",
    "check_resource_exhaustion",
    "check_file_access",
    "check_introspection_log_injection",
    "check_introspection_sensitive_data_logging"
]



