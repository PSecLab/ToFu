from .base import (
    check_path_traversal,
    check_command_injection,
    check_invalid_json,
    check_invalid_git_ref,
    check_unsafe_s3_bucket,
    check_log_injection,
    check_temp_file_leak,
    check_resource_exhaustion
)
from .db import (
    check_sql_injection,
    check_sqlite_extension_loading,
    check_sqlite_fileio_abuse,
    check_sqlite_attach_abuse,
    check_sqlite_vacuum_into,
    check_sqlite_virtual_table_abuse,
    check_sqlite_raw_page_access,
    check_sqlite_sensitive_metadata,
    check_sqlite_unsafe_pragma,
    check_sqlite_integrity_bypass,
    check_sqlite_destructive_operation,
    check_sqlite_any_write,
    check_sqlite_trigger_persistence,
    check_sqlite_orphan_transaction,
    check_sqlite_lock_abuse,
    check_sqlite_maintenance_dos,
    check_sqlite_resource_exhaustion,
    check_wildcard_abuse_dos,
    check_schema_jailbreak
)
from .web import (
    check_unsafe_url_ssrf,
    check_html_xss,
    check_local_file_uri
)
from .formats import (
    check_xml_xxe,
    check_xml_bomb,
    check_template_injection
)

AVAILABLE_SANITIZERS = {
    "check_sql_injection": "Used for tools that interact with databases using user-provided values. DO NOT use this sanitizer for tools that accept arbitrary raw SQL queries as their primary input (e.g. SQL client execution tools).",
    "check_path_traversal": "Used for tools that manipulate, read, or write files on the file system.",
    "check_command_injection": "Used for tools that invoke system commands or underlying shells.",
    "check_invalid_json": "Used for tools that parse, extract or manipulate JSON structured strings.",
    "check_unsafe_url_ssrf": "Used for tools that fetch remote URLs to prevent Server-Side Request Forgery.",
    "check_invalid_git_ref": "Used for tools that parse git revision ranges, tags, or references to prevent git parameter injections or crashes.",
    "check_unsafe_s3_bucket": "Used for tools that interact with AWS S3 buckets to validate bucket naming guidelines and prevent AWS SDK level exceptions.",
    "check_html_xss": "Used for tools that parse or convert HTML/Markdown to detect potential XSS payloads.",
    "check_xml_xxe": "Used for tools that parse XML/HTML documents to detect external entity injections (XXE).",
    "check_xml_bomb": "Used for tools that parse XML/HTML documents to detect recursive entity expansion / DoS payloads.",
    "check_local_file_uri": "Used for tools that accept URIs or URLs to block reading sensitive local files via file:// scheme.",
    "check_template_injection": "Used for tools that format or render templates with user input to detect SSTI.",
    "check_log_injection": "Used for tools that perform logging of user inputs to detect CRLF/log forging injections.",
    "check_temp_file_leak": "Used to monitor if temporary files are leaked in /tmp or temp directory after tool execution.",
    "check_resource_exhaustion": "Used to detect excessive execution time (ReDoS/infinite loops) or CPU hangs during tool execution.",
    "check_sqlite_extension_loading": "Detects calls to load_extension to load arbitrary shared libraries/DLLs in SQLite.",
    "check_sqlite_fileio_abuse": "Detects SQLite functions or table-valued functions that read, write, or query files from the host system (readfile, writefile, fsdir, zipfile).",
    "check_sqlite_attach_abuse": "Detects ATTACH or DETACH database statements in SQLite.",
    "check_sqlite_vacuum_into": "Detects VACUUM INTO statements which duplicate the database to an arbitrary path.",
    "check_sqlite_virtual_table_abuse": "Detects VIRTUAL TABLE creation using potentially unsafe modules.",
    "check_sqlite_raw_page_access": "Detects access to raw/low-level SQLite pages and structures (sqlite_dbpage, dbstat, etc.).",
    "check_sqlite_sensitive_metadata": "Detects queries targeting SQLite metadata, master/schema tables, or functions like database_list, function_list.",
    "check_sqlite_unsafe_pragma": "Detects modification of dangerous or sensitive SQLite configuration parameters (writable_schema, journal_mode, temp_store_directory, busy_timeout, locking_mode, etc.).",
    "check_sqlite_integrity_bypass": "Detects attempts to bypass SQLite constraints or integrity checks (foreign_keys=OFF, ignore_check_constraints=ON, defer_foreign_keys=ON, recursive_triggers=ON, read_uncommitted=ON).",
    "check_sqlite_destructive_operation": "Detects destructive actions like DROP, ALTER, UPDATE/DELETE without WHERE, or modification of sqlite_schema/stat tables.",
    "check_sqlite_any_write": "Detects any database mutation operations (INSERT, UPDATE, DELETE, REPLACE, CREATE, ALTER, DROP, VACUUM, REINDEX, ANALYZE).",
    "check_sqlite_trigger_persistence": "Detects creation of triggers or views that can persist code or execution vectors.",
    "check_sqlite_orphan_transaction": "Detects transactions or savepoints left open without COMMIT/ROLLBACK/RELEASE.",
    "check_sqlite_lock_abuse": "Detects exclusive lock acquisitions, locking mode modifications, or wal_checkpoint checkpoints.",
    "check_sqlite_maintenance_dos": "Detects heavy maintenance commands that can cause CPU/IO load or locking DoS (VACUUM, REINDEX, ANALYZE, integrity_check, WAL checkpoints).",
    "check_sqlite_resource_exhaustion": "Detects resource-intensive queries (large size, excessive statements, recursive queries, massive union all, cross joins, huge blobs).",
    "check_wildcard_abuse_dos": "Detects excessive use of search wildcards (% and _) in LIKE patterns to prevent CPU Denials of Service.",
    "check_schema_jailbreak": "Detects search parameters trying to traverse or target system/internal sqlite databases or metadata schemas."
}

# Predefined security profiles
SQLITE_PROFILE_BASE = {
    "check_sqlite_extension_loading": {"on_trigger": "raise_exception"},
    "check_sqlite_fileio_abuse": {"on_trigger": "raise_exception"},
    "check_sqlite_attach_abuse": {"on_trigger": "raise_exception"},
    "check_sqlite_vacuum_into": {"on_trigger": "raise_exception"},
    "check_sqlite_virtual_table_abuse": {"on_trigger": "raise_exception"},
    "check_sqlite_raw_page_access": {"on_trigger": "raise_exception"},
    "check_sqlite_unsafe_pragma": {"on_trigger": "raise_exception"},
    "check_sqlite_integrity_bypass": {"on_trigger": "raise_exception"},
    "check_sqlite_orphan_transaction": {"on_trigger": "raise_exception"},
    "check_sqlite_lock_abuse": {"on_trigger": "raise_exception"},
    "check_sqlite_maintenance_dos": {"on_trigger": "raise_exception"},
    "check_sqlite_resource_exhaustion": {"on_trigger": "raise_exception"}
}

SQLITE_PROFILE_CONTROLLED_RW = {
    **SQLITE_PROFILE_BASE,
    "check_sqlite_sensitive_metadata": {"on_trigger": "raise_exception"},
    "check_sqlite_destructive_operation": {"on_trigger": "raise_exception"},
    "check_sqlite_trigger_persistence": {"on_trigger": "raise_exception"}
}

SQLITE_PROFILE_READ_ONLY = {
    **SQLITE_PROFILE_BASE,
    "check_sqlite_sensitive_metadata": {"on_trigger": "raise_exception"},
    "check_sqlite_trigger_persistence": {"on_trigger": "raise_exception"},
    "check_sqlite_any_write": {"on_trigger": "raise_exception"}
}

SECURITY_PROFILES = {
    "base": SQLITE_PROFILE_BASE,
    "controlled_rw": SQLITE_PROFILE_CONTROLLED_RW,
    "read_only": SQLITE_PROFILE_READ_ONLY
}
