import re
import libinjection
from typing import Iterator

_NUM = r"[+-]?(?:0x[0-9a-f]+|\d+)"
_TRUE = {"1", "on", "true", "yes"}
_FALSE = {"0", "off", "false", "no"}
SAFE_VTAB_MODULES = frozenset()

def check_sql_injection(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return bool(libinjection.is_sql_injection(value).get('is_sqli'))

def _sql_code(sql: str) -> str:
    if not isinstance(sql, str):
        return ""
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        char = sql[i]
        next_char = sql[i + 1] if i + 1 < n else ""
        if char == "-" and next_char == "-":
            i += 2
            while i < n and sql[i] not in "\r\n":
                i += 1
            out.append(" ")
            continue
        if char == "/" and next_char == "*":
            i += 2
            while i + 1 < n:
                if sql[i] == "*" and sql[i + 1] == "/":
                    i += 2
                    break
                i += 1
            out.append(" ")
            continue
        if char == "'":
            i += 1
            while i < n:
                if sql[i] == "'" and i + 1 < n and sql[i + 1] == "'":
                    i += 2
                    continue
                if sql[i] == "'":
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        if char in {'"', "`"}:
            quote = char
            identifier: list[str] = []
            i += 1
            while i < n:
                if sql[i] == quote and i + 1 < n and sql[i + 1] == quote:
                    identifier.append(quote)
                    i += 2
                    continue
                if sql[i] == quote:
                    i += 1
                    break
                identifier.append(sql[i])
                i += 1
            out.append("".join(identifier).lower())
            continue
        if char == "[":
            identifier = []
            i += 1
            while i < n and sql[i] != "]":
                identifier.append(sql[i])
                i += 1
            if i < n:
                i += 1
            out.append("".join(identifier).lower())
            continue
        out.append(char.lower())
        i += 1
    return re.sub(r"\s+", " ", "".join(out)).strip()

def _statements(sql: str) -> list[str]:
    return [
        statement.strip()
        for statement in _sql_code(sql).split(";")
        if statement.strip()
    ]

def _pragma_assignments(code: str) -> Iterator[tuple[str, str | None]]:
    pattern = re.compile(
        r"\bpragma\s+"
        r"(?:(?:[a-z_][a-z0-9_$]*)\s*\.\s*)?"
        r"([a-z_][a-z0-9_$]*)"
        r"\s*"
        r"(?:"
        r"=\s*([a-z0-9_+\-x]+)"
        r"|"
        r"\(\s*([a-z0-9_+\-x]+)\s*\)"
        r")?",
        re.IGNORECASE,
    )
    for match in pattern.finditer(code):
        name = match.group(1).lower()
        value = match.group(2) or match.group(3)
        yield name, value.lower() if value else None

def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        return None

def _pragma_has_assignment(code: str, name: str) -> bool:
    return bool(
        re.search(
            rf"\bpragma\s+"
            rf"(?:(?:[a-z_][a-z0-9_$]*)\s*\.\s*)?"
            rf"{re.escape(name)}\s*(?:=|\()",
            code,
        )
    )

def check_sqlite_extension_loading(value: str) -> bool:
    code = _sql_code(value)
    return bool(re.search(r"\bload_extension\s*\(", code))

def check_sqlite_fileio_abuse(value: str) -> bool:
    code = _sql_code(value)
    function_call = re.search(
        r"\b(?:readfile|writefile|fsdir|lsmode)\s*\(",
        code,
    )
    file_table = re.search(
        r"\b(?:from|join)\s+"
        r"(?:[a-z_][a-z0-9_$]*\s*\.\s*)?"
        r"(?:fsdir|zipfile)\s*\(",
        code,
    )
    return bool(function_call or file_table)

def check_sqlite_attach_abuse(value: str) -> bool:
    code = _sql_code(value)
    return bool(
        re.search(
            r"\b(?:"
            r"attach(?:\s+database)?"
            r"|"
            r"detach(?:\s+database)?"
            r")\b",
            code,
        )
    )

def check_sqlite_vacuum_into(value: str) -> bool:
    code = _sql_code(value)
    return bool(
        re.search(
            r"\bvacuum"
            r"(?:\s+[a-z_][a-z0-9_$]*)?"
            r"\s+into\b",
            code,
        )
    )

def check_sqlite_virtual_table_abuse(value: str) -> bool:
    code = _sql_code(value)
    pattern = re.compile(
        r"\bcreate\s+virtual\s+table\b"
        r".*?"
        r"\busing\s+([a-z_][a-z0-9_$]*)",
        re.DOTALL,
    )
    for match in pattern.finditer(code):
        module = match.group(1).lower()
        if module not in SAFE_VTAB_MODULES:
            return True
    return False

def check_sqlite_raw_page_access(value: str) -> bool:
    code = _sql_code(value)
    return bool(
        re.search(
            r"\b(?:"
            r"sqlite_dbpage"
            r"|sqlite_dbdata"
            r"|sqlite_dbptr"
            r"|dbstat"
            r"|sqlite_stmt"
            r"|bytecode"
            r"|tables_used"
            r")\b",
            code,
        )
    )

def check_sqlite_sensitive_metadata(value: str) -> bool:
    code = _sql_code(value)
    internal_tables = re.search(
        r"\b(?:"
        r"sqlite_schema"
        r"|sqlite_master"
        r"|sqlite_temp_schema"
        r"|sqlite_temp_master"
        r"|sqlite_stat[1-4]?"
        r"|sqlite_sequence"
        r")\b",
        code,
    )
    sensitive_pragmas = re.search(
        r"\b(?:pragma_)?(?:"
        r"database_list"
        r"|compile_options"
        r"|function_list"
        r"|module_list"
        r"|collation_list"
        r"|pragma_list"
        r"|table_list"
        r")\b",
        code,
    )
    return bool(internal_tables or sensitive_pragmas)

def check_sqlite_unsafe_pragma(value: str) -> bool:
    code = _sql_code(value)
    always_block_on_assignment = {
        "temp_store_directory",
        "data_store_directory",
        "journal_mode",
        "page_size",
        "auto_vacuum",
        "schema_version",
        "application_id",
        "user_version",
        "max_page_count",
    }
    for name, raw_value in _pragma_assignments(code):
        if not _pragma_has_assignment(code, name):
            continue
        token = (raw_value or "").lower()
        number = _to_int(token)
        if name in always_block_on_assignment:
            return True
        if name == "writable_schema" and token in _TRUE:
            return True
        if name == "trusted_schema" and token in _TRUE:
            return True
        if name == "locking_mode" and token == "exclusive":
            return True
        if name == "synchronous" and token in {"0", "off"}:
            return True
        if name == "wal_autocheckpoint" and number == 0:
            return True
        if (
            name == "busy_timeout"
            and number is not None
            and number > 60_000
        ):
            return True
        if (
            name == "mmap_size"
            and number is not None
            and number > 256 * 1024 * 1024
        ):
            return True
        if (
            name == "cache_size"
            and number is not None
            and abs(number) > 200_000
        ):
            return True
        if (
            name in {"soft_heap_limit", "hard_heap_limit"}
            and number is not None
            and number > 512 * 1024 * 1024
        ):
            return True
        if (
            name == "threads"
            and number is not None
            and number > 8
        ):
            return True
    return False

def check_sqlite_integrity_bypass(value: str) -> bool:
    code = _sql_code(value)
    for name, raw_value in _pragma_assignments(code):
        token = (raw_value or "").lower()
        if name == "foreign_keys" and token in _FALSE:
            return True
        if (
            name in {
                "ignore_check_constraints",
                "defer_foreign_keys",
                "recursive_triggers",
            }
            and token in _TRUE
        ):
            return True
        if name == "read_uncommitted" and token in _TRUE:
            return True
    return False

def check_sqlite_destructive_operation(value: str) -> bool:
    code = _sql_code(value)
    if re.search(
        r"\bdrop\s+(?:table|view|index|trigger)\b",
        code,
    ):
        return True
    if re.search(r"\balter\s+table\b", code):
        return True
    if re.search(
        r"\b(?:"
        r"replace\s+into"
        r"|insert\s+or\s+replace\s+into"
        r")\b",
        code,
    ):
        return True
    if re.search(
        r"\b(?:delete|update|insert|replace)\b"
        r".*"
        r"\bsqlite_(?:"
        r"schema|master|stat[1-4]?|sequence"
        r")\b",
        code,
        re.DOTALL,
    ):
        return True
    for statement in _statements(value):
        if (
            re.search(r"\bdelete\s+from\b", statement)
            and not re.search(r"\bwhere\b", statement)
        ):
            return True
        starts_with_update = re.match(
            r"^(?:with\b.*?\b)?update\b",
            statement,
            re.DOTALL,
        )
        if starts_with_update and not re.search(
            r"\bwhere\b",
            statement,
        ):
            return True
    return False

def check_sqlite_any_write(value: str) -> bool:
    code = _sql_code(value)
    return bool(
        re.search(
            r"(?<![a-z0-9_$])(?:"
            r"insert"
            r"|update"
            r"|delete"
            r"|replace"
            r"|create"
            r"|alter"
            r"|drop"
            r"|vacuum"
            r"|reindex"
            r"|analyze"
            r")\b",
            code,
        )
    )

def check_sqlite_trigger_persistence(value: str) -> bool:
    code = _sql_code(value)
    trigger = re.search(
        r"\bcreate\s+"
        r"(?:temp(?:orary)?\s+)?"
        r"trigger\b",
        code,
    )
    view = re.search(
        r"\bcreate\s+"
        r"(?:temp(?:orary)?\s+)?"
        r"view\b",
        code,
    )
    return bool(trigger or view)

def check_sqlite_orphan_transaction(value: str) -> bool:
    code = _sql_code(value)
    if re.search(
        r"\bcreate\s+(?:temp(?:orary)?\s+)?trigger\b",
        code,
    ):
        return False
    transaction_open = False
    savepoint_depth = 0
    for statement in _statements(value):
        if re.match(
            r"^begin"
            r"(?:\s+(?:deferred|immediate|exclusive))?"
            r"(?:\s+transaction)?\b",
            statement,
        ):
            if transaction_open:
                return True
            transaction_open = True
            continue
        if re.match(r"^savepoint\b", statement):
            savepoint_depth += 1
            continue
        if re.match(
            r"^release(?:\s+savepoint)?\b",
            statement,
        ):
            savepoint_depth = max(0, savepoint_depth - 1)
            continue
        if re.match(r"^rollback\s+to\b", statement):
            continue
        if re.match(
            r"^(?:commit|end)(?:\s+transaction)?\b",
            statement,
        ):
            transaction_open = False
            savepoint_depth = 0
            continue
        if re.match(
            r"^rollback(?:\s+transaction)?\b",
            statement,
        ):
            transaction_open = False
            savepoint_depth = 0
    return transaction_open or savepoint_depth > 0

def check_sqlite_lock_abuse(value: str) -> bool:
    code = _sql_code(value)
    if re.search(
        r"\bbegin\s+(?:exclusive|immediate)\b",
        code,
    ):
        return True
    if re.search(
        r"\bpragma\s+"
        r"(?:(?:[a-z_][a-z0-9_$]*)\s*\.\s*)?"
        r"locking_mode\s*(?:=|\()\s*exclusive\b",
        code,
    ):
        return True
    if re.search(
        r"\bpragma\s+"
        r"(?:(?:[a-z_][a-z0-9_$]*)\s*\.\s*)?"
        r"wal_checkpoint\s*(?:=|\()\s*"
        r"(?:full|restart|truncate)\b",
        code,
    ):
        return True
    for name, raw_value in _pragma_assignments(code):
        if name != "busy_timeout":
            continue
        timeout = _to_int(raw_value)
        if timeout is not None and timeout > 60_000:
            return True
    return False

def check_sqlite_maintenance_dos(value: str) -> bool:
    code = _sql_code(value)
    maintenance_statement = re.search(
        r"\b(?:vacuum|reindex|analyze)\b",
        code,
    )
    maintenance_pragma = re.search(
        r"\bpragma\s+"
        r"(?:(?:[a-z_][a-z0-9_$]*)\s*\.\s*)?"
        r"(?:"
        r"integrity_check"
        r"|quick_check"
        r"|optimize"
        r"|incremental_vacuum"
        r"|wal_checkpoint"
        r")\b",
        code,
    )
    return bool(maintenance_statement or maintenance_pragma)

def check_sqlite_resource_exhaustion(value: str) -> bool:
    if not isinstance(value, str):
        return True
    if len(value.encode("utf-8", errors="ignore")) > 200_000:
        return True
    statements = _statements(value)
    if len(statements) > 32:
        return True
    code = _sql_code(value)
    if re.search(r"\bwith\s+recursive\b", code):
        return True
    if len(re.findall(r"\bunion\s+all\b", code)) > 64:
        return True
    if len(re.findall(r"\bcross\s+join\b", code)) >= 3:
        return True
    blob_pattern = re.compile(
        r"\b(?:zero|random)blob\s*\(\s*("
        + _NUM
        + r")\s*\)"
    )
    for match in blob_pattern.finditer(code):
        size = _to_int(match.group(1))
        if size is not None and size > 8 * 1024 * 1024:
            return True
    series_pattern = re.compile(
        r"\bgenerate_series\s*\(\s*("
        + _NUM
        + r")\s*,\s*("
        + _NUM
        + r")"
    )
    for match in series_pattern.finditer(code):
        start = _to_int(match.group(1))
        stop = _to_int(match.group(2))
        if (
            start is not None
            and stop is not None
            and abs(stop - start) > 1_000_000
        ):
            return True
    return False

def check_wildcard_abuse_dos(value: str) -> bool:
    if not isinstance(value, str):
        return False
    if len(re.findall(r'%|_', value)) > 10:
        return True
    if "%%%%%" in value or "_____" in value:
        return True
    return False

def check_schema_jailbreak(value: str) -> bool:
    if not isinstance(value, str):
        return False
    patterns = [
        r'\bsqlite_temp_schema\b',
        r'\bsqlite_temp_master\b',
        r'\bsqlite_schema\b',
        r'\bsqlite_master\b',
        r'\binformation_schema\b',
        r'\bpg_catalog\b'
    ]
    return any(bool(re.search(p, value, re.IGNORECASE)) for p in patterns)
