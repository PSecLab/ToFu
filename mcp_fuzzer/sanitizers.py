import libinjection
import re

def check_sql_injection(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return bool(libinjection.is_sql_injection(value).get('is_sqli'))

def check_path_traversal(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return "../" in value or "..\\" in value or bool(re.search(r'(/etc/passwd|windows\\win\.ini)', value, re.IGNORECASE))

def check_command_injection(value: str) -> bool:
    if not isinstance(value, str):
        return False
    patterns = [r';\s*sh\b', r';\s*bash\b', r'\|\s*sh\b', r'&&\s*']
    return any(bool(re.search(p, value)) for p in patterns)

def check_invalid_json(value: str) -> bool:
    if not isinstance(value, str):
        return False
    # Use standard library json parser to validate string structure
    import json
    stripped = value.strip()
    if '{' in stripped or '[' in stripped:
        try:
            json.loads(stripped)
            return False
        except json.JSONDecodeError:
            return True
    return False

AVAILABLE_SANITIZERS = {
    "check_sql_injection": "Used for tools that execute SQL queries or interact with databases.",
    "check_path_traversal": "Used for tools that manipulate, read, or write files on the file system.",
    "check_command_injection": "Used for tools that invoke system commands or underlying shells.",
    "check_invalid_json": "Used for tools that parse, extract or manipulate JSON structured strings."
}