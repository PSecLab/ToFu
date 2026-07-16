import re
import json

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
    stripped = value.strip()
    if '{' in stripped or '[' in stripped:
        try:
            json.loads(stripped)
            return False
        except json.JSONDecodeError:
            return True
    return False

def check_invalid_git_ref(value: str) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return False
    if "\x00" in stripped:
        return True
    if stripped.startswith("-"):
        return True
    shell_metachars = (";", "&", "|", "`", "$", "\n", "\r")
    if any(char in stripped for char in shell_metachars):
        return True
    return False

def check_unsafe_s3_bucket(value: str) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return False
    if len(stripped) < 3 or len(stripped) > 63:
        return True
    if not re.match(r'^[a-z0-9.-]+$', stripped):
        return True
    if stripped[0] in ".-" or stripped[-1] in ".-":
        return True
    if ".." in stripped or ".-" in stripped or "-." in stripped:
        return True
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', stripped):
        return True
    return False

def check_log_injection(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return "\r" in value or "\n" in value

def check_temp_file_leak(value: str) -> bool:
    return False

def check_resource_exhaustion(value: str) -> bool:
    return False
