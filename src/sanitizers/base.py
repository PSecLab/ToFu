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

def check_blocked_command_bypass(value: str, blocked_commands: list = None) -> bool:
    if not isinstance(value, str):
        return False
    if not blocked_commands:
        blocked_commands = ["format", "mount", "umount", "mkfs", "fdisk", "dd", "sudo", "su", "passwd", "adduser", "useradd", "usermod", "groupadd"]
    
    # Normalize input: strip backslashes, quotes, double quotes and whitespaces
    normalized = re.sub(r'[\'\\"\\ ]', '', value).lower()
    
    for cmd in blocked_commands:
        if cmd == "su":
            # Match su as a standalone word or in typical su commands
            if re.search(r'\bsu\b', value) or re.search(r'\bsu\b', normalized):
                return True
        else:
            if cmd in normalized:
                return True
    return False

def check_directory_jailbreak_write(value: str, allowed_dirs: list = None) -> bool:
    if not isinstance(value, str):
        return False
    if not allowed_dirs:
        return False
        
    import os
    try:
        # Expand home directory and resolve to absolute canonical path
        expanded = os.path.expanduser(value)
        abs_path = os.path.abspath(expanded)
        
        # Check if the path escapes all allowed directories
        allowed = False
        for allowed_dir in allowed_dirs:
            abs_allowed = os.path.abspath(os.path.expanduser(allowed_dir))
            # If allowed_dir is empty or '/', everything is allowed
            if abs_allowed == "/" or not allowed_dir:
                allowed = True
                break
            # Check if abs_path is within abs_allowed
            if abs_path.startswith(abs_allowed):
                allowed = True
                break
        return not allowed
    except Exception:
        return False

