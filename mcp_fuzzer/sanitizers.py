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

def check_unsafe_url_ssrf(value: str) -> bool:
    if not isinstance(value, str):
        return False
    from urllib.parse import urlparse
    import socket
    import ipaddress
    try:
        parsed = urlparse(value)
        if not parsed.scheme:
            return False
        if parsed.scheme.lower() not in ("http", "https"):
            return True
        if not parsed.netloc:
            return False
        hostname = parsed.hostname
        if not hostname:
            return True
        try:
            ips = {x[4][0] for x in socket.getaddrinfo(hostname, None)}
        except socket.gaierror:
            return False
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return True
            except ValueError:
                # If it's not a valid IP address
                pass
        return False
    except Exception:
        return False

def check_invalid_git_ref(value: str) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return False
    if "\x00" in stripped:
        return True
    # Argument injection (options starting with -)
    if stripped.startswith("-"):
        return True
    # Command injection (shell metacharacters)
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

AVAILABLE_SANITIZERS = {
    "check_sql_injection": "Used for tools that execute SQL queries or interact with databases.",
    "check_path_traversal": "Used for tools that manipulate, read, or write files on the file system.",
    "check_command_injection": "Used for tools that invoke system commands or underlying shells.",
    "check_invalid_json": "Used for tools that parse, extract or manipulate JSON structured strings.",
    "check_unsafe_url_ssrf": "Used for tools that fetch remote URLs to prevent Server-Side Request Forgery.",
    "check_invalid_git_ref": "Used for tools that parse git revision ranges, tags, or references to prevent git parameter injections or crashes.",
    "check_unsafe_s3_bucket": "Used for tools that interact with AWS S3 buckets to validate bucket naming guidelines and prevent AWS SDK level exceptions."
}