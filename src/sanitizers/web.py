import re
from urllib.parse import urlparse
import socket
import ipaddress

def check_unsafe_url_ssrf(value: str) -> bool:
    if not isinstance(value, str):
        return False
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

def check_html_xss(value: str) -> bool:
    if not isinstance(value, str):
        return False
    patterns = [
        r'<script\b',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'<iframe\b'
    ]
    return any(bool(re.search(p, value, re.IGNORECASE)) for p in patterns)

def check_local_file_uri(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = urlparse(value)
        if parsed.scheme.lower() == "file":
            return True
        if parsed.scheme == "" and (value.startswith("/") or (len(value) > 1 and value[0].lower() in "abcdefghijklmnopqrstuvwxyz" and value[1] == ":")):
            return True
        return False
    except Exception:
        return False
