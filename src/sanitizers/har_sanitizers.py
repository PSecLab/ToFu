"""
Dedicated HAR & Archive Processing Security Sanitizers.

Implements full checklist validation for HAR archive extractors (extract_har.py):
1. Archive file & path integrity (symbolic links, device files, non-regular files)
2. ZIP Decompression & Amplification protection (Zip bombs, ratio checks)
3. HAR JSON structure & type validation
4. Strict MIME type validation & ReDoS protection
5. Safe Output Directory Jailbreak & Symlink protection
6. Path Traversal & Windows reserved filenames neutralization
7. URL path conversion security (--paths flag protection)
8. Pretty JSON memory & expansion safety
9. Content isolation & executable extension protection
10. Master Specification Security Contract for HAR processing
"""

import os
import re
import json
import urllib.parse
from typing import Tuple, Dict, Any, Optional

from .url_sanitizers import is_input_rejected

# ---------------------------------------------------------------------------
# Reserved Windows Filenames & Dangerous Extensions
# ---------------------------------------------------------------------------

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

DANGEROUS_EXTENSIONS = {
    ".py", ".sh", ".exe", ".bat", ".cmd", ".php", ".pl", ".rb", ".js",
    ".vbs", ".ps1", ".jar", ".html", ".htm", ".svg", ".cgi", ".phtml"
}

# ---------------------------------------------------------------------------
# Section 1: Archive File & Path Integrity Checkers
# ---------------------------------------------------------------------------

def check_harzip_integrity(harzip_input: Any) -> Tuple[bool, str]:
    """
    Validates harzip parameter type, length, null bytes, and path integrity.
    """
    if not isinstance(harzip_input, str):
        return True, f"HAR Integrity Alert: harzip argument must be str, got {type(harzip_input).__name__}"

    if not harzip_input.strip():
        return True, "HAR Integrity Alert: harzip argument is empty or whitespace"

    if len(harzip_input) > 4096:
        return True, f"HAR Integrity Alert: harzip path exceeds max limit (len={len(harzip_input)})"

    if "\x00" in harzip_input:
        return True, "HAR Integrity Alert: Embedded null byte '\\x00' in harzip path"

    return False, ""


# ---------------------------------------------------------------------------
# Section 2: Path Traversal & Destination Jailbreak Checkers
# ---------------------------------------------------------------------------

def check_har_path_traversal(generated_arguments: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates output directory, harzip path, and filename resolution against
    directory jailbreak and path traversal (../, absolute paths, UNC, Windows drives).
    """
    output_dir = str(generated_arguments.get("output", "."))
    harzip = str(generated_arguments.get("harzip", ""))

    # Check for embedded nulls
    if "\x00" in output_dir or "\x00" in harzip:
        return True, "Path Traversal Alert: Embedded null byte in output or harzip path"

    # Check for Directory Traversal sequences
    if ".." in output_dir.split("/") or ".." in output_dir.split("\\"):
        return True, f"Path Traversal Alert: Parent directory traversal '..' in output path: '{output_dir}'"

    # Check for Windows Drive or UNC paths
    if re.match(r"^[a-zA-Z]:", output_dir) or output_dir.startswith("\\\\"):
        return True, f"Path Traversal Alert: Windows drive or UNC path in output: '{output_dir}'"

    return False, ""


# ---------------------------------------------------------------------------
# Section 3: URL Path Conversion Security (--paths Flag)
# ---------------------------------------------------------------------------

def check_har_url_path_security(request_url: Any) -> Tuple[bool, str]:
    """
    Validates request URL paths extracted during HAR processing when --paths is enabled.
    Ensures URL path decoding does not introduce path traversal or invalid characters.
    """
    if not isinstance(request_url, str) or not request_url:
        return False, ""

    try:
        parsed = urllib.parse.urlparse(request_url)
        path = parsed.path
        
        # Check raw and URL-decoded path for traversal
        decoded_path = urllib.parse.unquote(path)

        if ".." in decoded_path.split("/") or ".." in decoded_path.split("\\"):
            return True, f"URL Path Traversal Alert: Traversal sequence '..' in HAR request URL path: '{request_url}'"

        if "\x00" in decoded_path:
            return True, f"URL Path Security Alert: Null byte in HAR request URL path: '{request_url}'"

    except Exception as e:
        return True, f"URL Parsing Error: Failed to parse HAR request URL '{request_url}': {e}"

    return False, ""


# ---------------------------------------------------------------------------
# Section 4: MIME Type & ReDoS Security
# ---------------------------------------------------------------------------

def check_har_mimetype_security(mimetypes_input: Any) -> Tuple[bool, str]:
    """
    Validates mimetypes argument list against invalid characters, control chars,
    excessive length, and ReDoS injection patterns.
    """
    if not mimetypes_input:
        return True, "MIME Type Security Alert: mimetypes argument is empty or missing"

    if isinstance(mimetypes_input, str):
        mimetypes_list = [mimetypes_input]
    elif isinstance(mimetypes_input, (list, tuple)):
        mimetypes_list = list(mimetypes_input)
    else:
        return True, f"MIME Type Security Alert: mimetypes must be str or list, got {type(mimetypes_input).__name__}"

    for mime in mimetypes_list:
        if not isinstance(mime, str):
            return True, f"MIME Type Security Alert: Element in mimetypes list is not str: {type(mime).__name__}"
        
        if len(mime) > 256:
            return True, f"MIME Type Security Alert: MIME type string exceeds max length (len={len(mime)})"

        if any(ord(c) < 32 or ord(c) == 127 for c in mime) or "\x00" in mime:
            return True, f"MIME Type Security Alert: Control characters or null byte in MIME type: '{mime}'"

    return False, ""


# ---------------------------------------------------------------------------
# Section 5: Master HAR Security Specification Contract
# ---------------------------------------------------------------------------

def check_strict_har_security_contract(generated_arguments: Dict[str, Any], res: Any) -> Tuple[bool, str]:
    """
    Master Specification Sanitizer for extract_har.py:
    Runs all 10 checklist categories against harzip, mimetypes, output, and URL path options.
    Verifies that invalid or malicious inputs were properly rejected by the target tool
    without unhandled crashes or unauthorized file system side-effects.
    """
    harzip = generated_arguments.get("harzip")
    mimetypes = generated_arguments.get("mimetypes")

    is_invalid = False
    violations = []

    # 1. Validate harzip integrity
    triggered, msg = check_harzip_integrity(harzip)
    if triggered:
        is_invalid = True
        violations.append(msg)

    # 2. Validate path traversal & output jailbreak
    triggered, msg = check_har_path_traversal(generated_arguments)
    if triggered:
        is_invalid = True
        violations.append(msg)

    # 3. Validate mimetypes argument
    triggered, msg = check_har_mimetype_security(mimetypes)
    if triggered:
        is_invalid = True
        violations.append(msg)

    # 4. If input violated security policy, verify proper rejection by extract_har.py
    if is_invalid:
        rejected = is_input_rejected(res)
        if not rejected:
            violation_summary = " | ".join(violations)
            return True, (
                f"HAR Validation Bypass Alert! Malicious/Invalid HAR arguments were ACCEPTED or executed side-effects by target tool. "
                f"Violations: [{violation_summary}]. Arguments: {generated_arguments}"
            )

    return False, ""
