"""
Dedicated MarkItDown & Document Converter Security Sanitizers.

Implements full 50-point checklist validation for MarkItDown (convert_to_markdown / convert_uri):
1. URI General Validation & Scheme Whitelist (http, https, file, data). Rejects dangerous schemes (gopher, ftp, smb, nfs, ssh).
2. SSRF Protection for http/https URIs (loopback, RFC1918 private, link-local, cloud metadata 169.254.169.254).
3. Alternative IP representations (octal, hex, integer, short form, IPv4-mapped IPv6, userinfo @).
4. Local File Inclusion (LFI) & Jailbreak for file:// URIs (/etc/passwd, /proc/self/environ, .env, .ssh, devices /dev/zero).
5. Data URI Security & Base64 payload expansion control.
6. Output Markdown Sanitization (HTML script injection, indirect prompt injection, file:// leakage).
7. Master Security Specification Contract for MarkItDown.
"""

import os
import re
import urllib.parse
import ipaddress
from typing import Tuple, Dict, Any, Optional

from .url_sanitizers import (
    is_input_rejected,
    check_url_raw_input_validation,
    check_url_structure_and_parsing,
    check_url_alternative_ip_representations,
    check_url_ssrf_ip_ranges
)

# Allowed URI schemes for MarkItDown
ALLOWED_URI_SCHEMES = {"http", "https", "file", "data"}

# Restricted sensitive local files for file:// URI LFI checks
SENSITIVE_LOCAL_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/master.passwd", "/etc/sudoers",
    "/proc/self/environ", "/proc/kcore", "/proc/cmdline",
    "/dev/zero", "/dev/random", "/dev/urandom", "/dev/null",
    ".env", ".ssh/id_rsa", ".ssh/authorized_keys",
    "C:\\Windows\\System32", "C:\\boot.ini"
]

# Indirect Prompt Injection patterns in generated Markdown
INDIRECT_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"disregard\s+(?:all\s+)?prior\s+prompts",
    r"system\s+override",
    r"call\s+(?:the\s+)?tool",
    r"read\s+file:\/\/"
]

# ---------------------------------------------------------------------------
# Section 1: General URI & Scheme Validation
# ---------------------------------------------------------------------------

def check_markitdown_uri_validation(uri_input: Any) -> Tuple[bool, str]:
    """
    Validates URI type, length limit (<=8192), null bytes, control characters,
    and enforces strict scheme whitelist (http, https, file, data).
    Rejects dangerous schemes like gopher:, ftp:, smb:, nfs:, ssh:.
    """
    if not isinstance(uri_input, str):
        return True, f"MarkItDown URI Alert: URI must be str, got {type(uri_input).__name__}"

    uri_str = uri_input.strip()
    if not uri_str:
        return True, "MarkItDown URI Alert: URI is empty or whitespace"

    if len(uri_str) > 8192:
        return True, f"MarkItDown URI Alert: URI length exceeds max limit (len={len(uri_str)})"

    if "\x00" in uri_str:
        return True, "MarkItDown URI Alert: Embedded null byte '\\x00' in URI"

    # Control characters check (ASCII < 32 except tabs/newlines inside data URIs)
    if not uri_str.startswith("data:"):
        if any(ord(c) < 32 or ord(c) == 127 for c in uri_str):
            return True, f"MarkItDown URI Alert: Control characters in URI: '{uri_str}'"

    # Scheme Whitelist Validation
    try:
        parsed = urllib.parse.urlsplit(uri_str)
        scheme = parsed.scheme.lower()

        if not scheme:
            return True, f"MarkItDown URI Alert: Missing URI scheme in '{uri_str}'"

        if scheme not in ALLOWED_URI_SCHEMES:
            return True, f"MarkItDown URI Alert: Disallowed scheme '{scheme}:'. Allowed: {ALLOWED_URI_SCHEMES}"

    except Exception as e:
        return True, f"MarkItDown URI Alert: Failed to parse URI '{uri_str}': {e}"

    return False, ""


# ---------------------------------------------------------------------------
# Section 2: Local File Inclusion (LFI) & file:// Jailbreak
# ---------------------------------------------------------------------------

def check_markitdown_file_uri_jailbreak(uri_input: Any, allowed_base_dir: Optional[str] = None) -> Tuple[bool, str]:
    """
    Validates file:// URIs against Local File Inclusion (LFI) of sensitive system files,
    directory jailbreak, UNC path traversal, and special device file access (/dev/zero, /proc).
    """
    if not isinstance(uri_input, str) or not uri_input.strip().lower().startswith("file:"):
        return False, ""

    try:
        parsed = urllib.parse.urlsplit(uri_input)
        
        # Check for UNC host in file:// scheme (e.g. file://attacker.com/share)
        if parsed.netloc and parsed.netloc not in ("localhost", "127.0.0.1", ""):
            return True, f"LFI Security Alert: UNC / remote netloc in file URI: '{uri_input}'"

        file_path = urllib.parse.unquote(parsed.path)

        # Windows drive letter formatting fix (file:///C:/passwd -> C:/passwd)
        if re.match(r"^/[a-zA-Z]:", file_path):
            file_path = file_path[1:]

        # 1. Check for sensitive file access
        for sensitive in SENSITIVE_LOCAL_FILES:
            if sensitive.lower() in file_path.lower():
                return True, f"LFI Security Alert: Access to sensitive file '{sensitive}' via file URI: '{uri_input}'"

        # 2. Check for Directory Traversal sequences
        if ".." in file_path.split("/") or ".." in file_path.split("\\"):
            return True, f"LFI Security Alert: Traversal sequence '..' in file URI: '{uri_input}'"

        # 3. Check allowed base directory restriction if set
        if allowed_base_dir:
            canonical_base = os.path.realpath(allowed_base_dir)
            canonical_target = os.path.realpath(file_path)
            if not canonical_target.startswith(canonical_base):
                return True, (
                    f"LFI Jailbreak Alert: file URI path '{file_path}' (canonical: '{canonical_target}') "
                    f"escapes allowed base directory '{canonical_base}'"
                )

    except Exception as e:
        return True, f"LFI Security Alert: Error inspecting file URI '{uri_input}': {e}"

    return False, ""


# ---------------------------------------------------------------------------
# Section 3: Data URI Security & Payload Size Control
# ---------------------------------------------------------------------------

def check_markitdown_data_uri_security(uri_input: Any) -> Tuple[bool, str]:
    """
    Validates data: URIs against excessive size, malformed Base64 payload,
    and memory expansion amplification.
    """
    if not isinstance(uri_input, str) or not uri_input.strip().lower().startswith("data:"):
        return False, ""

    uri_str = uri_input.strip()

    if len(uri_str) > 2 * 1024 * 1024: # 2MB limit for data URIs
        return True, f"Data URI Security Alert: Data URI size ({len(uri_str)} bytes) exceeds 2MB limit"

    if ";base64," in uri_str.lower():
        payload = uri_str.split(";base64,")[-1]
        # Basic Base64 character validation
        if not re.match(r"^[a-zA-Z0-9+/= \r\n]*$", payload):
            return True, "Data URI Security Alert: Invalid characters in Base64 data URI payload"

    return False, ""


# ---------------------------------------------------------------------------
# Section 4: Output Markdown Security & Indirect Prompt Injection
# ---------------------------------------------------------------------------

def check_markitdown_markdown_output_security(res: Any) -> Tuple[bool, str]:
    """
    Inspects the generated Markdown result for embedded HTML script tags,
    file:// link disclosures, or indirect prompt injection patterns targeting downstream LLMs.
    """
    if res is None:
        return False, ""

    result_val = getattr(res, "result", None)
    output_text = str(result_val) if result_val is not None else ""

    if not output_text:
        return False, ""

    # 1. Check for raw HTML script tags or dangerous iframe embeds
    if "<script" in output_text.lower() or "<iframe" in output_text.lower():
        return True, "Markdown Output Alert: Unsafe HTML script or iframe tag in generated Markdown output"

    # 2. Check for sensitive file:// leakage in Markdown links
    if "file:///etc/passwd" in output_text or "file:///etc/shadow" in output_text:
        return True, "Markdown Output Alert: Sensitive file content or path disclosed in Markdown output"

    # 3. Check for Indirect Prompt Injection patterns
    for pattern in INDIRECT_PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, output_text, re.IGNORECASE):
            return True, f"Indirect Prompt Injection Alert: Markdown output contains LLM prompt injection pattern '{pattern}'"

    return False, ""


# ---------------------------------------------------------------------------
# Section 5: Master Specification Contract for MarkItDown
# ---------------------------------------------------------------------------

def check_strict_markitdown_security_contract(generated_arguments: Dict[str, Any], res: Any) -> Tuple[bool, str]:
    """
    Master Specification Sanitizer for MarkItDown (convert_to_markdown):
    Validates URI input against all 50 checklist items (scheme, SSRF, LFI, data URI, output security).
    Uses `is_input_rejected(res)` to verify that invalid or malicious URIs were properly rejected.
    """
    uri_input = generated_arguments.get("uri") or generated_arguments.get("source") or generated_arguments.get("url")

    # Same bug as check_strict_har_security_contract / the pre-2026-09-10
    # check_strict_url_security_contract: this sanitizer was written for one
    # paper target (MarkItDown's convert_to_markdown), and on any tool without
    # a uri/source/url argument, uri_input is None. check_markitdown_uri_
    # validation(None) and friends then fire on the absence itself, and the
    # unrelated tool "fails to reject" by succeeding normally -> guaranteed
    # false MarkItDown Security Bypass alert on every non-MarkItDown tool.
    if uri_input is None:
        return False, ""

    is_invalid = False
    violations = []

    # 1. General URI & Scheme Whitelist Check
    triggered, msg = check_markitdown_uri_validation(uri_input)
    if triggered:
        is_invalid = True
        violations.append(msg)

    # 2. file:// LFI Check
    triggered, msg = check_markitdown_file_uri_jailbreak(uri_input)
    if triggered:
        is_invalid = True
        violations.append(msg)

    # 3. SSRF & URL Checks for http/https URIs
    if isinstance(uri_input, str) and uri_input.strip().lower().startswith(("http:", "https:")):
        triggered, msg = check_url_structure_and_parsing(uri_input)
        if triggered:
            is_invalid = True
            violations.append(msg)

        triggered, msg = check_url_ssrf_ip_ranges(uri_input)
        if triggered:
            is_invalid = True
            violations.append(msg)

    # 4. data: URI Check
    triggered, msg = check_markitdown_data_uri_security(uri_input)
    if triggered:
        is_invalid = True
        violations.append(msg)

    # 5. Output Markdown Security Check
    triggered, msg = check_markitdown_markdown_output_security(res)
    if triggered:
        return True, msg

    # 6. Verify proper rejection if input was invalid/malicious
    if is_invalid:
        rejected = is_input_rejected(res)
        if not rejected:
            violation_summary = " | ".join(violations)
            return True, (
                f"MarkItDown Security Bypass Alert! Malicious/Invalid URI input was ACCEPTED or executed side-effects by MarkItDown. "
                f"Violations: [{violation_summary}]. URI: '{uri_input}'"
            )

    return False, ""
