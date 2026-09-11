"""
Dedicated URL & HTTP Security Sanitizers for MCP / Python Tool Fuzzing.

Implements input validation, URL structure checks, hostname canonicalization,
alternative IP detection, SSRF IP range filtering, and execution contract verification.
"""

import re
import urllib.parse
import ipaddress
import unicodedata
from typing import Tuple, Dict, Any, Optional

# ---------------------------------------------------------------------------
# Helper: Rejection Signal Detector
# ---------------------------------------------------------------------------

def is_input_rejected(res: Any) -> bool:
    """
    Determines if a target tool rejected an input, combining 4 signals:
    1. Explicit Exception / Error code (`res.success == False` or `res.error`)
    2. Absence of introspective side-effects (no network connections, file writes, or process executions)
    3. Rejection keywords in output string / stdout
    4. Fallback / empty return values (None, "", [], {})
    """
    if res is None:
        return True

    # Signal 1: Explicit exception or error status
    if hasattr(res, "success") and not res.success:
        return True
    if hasattr(res, "error") and res.error:
        return True

    # Signal 2: Absence of side effects (Introspection check)
    net_calls = getattr(res, "network_connections", [])
    cmd_calls = getattr(res, "executed_commands", [])
    written_files = getattr(res, "written_files", [])

    # If side-effects occurred (socket opened, process spawned, file written), input was NOT rejected
    if len(net_calls) > 0 or len(cmd_calls) > 0 or len(written_files) > 0:
        return False

    # Signal 3: Textual error signatures in tool output
    result_val = getattr(res, "result", None)
    output_str = str(result_val).lower() if result_val is not None else ""
    
    rejection_keywords = [
        "error", "invalid", "rejected", "failed", "malformed", 
        "unsupported", "refused", "forbidden", "[!]", "bad argument", "missing scheme"
    ]
    if any(keyword in output_str for keyword in rejection_keywords):
        return True

    # Signal 4: Empty / fallback return structure
    if result_val in (None, "", [], {}):
        return True

    return False


# ---------------------------------------------------------------------------
# 1. Raw Input Validation
# ---------------------------------------------------------------------------

def check_url_raw_input_validation(url: Any) -> Tuple[bool, str]:
    r"""
    Validates raw input string:
    - Type exactness (must be str)
    - Non-empty & length limit (<= 2048 chars)
    - Control characters (NUL, CR, LF, tab, Unicode control)
    - Spaces (raw spaces, non-breaking spaces, Unicode separators)
    - Unicode normalization & ambiguous characters (\, bidi chars, homoglyph slashes/dots)
    """
    if not isinstance(url, str):
        return True, f"Raw Input Error: Expected str type, got {type(url).__name__}"

    if not url or url.isspace():
        return True, "Raw Input Error: Empty or whitespace-only URL"

    if len(url) > 2048:
        return True, f"Raw Input Error: URL length ({len(url)}) exceeds maximum limit of 2048 characters"

    # Control characters (\x00, \r, \n, \t, etc.)
    for i, char in enumerate(url):
        char_code = ord(char)
        if char_code < 32 or char_code == 127:
            return True, f"Raw Input Error: Control character detected at index {i} (code {hex(char_code)})"
        cat = unicodedata.category(char)
        if cat.startswith("C"):  # Other / Control / Format / Surrogate
            return True, f"Raw Input Error: Unicode control/format character detected: U+{char_code:04X} ({cat})"

    # Spaces & Unicode separators
    for i, char in enumerate(url):
        if char in (" ", "\t", "\r", "\n", "\u00a0"):
            return True, f"Raw Input Error: Space character detected at index {i}"
        cat = unicodedata.category(char)
        if cat.startswith("Z"):  # Separator
            return True, f"Raw Input Error: Unicode whitespace separator detected: U+{ord(char):04X} ({cat})"

    # Ambiguous characters
    if "\\" in url:
        return True, "Raw Input Error: Backslash '\\' character detected"

    # Slashes, dots, colons, at-signs lookalikes in Unicode
    ambiguous_unicode = [
        "\u2044", "\u2215", "\uff0f",  # Slashes
        "\uff0e", "\u2024",           # Dots
        "\uff1a",                     # Colon
        "\uff20"                      # At sign
    ]
    for char in ambiguous_unicode:
        if char in url:
            return True, f"Raw Input Error: Ambiguous Unicode separator/delimiter detected: U+{ord(char):04X}"

    # Bidirectional control characters
    bidi_chars = [
        "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
        "\u2066", "\u2067", "\u2068", "\u2069"
    ]
    for char in bidi_chars:
        if char in url:
            return True, f"Raw Input Error: Bidirectional Unicode control character detected: U+{ord(char):04X}"

    # Unicode NFC normalization check
    nfc_url = unicodedata.normalize("NFC", url)
    if nfc_url != url:
        # Check if non-NFC string changes critically when normalized
        if nfc_url.lower() != url.lower():
            return True, "Raw Input Error: Significant mutation detected after Unicode NFC normalization"

    return False, ""


# ---------------------------------------------------------------------------
# 2. URL Parsing & Structure Validation
# ---------------------------------------------------------------------------

def check_url_structure_and_parsing(url: str) -> Tuple[bool, str]:
    """
    Validates URL structure using urllib.parse.urlsplit:
    - Absolute URL requirement (scheme and hostname present)
    - Scheme whitelist (https/http only, lowercased)
    - Non-empty hostname
    - Rejection of embedded userinfo (username:password@host)
    - Port numeric validation and range whitelist (1-65535, default 80/443)
    - Rejection of URL fragments (#...)
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception as e:
        return True, f"Parsing Error: Failed to parse URL with urlsplit: {e}"

    if not parsed.scheme:
        return True, "Structure Error: Missing scheme (relative URL or missing http/https)"

    scheme_lower = parsed.scheme.lower()

    # Scheme Whitelist (http, https only)
    forbidden_schemes = [
        "file", "ftp", "gopher", "data", "javascript", "dict", "ldap", "smb", 
        "php", "expect", "glob", "phar", "zip", "tftp", "telnet", "ssh"
    ]
    if scheme_lower in forbidden_schemes:
        return True, f"Structure Error: Forbidden scheme '{parsed.scheme}' detected"

    if scheme_lower not in ("http", "https"):
        return True, f"Structure Error: Scheme '{parsed.scheme}' not in whitelist (http, https)"

    # Require non-empty hostname
    if not parsed.netloc or not parsed.hostname:
        return True, "Structure Error: Missing or empty hostname (e.g. https:///path)"

    # Rejection of userinfo (user@host or user:pass@host)
    if parsed.username or parsed.password or "@" in parsed.netloc:
        return True, f"Structure Error: Embedded user credentials (userinfo) detected in URL authority: '{parsed.netloc}'"

    # Port validation
    if parsed.port is not None:
        if not (1 <= parsed.port <= 65535):
            return True, f"Structure Error: Port {parsed.port} out of valid range (1-65535)"
        
        # Whitelist standard web ports (80, 443) and reject internal/admin ports
        allowed_ports = (80, 443)
        if parsed.port not in allowed_ports:
            return True, f"Structure Error: Non-standard port {parsed.port} not in whitelist {allowed_ports}"

    # Rejection of Fragment (#...)
    if parsed.fragment or "#" in url:
        return True, "Structure Error: URL fragment (#...) detected"

    return False, ""


# ---------------------------------------------------------------------------
# 3. Hostname Canonicalization & Domain Validation
# ---------------------------------------------------------------------------

def check_url_hostname_canonicalization(url: str) -> Tuple[bool, str]:
    """
    Validates canonicalization of the hostname:
    - Trailing dot stripping (`example.com.`)
    - IDNA / Punycode conversion validation
    - Label length & character validation
    - Detection of homoglyphs and mixed scripts (e.g., Cyrillic + Latin)
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
    except Exception:
        return True, "Canonicalization Error: Cannot extract hostname"

    if not hostname:
        return True, "Canonicalization Error: Hostname is empty"

    # Remove trailing dot for check
    clean_host = hostname.rstrip(".")

    # Convert IDNA to ASCII
    try:
        idna_ascii = clean_host.encode("idna").decode("ascii").lower()
    except Exception as e:
        return True, f"Canonicalization Error: IDNA Punycode conversion failed for '{clean_host}': {e}"

    # Validate DNS Labels
    labels = idna_ascii.split(".")
    for label in labels:
        if not label:
            return True, f"Canonicalization Error: Empty label found in domain '{idna_ascii}'"
        if len(label) > 63:
            return True, f"Canonicalization Error: DNS label '{label}' exceeds 63 characters"
        if label.startswith("-") or label.endswith("-"):
            return True, f"Canonicalization Error: DNS label '{label}' cannot start or end with a hyphen"
        if not re.match(r"^[a-z0-9\-]+$", label):
            return True, f"Canonicalization Error: Invalid characters in DNS label '{label}'"

    # Check total domain length
    if len(idna_ascii) > 253:
        return True, f"Canonicalization Error: Total domain length ({len(idna_ascii)}) exceeds 253 characters"

    # Mixed-script / Homoglyph detection (e.g. Cyrillic characters mixed with Latin)
    scripts = set()
    for char in clean_host:
        if char.isalpha():
            name = unicodedata.name(char, "")
            script = name.split()[0] if name else "UNKNOWN"
            scripts.add(script)
            
    if len(scripts) > 1 and "LATIN" in scripts:
        return True, f"Canonicalization Error: Mixed Unicode script detected in domain '{clean_host}': {scripts}"

    return False, ""


# ---------------------------------------------------------------------------
# 4. Alternative IP Address Representations
# ---------------------------------------------------------------------------

def check_url_alternative_ip_representations(url: str) -> Tuple[bool, str]:
    """
    Detects non-canonical / alternative IP representations:
    - Decimal integer IPv4 (e.g., 2130706433)
    - Octal IPv4 (e.g., 0177.0.0.1)
    - Hexadecimal IPv4 (e.g., 0x7f.0.0.1)
    - Short IPv4 notation (e.g., 127.1)
    - IPv6 bracket handling and IPv6 scope IDs (%eth0)
    - IPv4-mapped IPv6 addresses (::ffff:127.0.0.1)
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        raw_host = parsed.hostname or ""
    except Exception:
        return True, "IP Representation Error: Cannot parse hostname"

    if not raw_host:
        return False, ""

    # Check for IPv6 scope ID / zone identifier (e.g. [fe80::1%eth0])
    if "%" in raw_host:
        return True, f"IP Representation Error: IPv6 zone identifier / scope ID detected: '{raw_host}'"

    # Strip brackets if IPv6
    clean_host = raw_host.strip("[]")

    # Octal (0177.0.0.1) or Hex (0x7f000001) or Decimal Integer (2130706433) or Short (127.1)
    if re.match(r"^(0[0-7]+|0x[0-9a-fA-F]+|\d+)$", clean_host):
        return True, f"IP Representation Error: Non-canonical integer/octal/hex IPv4 detected: '{clean_host}'"
        
    if re.match(r"^0[0-7]+\.", clean_host) or re.match(r"^0x[0-9a-fA-F]+\.", clean_host):
        return True, f"IP Representation Error: Non-canonical octal or hex IPv4 notation detected: '{clean_host}'"

    # Short form IPv4 (e.g. 127.1 or 10.1)
    parts = clean_host.split(".")
    if 1 < len(parts) < 4 and all(p.isdigit() for p in parts):
        return True, f"IP Representation Error: Shortened non-canonical IPv4 notation detected: '{clean_host}'"

    # Parse with ipaddress module
    try:
        ip_obj = ipaddress.ip_address(clean_host)
        
        # Check IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.ipv4_mapped:
                mapped_v4 = ip_obj.ipv4_mapped
                return True, f"IP Representation Error: IPv4-mapped IPv6 address detected pointing to '{mapped_v4}'"
                
    except ValueError:
        # Not a raw IP literal (probably a domain name)
        pass

    return False, ""


# ---------------------------------------------------------------------------
# 5. SSRF IP & Internal Hostname Protection
# ---------------------------------------------------------------------------

def check_url_ssrf_ip_ranges(url: str) -> Tuple[bool, str]:
    """
    Monitors hostnames and IP addresses against SSRF targets:
    - Loopback (127.0.0.0/8, ::1)
    - Private RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - IPv6 Unique Local (fc00::/7)
    - Link-Local (169.254.0.0/16, fe80::/10)
    - Unspecified (0.0.0.0, ::)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Reserved / CGNAT (100.64.0.0/10)
    - Cloud Metadata IPs (169.254.169.254)
    - Internal hostnames (localhost, db, redis, kubernetes, .local, .internal, .localhost)
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = (parsed.hostname or "").rstrip(".").lower()
    except Exception:
        return True, "SSRF Check Error: Cannot parse hostname"

    if not hostname:
        return True, "SSRF Check Error: Empty hostname"

    # Internal Hostnames Whitelist / Blacklist
    internal_names = [
        "localhost", "db", "redis", "postgres", "mysql", "mongodb", "elasticsearch", 
        "rabbitmq", "kafka", "kubernetes", "k8s", "consul", "vault", "etcd", "metadata"
    ]
    if hostname in internal_names:
        return True, f"SSRF Protection Alert: Internal service hostname detected: '{hostname}'"

    internal_tlds = (".local", ".internal", ".localhost", ".lan", ".home", ".corp")
    if any(hostname.endswith(tld) for tld in internal_tlds):
        return True, f"SSRF Protection Alert: Internal TLD domain detected: '{hostname}'"

    # Cloud Metadata Names
    metadata_domains = [
        "metadata.google.internal", "instance-data", "169.254.169.254"
    ]
    if any(m_dom in hostname for m_dom in metadata_domains):
        return True, f"SSRF Protection Alert: Cloud Metadata target detected: '{hostname}'"

    # Evaluate IP Address ranges if literal IP
    clean_ip_str = hostname.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(clean_ip_str)

        # 1. Loopback
        if ip_obj.is_loopback:
            return True, f"SSRF Protection Alert: Loopback IP address detected: {ip_obj}"

        # 2. Private networks (RFC 1918 / IPv6 Unique Local)
        if ip_obj.is_private:
            return True, f"SSRF Protection Alert: Private network IP address detected: {ip_obj}"

        # 3. Link-local (including 169.254.169.254)
        if ip_obj.is_link_local:
            return True, f"SSRF Protection Alert: Link-local IP address detected: {ip_obj}"

        # 4. Unspecified (0.0.0.0, ::)
        if ip_obj.is_unspecified:
            return True, f"SSRF Protection Alert: Unspecified IP address detected: {ip_obj}"

        # 5. Multicast
        if ip_obj.is_multicast:
            return True, f"SSRF Protection Alert: Multicast IP address detected: {ip_obj}"

        # 6. Reserved / Special-use
        if ip_obj.is_reserved:
            return True, f"SSRF Protection Alert: Reserved IP address detected: {ip_obj}"

        # CGNAT Check (100.64.0.0/10)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            cgnat_network = ipaddress.ip_network("100.64.0.0/10")
            if ip_obj in cgnat_network:
                return True, f"SSRF Protection Alert: CGNAT IP address detected: {ip_obj}"

    except ValueError:
        # Not an IP literal, standard hostname
        pass

    return False, ""


# ---------------------------------------------------------------------------
# Master Sanitizer: Specification Contract Verification
# ---------------------------------------------------------------------------

def _URLISH(name: str) -> bool:
    n = name.lower()
    return ("url" in n or "uri" in n or "link" in n or "endpoint" in n
            or "href" in n or "address" in n)


def _find_url_argument(generated_arguments: Dict[str, Any]):
    """The URL-valued argument, whatever it is called, or None.

    Handles the three shapes seen in real MCP schemas: a plain string
    (`url`, `targetUrl`, `endpoint`), a list of strings (`urls`), and a
    mapping whose VALUES are URLs (`urlMap` in bing-cn-mcp-server). Returns the
    first string that actually looks like a URL so the checks below have
    something real to evaluate; returns None when the tool has no URL argument
    at all, which is the signal to stay silent.
    """
    if not isinstance(generated_arguments, dict):
        return None
    candidates = []
    for k, v in generated_arguments.items():
        if not _URLISH(k):
            continue
        if isinstance(v, str):
            candidates.append(v)
        elif isinstance(v, dict):
            candidates.extend(x for x in v.values() if isinstance(x, str))
        elif isinstance(v, (list, tuple)):
            candidates.extend(x for x in v if isinstance(x, str))
    if not candidates:
        return None
    # Prefer something with a scheme separator; otherwise the first string.
    return next((c for c in candidates if "://" in c or ":" in c), candidates[0])


def check_strict_url_security_contract(generated_arguments: Dict[str, Any], res: Any) -> Tuple[bool, str]:
    """
    Master Specification Sanitizer for http_check.py:
    Runs the complete checklist of URL security checks against the 'url' argument.
    Uses `is_input_rejected(res)` to verify that invalid or malicious inputs
    were properly rejected by the target tool without initiating network calls.
    """
    # FIND the URL argument instead of assuming it is literally named "url".
    #
    # This was `generated_arguments.get("url")`, written for
    # targets/fuzz_http_check.py whose argument IS called url. The LLM selects
    # it for any URL-ish tool, and on a tool with a differently named argument
    # url_input was None -- whereupon every sub-check below fires on None
    # ("Expected str type, got NoneType", "Missing scheme", "Hostname is
    # empty") and the contract reports a Validation Bypass on every single
    # input. Measured 2026-09-10 on yan5236/bing-cn-mcp-server::crawl_webpage,
    # whose argument is `urlMap`: 19 alerts, all of them this, all reporting
    # "Input: 'None'".
    #
    # A sanitizer that cannot find the argument it is about must return False,
    # not fire. Silence is the correct answer to "not applicable"; firing is a
    # false positive that costs a reviewer's trust.
    url_input = _find_url_argument(generated_arguments)
    if url_input is None:
        return False, ""

    # 1. Evaluate input against all security checklist categories
    checkers = [
        check_url_raw_input_validation,
        check_url_structure_and_parsing,
        check_url_hostname_canonicalization,
        check_url_alternative_ip_representations,
        check_url_ssrf_ip_ranges
    ]

    is_invalid = False
    violations = []

    for check_func in checkers:
        triggered, err_msg = check_func(url_input)
        if triggered:
            is_invalid = True
            violations.append(err_msg)

    # 2. If the input violated the security policy, verify that http_check.py REJECTED it
    if is_invalid:
        rejected = is_input_rejected(res)
        if not rejected:
            violation_summary = " | ".join(violations)
            return True, (
                f"Validation Bypass Alert! Malicious/Invalid URL input was ACCEPTED or executed side-effects by target tool. "
                f"Violations: [{violation_summary}]. Input: '{url_input}'"
            )

    return False, ""
