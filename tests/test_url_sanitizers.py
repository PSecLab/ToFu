import unittest
from src.sanitizers.url_sanitizers import (
    check_url_raw_input_validation,
    check_url_structure_and_parsing,
    check_url_hostname_canonicalization,
    check_url_alternative_ip_representations,
    check_url_ssrf_ip_ranges,
    check_strict_url_security_contract,
    is_input_rejected
)
from src.runners.base import RunnerResult

class TestURLSanitizers(unittest.TestCase):

    def test_raw_input_validation(self):
        # Valid URL input
        triggered, err = check_url_raw_input_validation("https://example.com/api")
        self.assertFalse(triggered)

        # Invalid type
        triggered, err = check_url_raw_input_validation(12345)
        self.assertTrue(triggered)
        self.assertIn("Expected str type", err)

        # Empty / whitespace
        triggered, err = check_url_raw_input_validation("   ")
        self.assertTrue(triggered)
        self.assertIn("Empty or whitespace-only", err)

        # Length > 2048
        triggered, err = check_url_raw_input_validation("https://example.com/" + "a" * 2050)
        self.assertTrue(triggered)
        self.assertIn("exceeds maximum limit", err)

        # Control characters
        triggered, err = check_url_raw_input_validation("https://example.com/\x00admin")
        self.assertTrue(triggered)
        self.assertIn("Control character", err)

        # Newline CRLF
        triggered, err = check_url_raw_input_validation("https://example.com/\r\nHeader: bad")
        self.assertTrue(triggered)

        # Backslash
        triggered, err = check_url_raw_input_validation("https://example.com\\admin")
        self.assertTrue(triggered)
        self.assertIn("Backslash", err)

    def test_structure_and_parsing(self):
        # Valid https
        triggered, err = check_url_structure_and_parsing("https://example.com/path")
        self.assertFalse(triggered)

        # Missing scheme / relative
        triggered, err = check_url_structure_and_parsing("/admin")
        self.assertTrue(triggered)

        # Forbidden scheme (file://)
        triggered, err = check_url_structure_and_parsing("file:///etc/passwd")
        self.assertTrue(triggered)
        self.assertIn("Forbidden scheme", err)

        # Userinfo (user:pass@host)
        triggered, err = check_url_structure_and_parsing("https://admin:secret@example.com/")
        self.assertTrue(triggered)
        self.assertIn("Embedded user credentials", err)

        # Non-whitelisted port
        triggered, err = check_url_structure_and_parsing("https://example.com:8080/")
        self.assertTrue(triggered)
        self.assertIn("Non-standard port", err)

        # Fragment (#...)
        triggered, err = check_url_structure_and_parsing("https://example.com/#section")
        self.assertTrue(triggered)
        self.assertIn("fragment", err)

    def test_hostname_canonicalization(self):
        # Valid domain
        triggered, err = check_url_hostname_canonicalization("https://example.com.")
        self.assertFalse(triggered)

        # Invalid label (starts with hyphen)
        triggered, err = check_url_hostname_canonicalization("https://-badlabel.com")
        self.assertTrue(triggered)

        # Homoglyph / mixed script (cyrillic 'а' in latin domain)
        triggered, err = check_url_hostname_canonicalization("https://pаypal.com")
        self.assertTrue(triggered)
        self.assertIn("Mixed Unicode script", err)

    def test_alternative_ip_representations(self):
        # Decimal int IP (2130706433 = 127.0.0.1)
        triggered, err = check_url_alternative_ip_representations("http://2130706433/")
        self.assertTrue(triggered)

        # Octal IP (0177.0.0.1)
        triggered, err = check_url_alternative_ip_representations("http://0177.0.0.1/")
        self.assertTrue(triggered)

        # Hex IP (0x7f000001)
        triggered, err = check_url_alternative_ip_representations("http://0x7f000001/")
        self.assertTrue(triggered)

        # Short form IP (127.1)
        triggered, err = check_url_alternative_ip_representations("http://127.1/")
        self.assertTrue(triggered)

        # IPv6 zone ID (%eth0)
        triggered, err = check_url_alternative_ip_representations("http://[fe80::1%eth0]/")
        self.assertTrue(triggered)

        # IPv4-mapped IPv6
        triggered, err = check_url_alternative_ip_representations("http://[::ffff:127.0.0.1]/")
        self.assertTrue(triggered)

    def test_ssrf_ip_ranges(self):
        # Loopback
        triggered, err = check_url_ssrf_ip_ranges("http://127.0.0.1/")
        self.assertTrue(triggered)

        # Private RFC 1918 (10.0.0.1)
        triggered, err = check_url_ssrf_ip_ranges("http://10.0.0.1/")
        self.assertTrue(triggered)

        # AWS Cloud Metadata (169.254.169.254)
        triggered, err = check_url_ssrf_ip_ranges("http://169.254.169.254/latest/meta-data/")
        self.assertTrue(triggered)

        # Internal host (localhost, redis)
        triggered, err = check_url_ssrf_ip_ranges("http://localhost:80/")
        self.assertTrue(triggered)

        triggered, err = check_url_ssrf_ip_ranges("http://redis/")
        self.assertTrue(triggered)

    def test_is_input_rejected_helper(self):
        # Case 1: Error result
        res1 = RunnerResult(success=False, coverage=set(), error="ValueError: invalid URL")
        self.assertTrue(is_input_rejected(res1))

        # Case 2: Success result but opened network socket (NOT rejected)
        res2 = RunnerResult(success=True, coverage=set(), result="OK")
        setattr(res2, "network_connections", [{"host": "127.0.0.1", "port": 80}])
        self.assertFalse(is_input_rejected(res2))

        # Case 3: Output contains error string
        res3 = RunnerResult(success=True, coverage=set(), result="[!] Invalid URL structure")
        self.assertTrue(is_input_rejected(res3))

        # Case 4: Output is empty / None
        res4 = RunnerResult(success=True, coverage=set(), result="")
        self.assertTrue(is_input_rejected(res4))

    def test_master_contract_sanitizer(self):
        # Malicious URL that initiated network call -> Bypass Alert!
        res_bypass = RunnerResult(success=True, coverage=set(), result="Success")
        setattr(res_bypass, "network_connections", [{"host": "169.254.169.254", "port": 80}])
        
        triggered, err = check_strict_url_security_contract({"url": "http://169.254.169.254/"}, res_bypass)
        self.assertTrue(triggered)
        self.assertIn("Validation Bypass Alert!", err)

        # Malicious URL that was properly rejected by tool -> No Alert
        res_rejected = RunnerResult(success=False, coverage=set(), error="[!] Invalid destination")
        triggered, err = check_strict_url_security_contract({"url": "http://169.254.169.254/"}, res_rejected)
        self.assertFalse(triggered)

if __name__ == "__main__":
    unittest.main()
