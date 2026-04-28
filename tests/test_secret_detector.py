"""Additional secret detector edge-case tests."""
import pytest
from apkanalyzer.analysis.detectors.secret_detector import SecretDetector, shannon_entropy, _BASE64_CHARS, _HEX_CHARS


class TestEntropyEdgeCases:
    def test_empty_string(self):
        assert shannon_entropy("", _BASE64_CHARS) == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaaaaa", _BASE64_CHARS) == 0.0

    def test_uniform_distribution_max_entropy(self):
        s = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        e = shannon_entropy(s, _BASE64_CHARS)
        assert e > 5.5  # theoretical max for 64-char alphabet ≈ 6 bits

    def test_hex_entropy(self):
        e = shannon_entropy("deadbeef1234567890abcdef", _HEX_CHARS)
        assert e > 2.5


class TestFalsePositiveSuppression:
    def setup_method(self):
        self.d = SecretDetector()

    def test_resource_id_not_flagged(self):
        findings = self.d.scan_string_pool(["2131099685"], "<test>")
        assert findings == []

    def test_git_sha_not_aws(self):
        # 40-char hex strings are git SHAs — should NOT match AWS key pattern
        findings = self.d.scan_string_pool(
            ["a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"], "<test>"
        )
        aws = [f for f in findings if f.rule_id == "SECRET_AWS_KEY"]
        assert aws == []

    def test_base64_image_low_entropy_not_flagged(self):
        # Repeated base64 block — not a real secret
        fake_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        findings = self.d.scan_string_pool([fake_b64], "<test>")
        # Should not be flagged because entropy is near 0
        assert findings == []

    def test_jwt_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = self.d.scan_string_pool([jwt], "<test>")
        assert any(f.rule_id == "SECRET_JWT" for f in findings)
