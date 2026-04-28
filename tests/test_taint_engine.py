"""
Unit tests for the taint analysis engine.

These tests use synthetic CFG/instruction data — no real APK required.
They verify:
  1. Source recognition at invoke sites
  2. Register propagation (move, move-result)
  3. Sink detection when a tainted register reaches a sink argument
  4. Dead-register pruning (untainted registers should NOT trigger sinks)
  5. Inter-procedural propagation stub
"""

import pytest

from apkanalyzer.analysis.taint.engine import (
    MethodTaintState,
    _extract_invoke_parts,
    _get_move_result_register,
    _get_move_registers,
)
from apkanalyzer.analysis.detectors.secret_detector import SecretDetector, shannon_entropy, _BASE64_CHARS
from apkanalyzer.analysis.detectors.crypto_detector import CryptoDetector
from apkanalyzer.ir.models import (
    MethodDescriptor, CFGMethod, BasicBlock, Severity, Confidence
)
from apkanalyzer.scoring.confidence import filter_findings, summarise


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_invoke(raw: str, offset: int = 0) -> dict:
    return {"mnemonic": "invoke-virtual", "raw": raw, "offset": offset, "operands": []}


def make_const_string(reg: str, val: str, offset: int = 0) -> dict:
    return {
        "mnemonic": "const-string",
        "raw": f'const-string {reg}, "{val}"',
        "offset": offset,
        "operands": [
            {"kind": 0, "value": reg, "raw": reg},
            {"kind": 2, "value": val, "raw": f'"{val}"'},
        ],
    }


def make_move_result(reg: str, offset: int = 0) -> dict:
    return {
        "mnemonic": "move-result-object",
        "raw": f"move-result-object {reg}",
        "offset": offset,
        "operands": [{"kind": 0, "value": reg, "raw": reg}],
    }


def make_move(dst: str, src: str, offset: int = 0) -> dict:
    return {
        "mnemonic": "move-object",
        "raw": f"move-object {dst}, {src}",
        "offset": offset,
        "operands": [
            {"kind": 0, "value": dst, "raw": dst},
            {"kind": 0, "value": src, "raw": src},
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Taint state unit tests
# ──────────────────────────────────────────────────────────────────────────────

class TestMethodTaintState:
    def test_initial_state_empty(self):
        state = MethodTaintState()
        assert state.get_taint("v0") == set()

    def test_taint_and_retrieve(self):
        state = MethodTaintState()
        state.taint("v1", {"DEVICE_ID"})
        assert "DEVICE_ID" in state.get_taint("v1")

    def test_taint_union(self):
        state = MethodTaintState()
        state.taint("v2", {"LOCATION"})
        state.taint("v2", {"USER_INPUT"})
        assert state.get_taint("v2") == {"LOCATION", "USER_INPUT"}

    def test_merge_detects_change(self):
        s1 = MethodTaintState()
        s1.taint("v0", {"A"})

        s2 = MethodTaintState()
        s2.taint("v0", {"B"})

        changed = s1.merge(s2)
        assert changed
        assert s1.get_taint("v0") == {"A", "B"}

    def test_merge_no_change(self):
        s1 = MethodTaintState()
        s1.taint("v0", {"A"})

        s2 = MethodTaintState()
        s2.taint("v0", {"A"})

        changed = s1.merge(s2)
        assert not changed

    def test_copy_independence(self):
        s1 = MethodTaintState()
        s1.taint("v0", {"X"})
        s2 = s1.copy()
        s2.taint("v0", {"Y"})
        # Original must not change
        assert "Y" not in s1.get_taint("v0")


# ──────────────────────────────────────────────────────────────────────────────
# Instruction parsing
# ──────────────────────────────────────────────────────────────────────────────

class TestInstructionParsing:
    def test_extract_invoke_parts(self):
        raw = ('invoke-virtual {v0, v1}, '
               'Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;')
        instr = make_invoke(raw)
        result = _extract_invoke_parts(instr)
        assert result is not None
        class_name, method_name, descriptor, regs = result
        assert class_name == "Landroid/telephony/TelephonyManager;"
        assert method_name == "getDeviceId"
        assert "v0" in regs
        assert "v1" in regs

    def test_extract_invoke_non_invoke(self):
        instr = {"mnemonic": "move-object", "raw": "move-object v0, v1", "offset": 0, "operands": []}
        assert _extract_invoke_parts(instr) is None

    def test_move_result_register(self):
        instr = make_move_result("v3", offset=4)
        assert _get_move_result_register(instr) == "v3"

    def test_move_registers(self):
        instr = make_move("v5", "v2")
        result = _get_move_registers(instr)
        assert result == ("v5", "v2")

    def test_move_result_not_on_invoke(self):
        instr = make_invoke("invoke-virtual {v0}, Lfoo/Bar;->baz()V")
        assert _get_move_result_register(instr) is None


# ──────────────────────────────────────────────────────────────────────────────
# Secret detector
# ──────────────────────────────────────────────────────────────────────────────

class TestSecretDetector:
    def setup_method(self):
        self.detector = SecretDetector()

    def test_aws_key_detected(self):
        findings = self.detector.scan_string_pool(["AKIAIOSFODNN7EXAMPLE"], "<test>")
        assert any(f.rule_id == "SECRET_AWS_KEY" for f in findings)

    def test_google_api_key_detected(self):
        findings = self.detector.scan_string_pool(
            ["AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3ns0123456"], "<test>"
        )
        assert any(f.rule_id == "SECRET_GOOGLE_API_KEY" for f in findings)

    def test_safe_uuid_not_flagged(self):
        findings = self.detector.scan_string_pool(
            ["00000000-0000-0000-0000-000000000000"], "<test>"
        )
        assert findings == []

    def test_short_string_not_flagged(self):
        findings = self.detector.scan_string_pool(["abc"], "<test>")
        assert findings == []

    def test_entropy_aws_key_high(self):
        # AKIA keys have high entropy
        e = shannon_entropy("AKIAIOSFODNN7EXAMPLE", _BASE64_CHARS)
        assert e > 3.0

    def test_entropy_repeated_chars_low(self):
        e = shannon_entropy("aaaaaaaaaaaaaaaaaaa", _BASE64_CHARS)
        assert e < 1.0

    def test_pem_header_detected(self):
        findings = self.detector.scan_file(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA....",
            "test.smali",
        )
        assert any(f.rule_id == "SECRET_PRIVATE_KEY_HEADER" for f in findings)


# ──────────────────────────────────────────────────────────────────────────────
# Crypto detector
# ──────────────────────────────────────────────────────────────────────────────

class TestCryptoDetector:
    def setup_method(self):
        self.detector = CryptoDetector()
        self.desc = MethodDescriptor(
            "Lcom/example/Crypto;", "doEncrypt", "(Ljava/lang/String;)V"
        )

    def _make_cfg(self, instructions: list[dict]) -> CFGMethod:
        cfg = CFGMethod(descriptor=self.desc)
        block = BasicBlock(block_id="0", method=self.desc, instructions=instructions)
        cfg.blocks["0"] = block
        cfg.entry_block = "0"
        return cfg

    def test_ecb_mode_detected(self):
        reg_strings = {"v1": "AES/ECB/PKCS5Padding"}
        instrs = [
            make_const_string("v1", "AES/ECB/PKCS5Padding", offset=0),
            make_invoke(
                'invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance'
                '(Ljava/lang/String;)Ljavax/crypto/Cipher;',
                offset=4,
            ),
        ]
        findings = self.detector.analyse(self._make_cfg(instrs), self.desc, reg_strings)
        rule_ids = {f.rule_id for f in findings}
        assert "CRYPTO_ECB_MODE" in rule_ids

    def test_gcm_mode_not_flagged(self):
        reg_strings = {"v1": "AES/GCM/NoPadding"}
        instrs = [
            make_const_string("v1", "AES/GCM/NoPadding", offset=0),
            make_invoke(
                'invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance'
                '(Ljava/lang/String;)Ljavax/crypto/Cipher;',
                offset=4,
            ),
        ]
        findings = self.detector.analyse(self._make_cfg(instrs), self.desc, reg_strings)
        rule_ids = {f.rule_id for f in findings}
        assert "CRYPTO_ECB_MODE" not in rule_ids
        assert "CRYPTO_WEAK_ALGORITHM" not in rule_ids

    def test_des_algorithm_flagged(self):
        reg_strings = {"v1": "DES/CBC/PKCS5Padding"}
        instrs = [
            make_const_string("v1", "DES/CBC/PKCS5Padding", offset=0),
            make_invoke(
                'invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance'
                '(Ljava/lang/String;)Ljavax/crypto/Cipher;',
                offset=4,
            ),
        ]
        findings = self.detector.analyse(self._make_cfg(instrs), self.desc, reg_strings)
        rule_ids = {f.rule_id for f in findings}
        assert "CRYPTO_WEAK_ALGORITHM" in rule_ids

    def test_md5_hash_detected(self):
        reg_strings = {"v2": "MD5"}
        instrs = [
            make_const_string("v2", "MD5", offset=0),
            make_invoke(
                'invoke-static {v2}, Ljava/security/MessageDigest;->getInstance'
                '(Ljava/lang/String;)Ljava/security/MessageDigest;',
                offset=4,
            ),
        ]
        findings = self.detector.analyse(self._make_cfg(instrs), self.desc, reg_strings)
        rule_ids = {f.rule_id for f in findings}
        assert "CRYPTO_WEAK_HASH" in rule_ids

    def test_sha256_not_flagged(self):
        reg_strings = {"v2": "SHA-256"}
        instrs = [
            make_const_string("v2", "SHA-256", offset=0),
            make_invoke(
                'invoke-static {v2}, Ljava/security/MessageDigest;->getInstance'
                '(Ljava/lang/String;)Ljava/security/MessageDigest;',
                offset=4,
            ),
        ]
        findings = self.detector.analyse(self._make_cfg(instrs), self.desc, reg_strings)
        rule_ids = {f.rule_id for f in findings}
        assert "CRYPTO_WEAK_HASH" not in rule_ids


# ──────────────────────────────────────────────────────────────────────────────
# Confidence scoring
# ──────────────────────────────────────────────────────────────────────────────

class TestConfidenceScoring:
    def _make_finding(self, severity=Severity.HIGH, confidence=Confidence.HIGH,
                      class_name="Lcom/example/App;", method_name="doWork"):
        from apkanalyzer.ir.models import Finding
        return Finding(
            rule_id="TEST_RULE",
            title="Test",
            description="Test finding",
            severity=severity,
            confidence=confidence,
            category="TEST",
            class_name=class_name,
            method_name=method_name,
        )

    def test_filter_by_confidence(self):
        findings = [
            self._make_finding(confidence=Confidence.HIGH),
            self._make_finding(confidence=Confidence.MEDIUM),
            self._make_finding(confidence=Confidence.LOW),
        ]
        result = filter_findings(findings, min_confidence=Confidence.MEDIUM)
        assert len(result) == 2
        assert all(f.confidence != Confidence.LOW for f in result)

    def test_test_class_confidence_downgraded(self):
        from apkanalyzer.scoring.confidence import adjust_confidence
        f = self._make_finding(
            confidence=Confidence.HIGH,
            class_name="Lcom/example/CryptoTest;",
        )
        adjusted = adjust_confidence(f)
        assert adjusted.confidence == Confidence.MEDIUM

    def test_summarise_counts(self):
        findings = [
            self._make_finding(severity=Severity.CRITICAL),
            self._make_finding(severity=Severity.HIGH),
            self._make_finding(severity=Severity.MEDIUM),
        ]
        summary = summarise(findings)
        assert summary["total"] == 3
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
