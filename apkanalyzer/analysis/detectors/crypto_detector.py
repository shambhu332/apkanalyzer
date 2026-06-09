"""
Cryptography vulnerability detector.

Checks
------
CRYPTO_ECB_MODE          — Cipher.getInstance("AES/ECB/…") — deterministic, no IV
CRYPTO_WEAK_ALGORITHM    — DES, 3DES, RC4, Blowfish used for security purposes
CRYPTO_WEAK_HASH         — MD5, SHA-1 used in security contexts
CRYPTO_SMALL_KEY         — RSA < 2048-bit, AES < 128-bit key size
CRYPTO_CONSTANT_KEY      — SecretKeySpec constructed (possible hardcoded key)
CRYPTO_INSECURE_RANDOM   — java.util.Random instead of SecureRandom
CRYPTO_STATIC_IV         — IvParameterSpec constructed with constant byte array
CRYPTO_NO_PADDING        — Cipher with NoPadding on CBC (padding oracle risk)
CRYPTO_KEYSTORE_BYPASS   — Key generated outside AndroidKeyStore (software-only)

Cross-method algorithm tracking
-------------------------------
Key-size validation needs to know *which* algorithm the keygen was built for.
A factory pattern hides that information from the call site::

    private KeyPairGenerator newGen() {                  // method A
        return KeyPairGenerator.getInstance("RSA");      // <- algo string here
    }
    void doKey() {                                       // method B
        KeyPairGenerator g = newGen();
        g.initialize(1024);                              // <- key size here
    }

Without cross-method context, method B sees `initialize(1024)` and no
algorithm string, so the detector cannot decide whether 1024 bits is
sufficient (it is for AES-symmetric keys, it is not for RSA).

The orchestrator now performs a pre-pass over every reachable method to
collect declared algorithms per *declaring class* (factories almost
always produce one cipher family per class). That index is passed to
:class:`CryptoDetector` via :func:`set_algorithm_index`; `_check_key_size`
falls back to the class-level algorithm map when the local string pool
yields nothing.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions

logger = logging.getLogger(__name__)

_WEAK_CIPHER_ALGORITHMS = {
    "DES", "DESEDE", "3DES", "3DESEDE", "RC2", "RC4", "RC5", "BLOWFISH",
    "ARCFOUR",
}
_WEAK_HASH_ALGORITHMS = {"MD2", "MD5", "SHA1", "SHA-1"}
_INSECURE_MODES = {"ECB"}
_UNSAFE_PADDING = {"NOPADDING"}  # NoPadding on CBC is padding-oracle vulnerable

# Minimum key sizes (bits) for common algorithms
_MIN_KEY_SIZE = {
    "RSA": 2048, "DSA": 2048, "EC": 224, "ECDSA": 224,
    "AES": 128, "HMAC": 128,
}

_CONST_STRING_RE = re.compile(r'const-string[/\w]* \w+, "([^"]+)"')

# AndroidKeyStore usage — keys generated here are hardware-backed; suppress some findings
_KEYSTORE_PROVIDERS = {"AndroidKeyStore", "AndroidOpenSSL"}

# Class+method patterns whose first string argument is the cipher / KDF
# algorithm name. Used by `build_algorithm_index` to mine factory methods.
_KEYGEN_FACTORIES = (
    "Ljava/security/KeyPairGenerator;->getInstance",
    "Ljavax/crypto/KeyGenerator;->getInstance",
    "Ljava/security/AlgorithmParameters;->getInstance",
    "Ljavax/crypto/SecretKeyFactory;->getInstance",
    "Ljavax/crypto/Cipher;->getInstance",
    "Ljava/security/MessageDigest;->getInstance",
)


def build_algorithm_index(
    candidates: list,
) -> dict[str, set[str]]:
    """Pre-pass that mines algorithm names declared by every method.

    Walks every (cfg, desc, reg_strings) candidate from the orchestrator
    and records each algorithm string passed to a known keygen / cipher
    factory. The resulting `{class_name → {"AES", "RSA", ...}}` map lets
    `CryptoDetector._check_key_size` resolve the algorithm for an
    `initialize(N)` call even when the algorithm string lives in a
    *different* method on the same class (factory pattern).

    The index is keyed by the *declaring class* of the factory call, so
    a class with `getKeyGen()` returning `RSA` then a sister method
    `setKeySize(int)` calling `initialize` recovers the RSA association.
    """
    index: dict[str, set[str]] = {}
    for cfg, desc, _reg_strings in candidates:
        for block in cfg.blocks.values():
            for instr in block.instructions:
                raw = instr.get("raw", "")
                if not any(p in raw for p in _KEYGEN_FACTORIES):
                    continue
                for op in instr.get("operands", []):
                    val = op.get("value")
                    if isinstance(val, str) and 1 <= len(val) <= 64:
                        index.setdefault(desc.class_name, set()).add(val)
    return index


class CryptoDetector:
    """Per-method detector with optional cross-method algorithm hints.

    The detector is stateless across methods *except* for the optional
    `algorithm_index`: a `{class_name → set(algorithm)}` map populated by
    the orchestrator's pre-pass. When the per-method `reg_strings` does
    not yield an algorithm name (factory-pattern keygen), we consult the
    index to discover the algorithm declared elsewhere in the same class.
    """

    def __init__(self, algorithm_index: Optional[dict[str, set[str]]] = None) -> None:
        self.algorithm_index = algorithm_index or {}

    def set_algorithm_index(self, index: dict[str, set[str]]) -> None:
        """Replace the cross-method algorithm map used by `_check_key_size`."""
        self.algorithm_index = index or {}

    def analyse(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        string_pool: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instructions = get_all_instructions(cfg)

        # Build register→string map for this method
        reg_strings: dict[str, str] = dict(string_pool)
        for instr in instructions:
            raw = instr.get("raw", "")
            m = _CONST_STRING_RE.match(raw)
            if m:
                operands = instr.get("operands", [])
                if operands:
                    reg = str(operands[0].get("value", ""))
                    reg_strings[reg] = m.group(1)

        # Track whether this method uses AndroidKeyStore (suppresses some false positives)
        uses_keystore = any(
            any(p in (instr.get("raw", "")) for p in _KEYSTORE_PROVIDERS)
            for instr in instructions
        )

        # Track IvParameterSpec construction registers for static-IV detection
        iv_param_regs: set[str] = set()
        const_byte_regs: set[str] = set()  # registers loaded from const arrays

        for instr in instructions:
            raw = instr.get("raw", "")
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)

            # Track registers that hold constant byte arrays (fill-array-data)
            if "fill-array-data" in mnemonic or "new-array" in mnemonic:
                operands = instr.get("operands", [])
                if operands:
                    const_byte_regs.add(str(operands[0].get("value", "")))

            if not mnemonic.startswith("invoke"):
                continue

            findings.extend(self._check_cipher_getInstance(
                instr, raw, reg_strings, desc, uses_keystore))
            findings.extend(self._check_messageDigest(
                instr, raw, reg_strings, desc))
            findings.extend(self._check_constant_key(
                instr, raw, desc, uses_keystore))
            findings.extend(self._check_insecure_random(instr, raw, desc))
            findings.extend(self._check_static_iv(
                instr, raw, desc, const_byte_regs, iv_param_regs))
            findings.extend(self._check_key_size(
                instr, raw, reg_strings, desc, instructions))
            findings.extend(self._check_keystore_bypass(
                instr, raw, reg_strings, desc))

        return findings

    # ------------------------------------------------------------------

    def _check_cipher_getInstance(
        self, instr, raw, reg_strings, desc, uses_keystore,
    ) -> list[Finding]:
        if "Ljavax/crypto/Cipher;->getInstance" not in raw:
            return []

        algo_str = self._resolve_string_arg(instr, reg_strings)
        if algo_str is None:
            return []

        algo_upper = algo_str.upper()
        parts = [p.strip() for p in algo_upper.split("/")]
        algorithm = parts[0]
        mode = parts[1] if len(parts) > 1 else ""
        padding = parts[2] if len(parts) > 2 else ""

        findings = []

        if algorithm in _WEAK_CIPHER_ALGORITHMS:
            findings.append(Finding(
                rule_id="CRYPTO_WEAK_ALGORITHM",
                title=f"Weak cipher algorithm: {algo_str}",
                description=(
                    f"The application uses {algorithm}, a cryptographically "
                    "broken cipher that provides no meaningful confidentiality."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="CRYPTO",
                class_name=desc.class_name,
                method_name=desc.method_name,
                evidence=f'Cipher.getInstance("{algo_str}") @offset {instr["offset"]}',
                remediation="Replace with AES/GCM/NoPadding with a 256-bit key.",
                cwe_id="CWE-327",
                cvss=7.5,
            ))

        if mode in _INSECURE_MODES:
            findings.append(Finding(
                rule_id="CRYPTO_ECB_MODE",
                title="Cipher uses ECB mode — no semantic security",
                description=(
                    "ECB mode encrypts each block independently, leaking data "
                    "patterns. Identical plaintext blocks produce identical ciphertext."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="CRYPTO",
                class_name=desc.class_name,
                method_name=desc.method_name,
                evidence=f'Cipher.getInstance("{algo_str}") @offset {instr["offset"]}',
                remediation="Use AES/GCM/NoPadding (authenticated encryption).",
                cwe_id="CWE-327",
                cvss=7.5,
            ))

        # NoPadding on CBC is vulnerable to padding oracle attacks
        if mode == "CBC" and padding in _UNSAFE_PADDING:
            findings.append(Finding(
                rule_id="CRYPTO_NO_PADDING",
                title="AES/CBC/NoPadding — padding oracle attack risk",
                description=(
                    "Using CBC mode without padding verification is vulnerable "
                    "to padding oracle attacks (BEAST, POODLE variants). An "
                    "attacker can decrypt ciphertext without the key."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="CRYPTO",
                class_name=desc.class_name,
                method_name=desc.method_name,
                evidence=f'Cipher.getInstance("{algo_str}") @offset {instr["offset"]}',
                remediation="Use AES/GCM/NoPadding (authenticated) or AES/CBC/PKCS7Padding with MAC.",
                cwe_id="CWE-326",
                cvss=6.5,
            ))

        return findings

    def _check_messageDigest(self, instr, raw, reg_strings, desc) -> list[Finding]:
        if "Ljava/security/MessageDigest;->getInstance" not in raw:
            return []
        algo_str = self._resolve_string_arg(instr, reg_strings)
        if algo_str is None:
            return []
        algo_upper = algo_str.upper().replace("-", "")
        if algo_upper not in _WEAK_HASH_ALGORITHMS:
            return []
        return [Finding(
            rule_id="CRYPTO_WEAK_HASH",
            title=f"Weak hash algorithm: {algo_str}",
            description=(
                f"{algo_str} is cryptographically broken. Do not use for "
                "integrity checks, digital signatures, or password hashing."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category="CRYPTO",
            class_name=desc.class_name,
            method_name=desc.method_name,
            evidence=f'MessageDigest.getInstance("{algo_str}") @offset {instr["offset"]}',
            remediation="Use SHA-256 or SHA-3. For passwords, use Argon2id via Android Keystore.",
            cwe_id="CWE-328",
            cvss=5.3,
        )]

    def _check_constant_key(self, instr, raw, desc, uses_keystore) -> list[Finding]:
        if "Ljavax/crypto/spec/SecretKeySpec;-><init>" not in raw:
            return []
        # If the method uses AndroidKeyStore, suppress — likely wrapping a keystore key
        if uses_keystore:
            return []
        return [Finding(
            rule_id="CRYPTO_CONSTANT_KEY",
            title="Potentially hardcoded cryptographic key",
            description=(
                "SecretKeySpec is constructed directly. If the key material is "
                "hardcoded or derived from a constant, it can be extracted from the APK."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="CRYPTO",
            class_name=desc.class_name,
            method_name=desc.method_name,
            evidence=f"SecretKeySpec.<init> @offset {instr['offset']}",
            remediation="Generate keys using Android Keystore (KeyGenerator) so key material never leaves secure hardware.",
            cwe_id="CWE-321",
            cvss=8.0,
        )]

    def _check_insecure_random(self, instr, raw, desc) -> list[Finding]:
        if "Ljava/util/Random;-><init>" not in raw and \
                "Ljava/util/Random;->next" not in raw:
            return []
        return [Finding(
            rule_id="CRYPTO_INSECURE_RANDOM",
            title="java.util.Random — not cryptographically secure",
            description=(
                "java.util.Random is a linear congruential generator whose output "
                "is predictable after observing a small number of values."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="CRYPTO",
            class_name=desc.class_name,
            method_name=desc.method_name,
            evidence=f"java.util.Random @offset {instr['offset']}",
            remediation="Replace with java.security.SecureRandom for tokens, nonces, IVs, and salts.",
            cwe_id="CWE-338",
            cvss=5.9,
        )]

    def _check_static_iv(
        self, instr, raw, desc, const_byte_regs, iv_param_regs,
    ) -> list[Finding]:
        """Detect IvParameterSpec constructed from a constant byte array."""
        if "Ljavax/crypto/spec/IvParameterSpec;-><init>" not in raw:
            return []

        # Check if any argument register was loaded from a constant array
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            arg_regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            # Skip 'this' (index 0 for virtual) — IV bytes are first real arg
            for reg in arg_regs[1:]:
                if reg in const_byte_regs:
                    return [Finding(
                        rule_id="CRYPTO_STATIC_IV",
                        title="IvParameterSpec constructed from constant byte array",
                        description=(
                            "A static (hardcoded) IV was detected. Reusing the same IV "
                            "with the same key in CBC or CTR mode leaks information about "
                            "the plaintext and can enable nonce-reuse attacks."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="CRYPTO",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"IvParameterSpec.<init> with const bytes @offset {instr['offset']}",
                        remediation="Generate a fresh random IV for every encryption: SecureRandom().nextBytes(iv).",
                        cwe_id="CWE-330",
                        cvss=7.4,
                    )]
        except (ValueError, IndexError):
            pass
        return []

    def _check_key_size(
        self, instr, raw, reg_strings, desc, instructions=None,
    ) -> list[Finding]:
        """Detect weak key sizes in KeyPairGenerator and KeyGenerator.

        Algorithm resolution order:
          1. Local `reg_strings` — the algo string is in this method's
             const-string pool (typical inline construction).
          2. The same method's instruction stream — look for any
             ``getInstance("ALGO")`` call whose argument is a const-string
             we have already seen, even if the string never made it into
             the method's `reg_strings` dict (some build pipelines strip
             unused entries).
          3. The cross-method `algorithm_index` keyed by declaring class —
             handles factory-pattern keygens where one method calls
             `getInstance("RSA")` and another calls `initialize(1024)`.
        """
        if "KeyPairGenerator;->initialize" not in raw and \
                "KeyGenerator;->init" not in raw:
            return []

        # Try to find the key size integer argument
        operands = instr.get("operands", [])
        for op in operands:
            val = op.get("value")
            if isinstance(val, int) and 64 <= val <= 16384:
                algo = self._resolve_algorithm(
                    reg_strings, desc, instructions or [],
                )

                min_size = _MIN_KEY_SIZE.get(algo, 2048)
                if val < min_size:
                    return [Finding(
                        rule_id="CRYPTO_SMALL_KEY",
                        title=f"Insufficient key size: {val} bits (minimum {min_size})",
                        description=(
                            f"A {val}-bit key was detected for {algo or 'an asymmetric cipher'}. "
                            f"Modern guidance requires at least {min_size} bits to resist "
                            "brute-force and factoring attacks."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="CRYPTO",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"key size={val} @offset {instr['offset']}",
                        remediation=f"Use a minimum {min_size}-bit key for {algo or 'asymmetric algorithms'}.",
                        cwe_id="CWE-326",
                        cvss=7.5,
                    )]
        return []

    def _check_keystore_bypass(self, instr, raw, reg_strings, desc) -> list[Finding]:
        """Detect key generation that bypasses AndroidKeyStore (software-only keys)."""
        if "KeyGenerator;->getInstance" not in raw and \
                "KeyPairGenerator;->getInstance" not in raw:
            return []

        algo_str = self._resolve_string_arg(instr, reg_strings)
        if not algo_str:
            return []

        # If provider is explicitly "AndroidKeyStore", it's hardware-backed — skip
        if any(p in raw for p in _KEYSTORE_PROVIDERS):
            return []

        # Two-argument form: getInstance(algo, provider) — check if provider is keystore
        return [Finding(
            rule_id="CRYPTO_KEYSTORE_BYPASS",
            title=f"Key generation outside AndroidKeyStore: {algo_str}",
            description=(
                f"KeyGenerator.getInstance(\"{algo_str}\") without the "
                "\"AndroidKeyStore\" provider generates keys in software memory. "
                "Software keys can be extracted from memory or backup storage."
            ),
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            category="CRYPTO",
            class_name=desc.class_name,
            method_name=desc.method_name,
            evidence=f'KeyGenerator.getInstance("{algo_str}") @offset {instr["offset"]}',
            remediation=(
                'Use KeyGenerator.getInstance("AES", "AndroidKeyStore") with '
                "KeyGenParameterSpec to generate hardware-backed keys."
            ),
            cwe_id="CWE-321",
            cvss=4.3,
        )]

    # ------------------------------------------------------------------

    def _resolve_algorithm(
        self,
        reg_strings: dict[str, str],
        desc: MethodDescriptor,
        instructions: list[dict],
    ) -> str:
        """Best-effort resolution of which algorithm this keygen targets.

        Returns the empty string if no algorithm could be determined; the
        caller treats that as "use the conservative 2048-bit default".
        """
        # 1. Local string pool
        for v in reg_strings.values():
            v_upper = v.upper()
            for alg in _MIN_KEY_SIZE:
                if alg in v_upper:
                    return alg
        # 2. Same-method getInstance scan — pick up algo strings that
        # androguard parsed but the orchestrator didn't fold into reg_strings.
        for ins in instructions:
            if "KeyPairGenerator;->getInstance" not in ins.get("raw", "") and \
                    "KeyGenerator;->getInstance" not in ins.get("raw", ""):
                continue
            for op in ins.get("operands", []):
                val = op.get("value")
                if not isinstance(val, str):
                    continue
                v_upper = val.upper()
                for alg in _MIN_KEY_SIZE:
                    if alg in v_upper:
                        return alg
        # 3. Cross-method index keyed by declaring class
        cls_algos = self.algorithm_index.get(desc.class_name, set())
        for alg in cls_algos:
            alg_upper = alg.upper()
            for known in _MIN_KEY_SIZE:
                if known in alg_upper:
                    return known
        return ""

    def _resolve_string_arg(
        self,
        instr: dict,
        reg_strings: dict[str, str],
    ) -> Optional[str]:
        raw = instr.get("raw", "")
        mnemonic = instr.get("mnemonic", "")
        is_static = "static" in mnemonic or raw.lstrip().startswith("invoke-static")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            registers = [r.strip() for r in reg_part.split(",") if r.strip()]
            start = 0 if is_static else 1
            for reg in registers[start:]:
                if reg in reg_strings:
                    return reg_strings[reg]
        except (ValueError, IndexError):
            pass
        return None
