"""
Hardcoded secrets detector.

Approach: Shannon entropy + pattern matching hybrid.

Patterns added in this revision
---------------------------------
- AWS Access Key ID / Secret Access Key
- Google API Key (AIza prefix)
- PEM Private Keys (RSA, EC, DSA, OpenSSH)
- Generic API key / client secret
- JSON Web Tokens
- Firebase API key
- High-entropy hex strings
- GitHub Personal Access Tokens (ghp_, gho_, ghu_, ghs_ prefixes)
- Stripe API keys (sk_live_, pk_live_, rk_live_)
- Slack Webhook URLs / Bot tokens (xoxb-, xoxp-, xoxa-, xoxr-)
- Twilio credentials
- SendGrid API keys (SG. prefix)
- Mailgun API keys
- Square access tokens
- OAuth client secret patterns
- SSH private key headers (OpenSSH format)
- Database connection strings with embedded credentials
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from typing import Optional

from apkanalyzer.ir.models import Finding, Severity, Confidence, MethodDescriptor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

_BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_BASE64URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX_CHARS = set("0123456789abcdefABCDEF")
_ALPHANUM_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")


def shannon_entropy(s: str, charset: set[str]) -> float:
    """Shannon entropy in bits per character over the given charset."""
    filtered = [c for c in s if c in charset]
    if len(filtered) < 8:
        return 0.0
    freq: dict[str, int] = {}
    for c in filtered:
        freq[c] = freq.get(c, 0) + 1
    n = len(filtered)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class SecretPattern:
    rule_id: str
    name: str
    pattern: re.Pattern
    min_entropy: float
    charset: set[str]
    min_length: int
    severity: Severity
    cwe_id: str
    remediation: str


_PATTERNS: list[SecretPattern] = [

    # AWS
    SecretPattern(
        rule_id="SECRET_AWS_KEY",
        name="AWS Access Key ID",
        pattern=re.compile(r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'),
        min_entropy=3.0, charset=_BASE64_CHARS, min_length=20,
        severity=Severity.CRITICAL, cwe_id="CWE-798",
        remediation="Rotate immediately. Use IAM roles or AWS Secrets Manager.",
    ),
    SecretPattern(
        rule_id="SECRET_AWS_SECRET",
        name="AWS Secret Access Key",
        pattern=re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+]{40})["\']'),
        min_entropy=4.0, charset=_BASE64_CHARS, min_length=40,
        severity=Severity.CRITICAL, cwe_id="CWE-798",
        remediation="Rotate immediately. Use AWS Secrets Manager or IAM instance roles.",
    ),

    # Google
    SecretPattern(
        rule_id="SECRET_GOOGLE_API_KEY",
        name="Google API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        min_entropy=3.5, charset=_BASE64_CHARS, min_length=39,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Restrict the key in Google Cloud Console. Use server-side proxy.",
    ),

    # PEM private keys
    SecretPattern(
        rule_id="SECRET_PRIVATE_KEY_PEM",
        name="PEM Private Key",
        pattern=re.compile(r'-----BEGIN (RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----'),
        min_entropy=0.0, charset=_BASE64_CHARS, min_length=0,
        severity=Severity.CRITICAL, cwe_id="CWE-321",
        remediation="Never embed private keys in APK. Use Android Keystore.",
    ),
    SecretPattern(
        rule_id="SECRET_PRIVATE_KEY_OPENSSH",
        name="OpenSSH Private Key",
        pattern=re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        min_entropy=0.0, charset=_BASE64_CHARS, min_length=0,
        severity=Severity.CRITICAL, cwe_id="CWE-321",
        remediation="Never embed SSH private keys in APK.",
    ),

    # GitHub tokens
    SecretPattern(
        rule_id="SECRET_GITHUB_PAT",
        name="GitHub Personal Access Token",
        pattern=re.compile(r'(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'),
        min_entropy=3.5, charset=_ALPHANUM_CHARS, min_length=36,
        severity=Severity.CRITICAL, cwe_id="CWE-798",
        remediation="Revoke the token on GitHub immediately. Use server-side GitHub API calls.",
    ),

    # Stripe
    SecretPattern(
        rule_id="SECRET_STRIPE_KEY",
        name="Stripe API Key",
        pattern=re.compile(r'(sk_live_[A-Za-z0-9]{24}|rk_live_[A-Za-z0-9]{24})'),
        min_entropy=3.5, charset=_ALPHANUM_CHARS, min_length=28,
        severity=Severity.CRITICAL, cwe_id="CWE-798",
        remediation="Rotate the Stripe key immediately. Never use live secret keys in mobile apps.",
    ),
    SecretPattern(
        rule_id="SECRET_STRIPE_PK",
        name="Stripe Publishable Key",
        pattern=re.compile(r'pk_live_[A-Za-z0-9]{24}'),
        min_entropy=3.0, charset=_ALPHANUM_CHARS, min_length=28,
        severity=Severity.MEDIUM, cwe_id="CWE-798",
        remediation="Publishable keys have limited scope but should not be hardcoded in production.",
    ),

    # Slack
    SecretPattern(
        rule_id="SECRET_SLACK_TOKEN",
        name="Slack API Token / Webhook",
        pattern=re.compile(r'(xoxb-[0-9A-Za-z\-]{50,}|xoxp-[0-9A-Za-z\-]{50,}|xoxa-[0-9A-Za-z\-]{50,}|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)'),
        min_entropy=3.5, charset=_ALPHANUM_CHARS, min_length=50,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Revoke the token in Slack app settings. Route Slack calls through a backend.",
    ),

    # Twilio
    SecretPattern(
        rule_id="SECRET_TWILIO",
        name="Twilio Auth Token or Account SID",
        pattern=re.compile(r'(?i)twilio.{0,30}["\']([A-Za-z0-9]{32,34})["\']'),
        min_entropy=3.5, charset=_ALPHANUM_CHARS, min_length=32,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Rotate Twilio credentials. Proxy Twilio calls through a backend server.",
    ),

    # SendGrid
    SecretPattern(
        rule_id="SECRET_SENDGRID",
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
        min_entropy=3.5, charset=_BASE64URL_CHARS, min_length=67,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Rotate the SendGrid API key. Email sending should occur server-side.",
    ),

    # Mailgun
    SecretPattern(
        rule_id="SECRET_MAILGUN",
        name="Mailgun API Key",
        pattern=re.compile(r'key-[0-9a-f]{32}'),
        min_entropy=3.0, charset=_HEX_CHARS, min_length=36,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Rotate the Mailgun key. Route email calls through a backend.",
    ),

    # Square
    SecretPattern(
        rule_id="SECRET_SQUARE",
        name="Square Access Token",
        pattern=re.compile(r'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}'),
        min_entropy=3.5, charset=_BASE64URL_CHARS, min_length=25,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Rotate Square credentials. Use server-side payment processing.",
    ),

    # JWT
    SecretPattern(
        rule_id="SECRET_JWT",
        name="JSON Web Token",
        pattern=re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
        min_entropy=4.0, charset=_BASE64URL_CHARS, min_length=50,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Never hardcode JWTs. Obtain tokens at runtime via OAuth 2.0.",
    ),

    # Firebase
    SecretPattern(
        rule_id="SECRET_FIREBASE_KEY",
        name="Firebase API Key",
        pattern=re.compile(r'(?i)firebase.*["\']([A-Za-z0-9_\-]{20,})["\']'),
        min_entropy=3.5, charset=_BASE64_CHARS, min_length=20,
        severity=Severity.MEDIUM, cwe_id="CWE-798",
        remediation="Restrict Firebase keys with Security Rules and API restrictions.",
    ),

    # Generic API key / client secret
    SecretPattern(
        rule_id="SECRET_GENERIC_API_KEY",
        name="Generic API key or client secret",
        pattern=re.compile(
            r'(?i)(?:api[_\-]?key|secret[_\-]?key|auth[_\-]?token|client[_\-]?secret|'
            r'access[_\-]?token|oauth[_\-]?token|bearer[_\-]?token)'
            r'["\s:=]+["\']([A-Za-z0-9_\-+/]{20,})["\']',
        ),
        min_entropy=3.5, charset=_BASE64_CHARS, min_length=20,
        severity=Severity.HIGH, cwe_id="CWE-798",
        remediation="Move secrets to a remote secrets manager; fetch at runtime over mTLS.",
    ),

    # Database connection string
    SecretPattern(
        rule_id="SECRET_DB_CONN_STRING",
        name="Database connection string with credentials",
        pattern=re.compile(
            r'(?i)(jdbc:[a-z]+://[^"\']+:[^"\'@]+@[^"\']+|'
            r'mongodb(\+srv)?://[^:]+:[^@]+@[^"\']+|'
            r'postgres://[^:]+:[^@]+@[^"\']+|'
            r'mysql://[^:]+:[^@]+@[^"\']+)',
        ),
        min_entropy=2.5, charset=_BASE64_CHARS, min_length=20,
        severity=Severity.CRITICAL, cwe_id="CWE-798",
        remediation="Never embed database credentials in mobile apps. Use a backend API.",
    ),

    # High-entropy hex (key material / seeds)
    SecretPattern(
        rule_id="SECRET_HIGH_ENTROPY_HEX",
        name="High-entropy hex string (possible key/IV/seed)",
        pattern=re.compile(r'["\']([0-9a-fA-F]{32,})["\']'),
        min_entropy=3.5, charset=_HEX_CHARS, min_length=32,
        severity=Severity.MEDIUM, cwe_id="CWE-321",
        remediation="If this is key material, move it to Android Keystore or a remote KMS.",
    ),
]

# ---------------------------------------------------------------------------
# False-positive filters
# ---------------------------------------------------------------------------

# Resource IDs, color codes, version strings, etc.
_KNOWN_SAFE_PATTERNS = [
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),  # UUID
    re.compile(r'^#[0-9a-fA-F]{3,8}$'),           # color hex
    re.compile(r'^[0-9]+$'),                        # pure numeric
    re.compile(r'^[a-z_]+$'),                       # lowercase identifier
    re.compile(r'^[A-Z_]+$'),                       # constant name
    re.compile(r'^[0-9a-f]{40}$'),                  # git SHA (40 char hex)
    re.compile(r'^[0-9a-f]{64}$'),                  # SHA-256 hash
    re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}'),    # date
    re.compile(r'^(true|false|null|undefined)$', re.I),  # literals
    re.compile(r'^\d+\.\d+\.\d+'),                 # version number
    re.compile(r'^https?://'),                      # URL (already checked by network detector)
    re.compile(r'^[A-Z][a-z]+[A-Z]'),              # CamelCase — class name fragment
    re.compile(r'^com\.[a-z]+'),                    # package name
]

# Strings that contain these words are likely safe (test fixtures, resources)
_SAFE_CONTEXT_WORDS = frozenset([
    "example", "sample", "test", "fake", "mock", "dummy", "placeholder",
    "your_", "my_", "insert_", "replace_", "xxxx", "????", "1234",
    "abcdef", "aabbcc", "000000", "ffffff",
])


def _is_known_safe(s: str) -> bool:
    if any(p.match(s) for p in _KNOWN_SAFE_PATTERNS):
        return True
    s_lower = s.lower()
    return any(w in s_lower for w in _SAFE_CONTEXT_WORDS)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class SecretDetector:

    def scan_string_pool(
        self,
        strings: list[str],
        source_hint: str = "<dex string pool>",
    ) -> list[Finding]:
        """Scan a list of string literals extracted from the DEX."""
        findings: list[Finding] = []
        for s in strings:
            findings.extend(self._check_string(s, source_hint, None, 0))
        return self._deduplicate(findings)

    def scan_file(self, content: str, file_path: str) -> list[Finding]:
        """Scan the text content of a decompiled source file."""
        findings: list[Finding] = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            for pattern in _PATTERNS:
                findings.extend(
                    self._check_string_in_line(line, file_path, line_no, pattern)
                )
        return self._deduplicate(findings)

    # ------------------------------------------------------------------

    def _check_string(
        self,
        s: str,
        file_path: str,
        desc: Optional[MethodDescriptor],
        line_no: int,
    ) -> list[Finding]:
        if len(s) < 8 or _is_known_safe(s):
            return []

        findings: list[Finding] = []
        for pattern in _PATTERNS:
            m = pattern.pattern.search(s)
            if not m:
                continue

            candidate = m.group(1) if m.lastindex else m.group(0)
            if len(candidate) < pattern.min_length:
                continue
            if pattern.min_entropy > 0:
                entropy = shannon_entropy(candidate, pattern.charset)
                if entropy < pattern.min_entropy:
                    continue
            if _is_known_safe(candidate):
                continue

            entropy_val = shannon_entropy(candidate, pattern.charset)
            findings.append(Finding(
                rule_id=pattern.rule_id,
                title=f"Hardcoded {pattern.name} detected",
                description=(
                    f"A {pattern.name} was found hardcoded in the APK. "
                    f"Entropy: {entropy_val:.2f} bits/char. "
                    "Hardcoded secrets can be trivially extracted by decompiling the APK."
                ),
                severity=pattern.severity,
                confidence=Confidence.HIGH,
                category="SECRETS",
                class_name=desc.class_name if desc else "",
                method_name=desc.method_name if desc else "",
                file_path=file_path,
                line_number=line_no,
                evidence=f"Matched: {candidate[:40]}{'...' if len(candidate) > 40 else ''}",
                remediation=pattern.remediation,
                cwe_id=pattern.cwe_id,
                cvss=9.0 if pattern.severity == Severity.CRITICAL else 7.5,
            ))

        return findings

    def _check_string_in_line(
        self,
        line: str,
        file_path: str,
        line_no: int,
        pattern: SecretPattern,
    ) -> list[Finding]:
        m = pattern.pattern.search(line)
        if not m:
            return []

        candidate = m.group(1) if m.lastindex else m.group(0)
        if len(candidate) < pattern.min_length:
            return []
        if pattern.min_entropy > 0:
            entropy = shannon_entropy(candidate, pattern.charset)
            if entropy < pattern.min_entropy:
                return []
        if _is_known_safe(candidate):
            return []

        entropy_val = shannon_entropy(candidate, pattern.charset)
        return [Finding(
            rule_id=pattern.rule_id,
            title=f"Hardcoded {pattern.name} detected",
            description=(
                f"A {pattern.name} was found hardcoded in source. "
                f"Entropy: {entropy_val:.2f} bits/char."
            ),
            severity=pattern.severity,
            confidence=Confidence.HIGH,
            category="SECRETS",
            file_path=file_path,
            line_number=line_no,
            evidence=f"Line {line_no}: {line.strip()[:120]}",
            remediation=pattern.remediation,
            cwe_id=pattern.cwe_id,
            cvss=9.0 if pattern.severity == Severity.CRITICAL else 7.5,
        )]

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple] = set()
        result = []
        for f in findings:
            key = (f.rule_id, f.evidence[:40])
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
