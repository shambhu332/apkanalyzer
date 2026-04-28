"""
Network security detector.

Checks
------
NETWORK_CLEARTEXT          — http:// URLs in code
NETWORK_SSL_DISABLED       — ALLOW_ALL_HOSTNAME_VERIFIER / TrustAllCerts
NETWORK_TRUSTMANAGER_STUB  — Custom X509TrustManager that accepts all certs
NETWORK_WEAK_TLS           — SSLContext.getInstance("SSLv3"/"TLSv1"/"TLSv1.1")
NETWORK_OKHTTP_CUSTOM_VERIFIER — Custom HostnameVerifier on OkHttpClient
NETWORK_OKHTTP_CERT_PINNER — OkHttp CertificatePinner detected (informational)
NETWORK_NSC_CLEARTEXT      — network_security_config base-config allows cleartext
NETWORK_NSC_DOMAIN_CLEARTEXT — per-domain cleartext exception in NSC
NETWORK_NSC_USER_CA        — debug-overrides trusts user CA certs
NETWORK_PINNING_MISSING    — no certificate pinning found in NSC
NETWORK_VOLLEY_NO_SSL      — Volley RequestQueue using HurlStack without SSL config
NETWORK_RETROFIT_UNSAFE    — Retrofit builder with unsafe OkHttp client
"""

from __future__ import annotations

import logging
import re
from xml.etree import ElementTree as ET

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions

logger = logging.getLogger(__name__)

_HTTP_URL_RE = re.compile(r'\bhttp://[^\s"\'<>{}\[\]]+', re.IGNORECASE)
_WEAK_TLS_VERSIONS = {
    "sslv2", "sslv3", "ssl", "tlsv1", "tls1", "tlsv1.0",
    "tlsv1.1", "tls1.1",
}


class NetworkDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instructions = get_all_instructions(cfg)

        # ── Method-level: X509TrustManager empty stub ──────────────
        # Fire ONCE per method when:
        #   - the enclosing method IS checkServerTrusted / checkClientTrusted,
        #   - AND its body never throws (no `throw` opcode and no
        #     CertificateException reference) — i.e. it returns silently.
        # The previous implementation substring-matched anywhere in any
        # method body, which produced a flood of false positives. Hoisted
        # outside the per-instruction loop because the trust-manager
        # signal is method-scoped, not instruction-scoped.
        if desc.method_name in ("checkServerTrusted", "checkClientTrusted"):
            body_has_throw = any(
                ins.get("mnemonic", "").startswith("throw")
                or "CertificateException" in ins.get("raw", "")
                for ins in instructions
            )
            if not body_has_throw:
                findings.append(Finding(
                    rule_id="NETWORK_TRUSTMANAGER_STUB",
                    title="Custom X509TrustManager accepts all certificates",
                    description=(
                        f"{desc.method_name}() never throws CertificateException, "
                        "so every TLS certificate (including self-signed and expired) "
                        "is accepted. This breaks TLS authentication entirely."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"{desc.method_name}() body has no `throw` opcode",
                    remediation=(
                        "Remove the custom TrustManager. Use TrustManagerFactory "
                        "with the default trust store, or delegate to the default "
                        "TrustManager and re-throw on validation failure."
                    ),
                    cwe_id="CWE-295",
                    cvss=8.1,
                ))

        for instr in instructions:
            raw = instr.get("raw", "")
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)

            # ── Cleartext URLs ─────────────────────────────────────────
            if "const-string" in mnemonic:
                for operand in instr.get("operands", []):
                    val = str(operand.get("raw", ""))
                    # Skip test endpoints and localhost
                    if any(safe in val.lower() for safe in
                           ("localhost", "127.0.0.1", "0.0.0.0", "example.com",
                            "test", "mock", "staging", "dev.")):
                        continue
                    if _HTTP_URL_RE.search(val):
                        findings.append(Finding(
                            rule_id="NETWORK_CLEARTEXT",
                            title="Cleartext HTTP URL in code",
                            description=(
                                f"A hardcoded http:// URL was found: {val[:120]}. "
                                "HTTP traffic is unencrypted and susceptible to "
                                "interception and modification."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="NETWORK",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f'const-string @offset {offset}: {val[:120]}',
                            remediation="Replace all http:// endpoints with https://.",
                            cwe_id="CWE-319",
                            cvss=6.5,
                        ))

            if not mnemonic.startswith("invoke"):
                continue

            # ── ALLOW_ALL / NullHostnameVerifier ──────────────────────
            if ("ALLOW_ALL_HOSTNAME_VERIFIER" in raw
                    or "NullHostnameVerifier" in raw
                    or "AllowAllHostnameVerifier" in raw):
                findings.append(Finding(
                    rule_id="NETWORK_SSL_DISABLED",
                    title="Hostname verification disabled (ALLOW_ALL)",
                    description=(
                        "Setting ALLOW_ALL_HOSTNAME_VERIFIER disables TLS hostname "
                        "verification, making the app vulnerable to MITM attacks from "
                        "any attacker with a valid certificate for any domain."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"@offset {offset}: {raw[:120]}",
                    remediation=(
                        "Remove ALLOW_ALL_HOSTNAME_VERIFIER. Use the default "
                        "verifier or OkHttp CertificatePinner."
                    ),
                    cwe_id="CWE-297",
                    cvss=9.1,
                ))

            # Trust-all pattern strings.
            # Parentheses are explicit so the `and` binds tightly to the
            # SSLSocketFactory/setSocketFactory pair only — Python's `and`
            # has higher precedence than `or`, but the implicit grouping is
            # too easy to misread.
            if (
                "TrustAllCerts" in raw
                or "TrustAll" in raw
                or "AcceptAllCerts" in raw
                or ("SSLSocketFactory" in raw and "setSocketFactory" in raw)
            ):
                findings.append(Finding(
                    rule_id="NETWORK_SSL_DISABLED",
                    title="Trust-all SSL pattern detected",
                    description=(
                        "A 'TrustAllCerts' or similar pattern was found in the bytecode. "
                        "This typically accepts any TLS certificate including self-signed "
                        "and expired ones."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    category="NETWORK",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"@offset {offset}: {raw[:120]}",
                    remediation="Remove trust-all SSL patterns. Use default TLS validation.",
                    cwe_id="CWE-295",
                    cvss=9.1,
                ))

            # ── OkHttp custom HostnameVerifier ─────────────────────────
            if "Lokhttp3/OkHttpClient$Builder;->hostnameVerifier" in raw:
                findings.append(Finding(
                    rule_id="NETWORK_OKHTTP_CUSTOM_VERIFIER",
                    title="OkHttp custom HostnameVerifier — potential pinning bypass",
                    description=(
                        "A custom HostnameVerifier is installed on OkHttpClient. "
                        "If it returns true unconditionally, hostname verification "
                        "and certificate pinning are bypassed."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    category="NETWORK",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"OkHttpClient.Builder.hostnameVerifier() @offset {offset}",
                    remediation="Remove custom HostnameVerifier. Use OkHttp CertificatePinner.",
                    cwe_id="CWE-297",
                    cvss=8.1,
                ))

            # ── OkHttp CertificatePinner (informational) ───────────────
            if "Lokhttp3/CertificatePinner" in raw:
                findings.append(Finding(
                    rule_id="NETWORK_OKHTTP_CERT_PINNER",
                    title="OkHttp CertificatePinner detected",
                    description=(
                        "The app uses OkHttp certificate pinning. Ensure pins are "
                        "up-to-date and a backup pin is configured."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"CertificatePinner @offset {offset}",
                    remediation="Include at least two pins (current + backup). Implement pin expiry handling.",
                    cwe_id="CWE-295",
                    cvss=0.0,
                ))

            # ── Weak TLS version ───────────────────────────────────────
            if "Ljavax/net/ssl/SSLContext;->getInstance" in raw:
                algo_reg = self._first_string_arg(instr, reg_strings)
                if algo_reg and algo_reg.lower() in _WEAK_TLS_VERSIONS:
                    findings.append(Finding(
                        rule_id="NETWORK_WEAK_TLS",
                        title=f"Weak TLS version requested: {algo_reg}",
                        description=(
                            f'SSLContext.getInstance("{algo_reg}") requests a '
                            "deprecated protocol with known vulnerabilities (POODLE, BEAST)."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="NETWORK",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f'SSLContext.getInstance("{algo_reg}") @offset {offset}',
                        remediation='Use SSLContext.getInstance("TLSv1.3") or at minimum "TLSv1.2".',
                        cwe_id="CWE-326",
                        cvss=7.4,
                    ))

            # ── Retrofit unsafe OkHttpClient ───────────────────────────
            if ("Lretrofit2/Retrofit$Builder;->client" in raw
                    or "Lretrofit2/Retrofit$Builder;->callFactory" in raw):
                # Flag if OkHttpClient being set — check if it uses custom verifier
                # This is a soft finding; confidence LOW since we can't verify the client config
                findings.append(Finding(
                    rule_id="NETWORK_RETROFIT_VERIFY",
                    title="Retrofit: verify OkHttpClient TLS configuration",
                    description=(
                        "A custom OkHttpClient is set on Retrofit. Ensure the client "
                        "does not disable hostname verification or certificate validation."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    category="NETWORK",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Retrofit.Builder.client() @offset {offset}",
                    remediation="Audit the OkHttpClient passed to Retrofit for disabled SSL checks.",
                    cwe_id="CWE-295",
                    cvss=0.0,
                ))

        return findings

    def analyse_network_security_config(
        self,
        config_xml: str,
        apk_name: str,
    ) -> list[Finding]:
        """Analyse the network_security_config.xml for misconfigurations."""
        findings: list[Finding] = []
        try:
            root = ET.fromstring(config_xml)
        except ET.ParseError as exc:
            logger.debug("NSC parse error: %s", exc)
            return findings

        # ── base-config ────────────────────────────────────────────────
        base_config = root.find("base-config")
        if base_config is not None:
            cleartext = base_config.get("cleartextTrafficPermitted", "false")
            if cleartext.lower() == "true":
                findings.append(Finding(
                    rule_id="NETWORK_NSC_CLEARTEXT",
                    title="network_security_config: base-config allows cleartext traffic",
                    description=(
                        "cleartextTrafficPermitted=true in base-config allows HTTP "
                        "for ALL domains, bypassing Android 9+ HTTPS enforcement."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    file_path="res/xml/network_security_config.xml",
                    evidence='cleartextTrafficPermitted="true" in base-config',
                    remediation='Set cleartextTrafficPermitted="false" in base-config.',
                    cwe_id="CWE-319",
                    cvss=7.5,
                ))

        # ── domain-config cleartext exceptions ─────────────────────────
        for domain_config in root.findall("domain-config"):
            cleartext = domain_config.get("cleartextTrafficPermitted", "false")
            if cleartext.lower() == "true":
                domains = [
                    d.text or "" for d in domain_config.findall("domain")
                ]
                domain_str = ", ".join(domains) or "(unspecified)"
                findings.append(Finding(
                    rule_id="NETWORK_NSC_DOMAIN_CLEARTEXT",
                    title=f"network_security_config: domain-config cleartext for {domain_str}",
                    description=(
                        f"cleartextTrafficPermitted=true in domain-config for "
                        f"{domain_str} allows HTTP traffic to those domains. "
                        "This is a per-domain exception that may go unnoticed."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    file_path="res/xml/network_security_config.xml",
                    evidence=f'domain-config cleartextTrafficPermitted="true" for: {domain_str}',
                    remediation=f'Set cleartextTrafficPermitted="false" for {domain_str} and migrate to HTTPS.',
                    cwe_id="CWE-319",
                    cvss=5.9,
                ))

        # ── debug-overrides user CA ────────────────────────────────────
        debug_overrides = root.find("debug-overrides")
        if debug_overrides is not None:
            trust_anchors = debug_overrides.find("trust-anchors")
            if trust_anchors is not None:
                for cert in trust_anchors.findall("certificates"):
                    src = cert.get("src", "")
                    if src == "user":
                        findings.append(Finding(
                            rule_id="NETWORK_NSC_USER_CA",
                            title="debug-overrides trusts user-installed CA certificates",
                            description=(
                                "If debug-overrides ships in production, user-installed "
                                "CA certs (e.g., Burp Suite proxy CA) are trusted, "
                                "enabling trivial SSL interception."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="NETWORK",
                            file_path="res/xml/network_security_config.xml",
                            evidence="debug-overrides with src=user certificates",
                            remediation=(
                                "Remove debug-overrides from release builds "
                                "or guard with BuildConfig.DEBUG."
                            ),
                            cwe_id="CWE-295",
                            cvss=6.5,
                        ))

        # ── certificate pinning presence ───────────────────────────────
        has_pinning = root.find(".//pin-set") is not None
        if not has_pinning:
            findings.append(Finding(
                rule_id="NETWORK_PINNING_MISSING",
                title="No certificate pinning configured in network_security_config",
                description=(
                    "Without pinning, any certificate signed by a trusted CA "
                    "(including rogue or compromised CAs) is accepted."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="NETWORK",
                file_path="res/xml/network_security_config.xml",
                evidence="No <pin-set> element found",
                remediation=(
                    "Add <pin-set> in network_security_config.xml for all API domains. "
                    "Include at least two pins (current + backup)."
                ),
                cwe_id="CWE-295",
                cvss=5.9,
            ))

        # ── pin expiry warning ─────────────────────────────────────────
        for pin_set in root.findall(".//pin-set"):
            expiration = pin_set.get("expiration")
            if expiration:
                findings.append(Finding(
                    rule_id="NETWORK_PIN_EXPIRY",
                    title=f"Certificate pin expires: {expiration}",
                    description=(
                        f"A pin-set has an expiration date of {expiration}. "
                        "After expiry, pinning is automatically disabled by Android, "
                        "removing the protection without any code change."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    file_path="res/xml/network_security_config.xml",
                    evidence=f'pin-set expiration="{expiration}"',
                    remediation="Monitor certificate expiry and update pins before expiration.",
                    cwe_id="CWE-295",
                    cvss=0.0,
                ))

        return findings

    def _first_string_arg(self, instr, reg_strings) -> str | None:
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            for reg in regs[1:]:
                if reg in reg_strings:
                    return reg_strings[reg]
        except (ValueError, IndexError):
            pass
        return None
