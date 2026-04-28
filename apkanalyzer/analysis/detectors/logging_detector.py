"""
Insecure logging detector.

Catches sensitive data being written to Logcat, System.out, or printed traces —
addresses OWASP M6 (Inadequate Privacy Controls) and M9 (Insecure Data Storage).

Why this matters
----------------
Logcat output is readable by:
  • Any app with READ_LOGS on rooted/dev devices
  • Crash-reporting SDKs that ship logs to third parties
  • adb logcat without authentication

Releasing an APK with verbose logging of tokens, passwords, or PII is one of
the most common real-world findings in mobile pentests.

Checks
------
LOG_SENSITIVE_LITERAL    — Log.* call with a string literal that mentions a sensitive key
LOG_TAINTED_OUTPUT       — Log.* call sourced from a known taint-source (caught by taint engine)
LOG_PRINT_STACKTRACE     — printStackTrace() in release-style code (leaks call paths)
LOG_SYSTEM_OUT           — System.out.print* in production (Android logcat redirects to Log.I)
LOG_VERBOSE_DEBUG        — Calls to Log.d/Log.v that look like real debugging code paths
"""

from __future__ import annotations

import re

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions


_LOG_METHOD_RE = re.compile(
    r'Landroid/util/Log;->(?P<m>v|d|i|w|e|wtf|println)\('
)
_SYSTEM_OUT_RE = re.compile(
    r'Ljava/io/PrintStream;->(?:print|println|printf)\('
)
_PRINT_STACKTRACE_RE = re.compile(
    r'Ljava/lang/Throwable;->printStackTrace\(\)V'
    r'|Ljava/lang/Exception;->printStackTrace\(\)V'
)

_SENSITIVE_KEYWORD_RE = re.compile(
    r'(?i)\b('
    r'password|passwd|secret|token|api[_\-]?key|auth[_\-]?token|'
    r'session|cookie|jwt|bearer|credential|private[_\-]?key|'
    r'access[_\-]?key|client[_\-]?secret|oauth|pin\b|otp|'
    r'ssn|credit[_\-]?card|cvv|account[_\-]?number|'
    r'phone[_\-]?number|imei|imsi|android[_\-]?id|advertising[_\-]?id|'
    r'email|firstname|lastname|address|location|gps|latitude|longitude|'
    r'response\.body|userdata|user_data'
    r')\b'
)

_SEVERITY_LEVELS = {
    "v": Severity.LOW,
    "d": Severity.LOW,
    "i": Severity.MEDIUM,
    "w": Severity.MEDIUM,
    "e": Severity.HIGH,
    "wtf": Severity.MEDIUM,
    "println": Severity.LOW,
}


class LoggingDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instrs = get_all_instructions(cfg)
        method_strings = list(reg_strings.values())

        # Skip pure logging utility classes (they're meant to log, not the app)
        if "Logger" in desc.class_name or "Logging" in desc.class_name:
            return findings

        for instr in instrs:
            raw = instr.get("raw", "")
            offset = instr.get("offset", 0)

            # ── Log.* with sensitive literal ──────────────────────────────
            m = _LOG_METHOD_RE.search(raw)
            if m:
                level = m.group("m")
                # Look at any string in this method that looks sensitive
                for s in method_strings:
                    if (
                        len(s) >= 4
                        and len(s) < 200
                        and _SENSITIVE_KEYWORD_RE.search(s)
                    ):
                        findings.append(Finding(
                            rule_id="LOG_SENSITIVE_LITERAL",
                            title=f"Sensitive keyword logged via Log.{level}()",
                            description=(
                                "Logcat output is captured by crash reporters and is readable "
                                "on rooted devices and dev builds. Logging a string that "
                                "references a credential, token, or PII can leak the value "
                                "next to it (e.g., \"Token: <jwt>\")."
                            ),
                            severity=_SEVERITY_LEVELS.get(level, Severity.MEDIUM),
                            confidence=Confidence.MEDIUM,
                            category="PRIVACY",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"Log.{level}(): \"{s[:120]}\"",
                            remediation=(
                                "Wrap log calls in `if (BuildConfig.DEBUG)` or strip them "
                                "via ProGuard `assumenosideeffects`. Never log secrets, "
                                "tokens, PII, or full request/response bodies."
                            ),
                            cwe_id="CWE-532",
                            cvss=5.3,
                        ))
                        break  # one finding per Log call is enough
                else:
                    # Verbose/debug log without sensitive literal — informational
                    if level in ("v", "d"):
                        findings.append(Finding(
                            rule_id="LOG_VERBOSE_DEBUG",
                            title=f"Log.{level}() call in production code",
                            description=(
                                "Verbose/debug logs that are not stripped by ProGuard "
                                "leak runtime details (variable values, control flow). "
                                "This is informational unless combined with sensitive data."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            category="PRIVACY",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"Log.{level}() at offset {offset}",
                            remediation=(
                                "Use `assumenosideeffects` on android.util.Log in your "
                                "ProGuard rules to strip Log.v/Log.d in release builds."
                            ),
                            cwe_id="CWE-532",
                            cvss=2.0,
                        ))

            # ── System.out.print* — replaced by logcat at runtime ─────────
            if _SYSTEM_OUT_RE.search(raw):
                findings.append(Finding(
                    rule_id="LOG_SYSTEM_OUT",
                    title="System.out.print(ln) used as a logging mechanism",
                    description=(
                        "Android redirects System.out to Logcat, but unlike Log.* it cannot "
                        "be filtered by tag/level. Output is always visible at the I level."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="PRIVACY",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"System.out.print(...) at offset {offset}",
                    remediation="Use android.util.Log with explicit tag/level controls.",
                    cwe_id="CWE-532",
                    cvss=2.7,
                ))
                break  # one per method

            # ── printStackTrace() — exposes internal call paths ────────────
            if _PRINT_STACKTRACE_RE.search(raw):
                findings.append(Finding(
                    rule_id="LOG_PRINT_STACKTRACE",
                    title="printStackTrace() used in catch block",
                    description=(
                        "printStackTrace dumps the full Java call chain to Logcat including "
                        "internal class names. On obfuscated builds this leaks the original "
                        "package layout via line numbers in the mapping file."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="PRIVACY",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"printStackTrace() at offset {offset}",
                    remediation=(
                        "Replace with Log.e(TAG, msg, throwable) so the output is filterable, "
                        "or send the trace to a server-side crash reporter only."
                    ),
                    cwe_id="CWE-209",
                    cvss=3.1,
                ))
                break

        return findings
