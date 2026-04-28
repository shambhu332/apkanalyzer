"""
Anti-analysis / root / emulator detection detector.

Checks
------
ANTIANALYSIS_ROOT_CHECK      — su binary / RootBeer / SuperUser.apk checks
ANTIANALYSIS_EMULATOR_CHECK  — Build.FINGERPRINT, ro.kernel.qemu checks
ANTIANALYSIS_DEBUGGER_CHECK  — isDebuggerConnected, ptrace detection
ANTIANALYSIS_FRIDA_DETECT    — Frida server port scan, frida string checks
ANTIANALYSIS_HOOK_DETECT     — Xposed/LSPosed framework detection
ANTIANALYSIS_PACKAGE_TAMPER  — Signature verification / package name checks
ANTIANALYSIS_PROC_CHECK      — /proc/self/status TracerPid / maps scanning
ANTIANALYSIS_PORT_SCAN       — Network socket connect to known tool ports

Anti-analysis techniques are dual-use:
- Legitimate apps use them to harden against reverse engineering
- Malware uses them to hide behavior during analysis

We flag ALL as findings so the analyst can:
1. Confirm legitimate use (accept as hardening)
2. Verify coverage is complete (all vectors detected)
3. Identify potential evasion gaps for security testing
"""

from __future__ import annotations

import logging
import re

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions

logger = logging.getLogger(__name__)

# Root-related strings
_ROOT_STRINGS = frozenset({
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "supersu", "superuser", "rootbeer", "magisk", "magiskmanager",
    "/data/local/tmp/su", "com.noshufou.android.su",
    "com.thirdparty.superuser", "com.yellowes.su",
    "eu.chainfire.supersu", "com.koushikdutta.superuser",
    "com.koushikdutta.rommanager", "com.zachspong.temprootremovejb",
    "com.ramdroid.appquarantine", "com.topjohnwu.magisk",
})

# Emulator / virtual device strings
_EMULATOR_STRINGS = frozenset({
    "goldfish", "sdk_gphone", "generic", "vbox86", "android_x86",
    "ro.kernel.qemu", "ro.hardware", "andy", "genymotion",
    "emulator-5554", "emulator", "bluestacks", "noxplayer",
    "vmos", "ldplayer", "memu", "droid4x", "youwave",
    "sdk_google_phone_x86", "google_sdk", "qemu-i386",
    "ttvm_hdragon", "leapdroid", "windroye",
})

# Frida dynamic instrumentation strings
_FRIDA_STRINGS = frozenset({
    "frida-agent", "frida-server", "gum-js-loop", "linjector",
    "re.frida.server", "frida-gadget", "frida_agent_main",
    "27042",   # Frida default port
    "27043",   # Frida alternative port
    "fridaclient",
})

# Xposed / LSPosed strings
_XPOSED_STRINGS = frozenset({
    "xposedbridge", "de.robv.android.xposed",
    "io.github.lsposed", "org.lsposed", "xposed_init",
    "de.robv.android.xposed.installer",
})

# /proc virtual filesystem strings used to detect analysis tools
_PROC_STRINGS = frozenset({
    "/proc/self/status", "/proc/self/maps", "/proc/self/fd",
    "tracerpid", "/proc/net/tcp",
})

# Known analysis tool ports for socket-based detection
_TOOL_PORT_STRINGS = frozenset({
    "27042", "27043",  # Frida
    "5037",            # ADB
    "1234", "4321",    # GDB server defaults
})

_ROOT_FILE_PATTERN = re.compile(
    r'(?i)(/?system/(bin|xbin|app)/su|/data/local(/tmp)?/su|/sbin/su)',
)


class AntiAnalysisDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instructions = get_all_instructions(cfg)

        seen: set[str] = set()  # deduplicate categories within this method

        # Flatten all string values seen in this method
        all_strings = {v.lower() for v in reg_strings.values()}

        for instr in instructions:
            raw = instr.get("raw", "")
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)

            # ── String constant checks ────────────────────────────────
            if "const-string" in mnemonic:
                for val in reg_strings.values():
                    val_lower = val.lower()

                    if "ROOT" not in seen and (
                        any(s in val_lower for s in _ROOT_STRINGS)
                        or _ROOT_FILE_PATTERN.search(val)
                    ):
                        seen.add("ROOT")
                        findings.append(Finding(
                            rule_id="ANTIANALYSIS_ROOT_CHECK",
                            title="Root detection attempt detected",
                            description=(
                                f"The app checks for root-related files, packages, or "
                                f"strings (found: '{val[:80]}'). May refuse service on "
                                "rooted devices or evade analysis on rooted test devices."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            category="ANTIANALYSIS",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"const-string '{val[:80]}' @offset {offset}",
                            remediation=(
                                "Document root-detection rationale. Ensure checks are "
                                "not used to block security researchers or hide behavior. "
                                "Prefer Play Integrity API for attestation."
                            ),
                            cwe_id="CWE-693",
                            cvss=0.0,
                        ))

                    if "EMULATOR" not in seen and any(
                        s in val_lower for s in _EMULATOR_STRINGS
                    ):
                        seen.add("EMULATOR")
                        findings.append(Finding(
                            rule_id="ANTIANALYSIS_EMULATOR_CHECK",
                            title="Emulator detection attempt detected",
                            description=(
                                f"The app checks for emulator/virtual device fingerprints "
                                f"(found: '{val[:80]}'). May prevent automated test "
                                "environments and indicate behavior-hiding."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category="ANTIANALYSIS",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"Emulator string '{val[:80]}' @offset {offset}",
                            remediation=(
                                "Use Play Integrity API for device attestation instead of "
                                "manual emulator checks, which are easy to bypass."
                            ),
                            cwe_id="CWE-693",
                            cvss=3.1,
                        ))

                    if "FRIDA" not in seen and any(
                        s in val_lower for s in _FRIDA_STRINGS
                    ):
                        seen.add("FRIDA")
                        findings.append(Finding(
                            rule_id="ANTIANALYSIS_FRIDA_DETECT",
                            title="Frida dynamic instrumentation detection attempt",
                            description=(
                                f"The app detects the Frida instrumentation framework "
                                f"(found: '{val[:80]}'). Blocks legitimate security testing "
                                "and indicates potential malicious behavior hiding."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="ANTIANALYSIS",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"Frida string '{val[:80]}' @offset {offset}",
                            remediation=(
                                "Anti-Frida checks are fragile and easily bypassed. "
                                "Use server-side integrity checks instead."
                            ),
                            cwe_id="CWE-693",
                            cvss=3.7,
                        ))

                    if "XPOSED" not in seen and any(
                        s in val_lower for s in _XPOSED_STRINGS
                    ):
                        seen.add("XPOSED")
                        findings.append(Finding(
                            rule_id="ANTIANALYSIS_HOOK_DETECT",
                            title="Xposed/LSPosed hook framework detection attempt",
                            description=(
                                f"The app checks for Xposed or LSPosed hooking frameworks "
                                f"(found: '{val[:80]}'). Indicates anti-tamper logic."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            category="ANTIANALYSIS",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"Xposed string '{val[:80]}' @offset {offset}",
                            remediation=(
                                "Use Play Integrity API for runtime integrity attestation "
                                "instead of manual hook detection."
                            ),
                            cwe_id="CWE-693",
                            cvss=0.0,
                        ))

                    if "PROC" not in seen and any(
                        s in val_lower for s in _PROC_STRINGS
                    ):
                        seen.add("PROC")
                        findings.append(Finding(
                            rule_id="ANTIANALYSIS_PROC_CHECK",
                            title="Process-level analysis detection via /proc filesystem",
                            description=(
                                f"The app reads from /proc virtual filesystem "
                                f"(found: '{val[:80]}'). Reading /proc/self/status "
                                "for TracerPid detects attached debuggers; reading "
                                "/proc/self/maps detects Frida memory mappings."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="ANTIANALYSIS",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"/proc path '{val[:80]}' @offset {offset}",
                            remediation=(
                                "Document why /proc is read. Ensure this is not used "
                                "to block legitimate security research."
                            ),
                            cwe_id="CWE-693",
                            cvss=3.1,
                        ))

                    if "PORT_SCAN" not in seen and any(
                        port in val_lower for port in _TOOL_PORT_STRINGS
                    ) and ("socket" in all_strings or "connect" in all_strings
                           or "sockaddr" in all_strings):
                        seen.add("PORT_SCAN")
                        findings.append(Finding(
                            rule_id="ANTIANALYSIS_PORT_SCAN",
                            title="Analysis tool port scan detected",
                            description=(
                                f"The app references port {val[:10]} in a network context. "
                                "Port 27042/27043 is Frida's default port; 5037 is ADB. "
                                "This pattern indicates scanning for running analysis tools."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            category="ANTIANALYSIS",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"Tool port '{val[:10]}' with socket usage @offset {offset}",
                            remediation=(
                                "Port scanning for analysis tools indicates evasive behavior. "
                                "Use Play Integrity API for attestation instead."
                            ),
                            cwe_id="CWE-693",
                            cvss=4.0,
                        ))

            if not mnemonic.startswith("invoke"):
                continue

            # ── Debugger detection ────────────────────────────────────
            if "isDebuggerConnected" in raw and "DEBUGGER" not in seen:
                seen.add("DEBUGGER")
                findings.append(Finding(
                    rule_id="ANTIANALYSIS_DEBUGGER_CHECK",
                    title="Debugger detection via isDebuggerConnected()",
                    description=(
                        "The app calls Debug.isDebuggerConnected() to detect an attached "
                        "debugger. Legitimate as anti-tamper, but also used to hide "
                        "malicious behavior during analysis."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="ANTIANALYSIS",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Debug.isDebuggerConnected() @offset {offset}",
                    remediation=(
                        "Use Play Integrity API for attestation. If anti-debug is required, "
                        "use it only to refuse sensitive operations, not hide behavior."
                    ),
                    cwe_id="CWE-693",
                    cvss=0.0,
                ))

            # ── waitingForDebugger detection ──────────────────────────
            if "waitingForDebugger" in raw and "DEBUGGER_WAIT" not in seen:
                seen.add("DEBUGGER_WAIT")
                findings.append(Finding(
                    rule_id="ANTIANALYSIS_DEBUGGER_CHECK",
                    title="Debugger detection via Debug.waitingForDebugger()",
                    description=(
                        "Debug.waitingForDebugger() returns true when the app is "
                        "paused waiting for a debugger to attach. This is used in "
                        "combination with isDebuggerConnected for advanced detection."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="ANTIANALYSIS",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Debug.waitingForDebugger() @offset {offset}",
                    remediation="Use Play Integrity API for attestation.",
                    cwe_id="CWE-693",
                    cvss=0.0,
                ))

            # ── Signature / package tampering check ───────────────────
            if ("GET_SIGNATURES" in raw or "GET_SIGNING_CERTIFICATES" in raw) \
                    and "TAMPER" not in seen:
                seen.add("TAMPER")
                findings.append(Finding(
                    rule_id="ANTIANALYSIS_PACKAGE_TAMPER",
                    title="APK signature verification (anti-tamper check)",
                    description=(
                        "The app verifies its own package signature, a common "
                        "anti-repackaging technique. This check can be bypassed with "
                        "Xposed hooks or smali patching."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="ANTIANALYSIS",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"getPackageInfo with GET_SIGNATURES @offset {offset}",
                    remediation=(
                        "Combine signature checks with Play Integrity API for "
                        "server-verified attestation. Obfuscate the check itself."
                    ),
                    cwe_id="CWE-693",
                    cvss=0.0,
                ))

            # ── SafetyNet / Play Integrity (informational — hardening) ─
            if ("SafetyNet" in raw or "Integrity" in raw) and "INTEGRITY" not in seen:
                seen.add("INTEGRITY")
                findings.append(Finding(
                    rule_id="ANTIANALYSIS_INTEGRITY_API",
                    title="Play Integrity / SafetyNet attestation detected (hardening)",
                    description=(
                        "The app uses Google Play Integrity API or SafetyNet for "
                        "device attestation. This is the recommended hardening approach."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    category="ANTIANALYSIS",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Integrity/SafetyNet @offset {offset}",
                    remediation=(
                        "Ensure attestation results are validated server-side. "
                        "Migrate from SafetyNet to Play Integrity API (SafetyNet deprecated)."
                    ),
                    cwe_id="CWE-693",
                    cvss=0.0,
                ))

        return findings
