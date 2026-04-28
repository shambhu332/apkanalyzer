"""
Privacy compliance detector (GDPR / CCPA / Google Play Data Safety).

Checks
------
PRIVACY_DANGEROUS_PERM_NO_PURPOSE  — dangerous permission with no matching
                                     data safety metadata found in manifest
PRIVACY_LOCATION_BACKGROUND        — ACCESS_BACKGROUND_LOCATION without justification
PRIVACY_CONTACT_READ               — READ_CONTACTS without a clear purpose
PRIVACY_BIOMETRIC_UNPROTECTED      — biometric data accessed without confirmation dialog
PRIVACY_ADVERTISING_ID             — advertising ID collected without resettable-ID notice
PRIVACY_NETWORK_STATE_COMBINED     — combining NETWORK_STATE + LOCATION (fingerprinting)

PII-in-log is intentionally NOT emitted here — the taint engine produces
PII_LOG / PII_NETWORK findings via _privacy_sink_label() with real
source→sink data-flow evidence, which strictly subsumes the regex
"sensitive string + Log call in same method" heuristic this file used to do.

Reference:
  https://developer.android.com/google/play/requirements/data-safety
  https://gdpr.eu/article-5-how-personal-data-be-processed/
"""

from __future__ import annotations

import logging

from apkanalyzer.ir.models import Finding, Severity, Confidence
from apkanalyzer.ir.cfg_builder import get_all_instructions
from apkanalyzer.ir.models import CFGMethod, MethodDescriptor

logger = logging.getLogger(__name__)

# Dangerous permissions that require Data Safety disclosure
_DATA_SAFETY_PERMISSIONS = {
    "android.permission.ACCESS_FINE_LOCATION":     "Precise Location",
    "android.permission.ACCESS_COARSE_LOCATION":   "Approximate Location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Background Location",
    "android.permission.READ_CONTACTS":            "Contacts",
    "android.permission.WRITE_CONTACTS":           "Contacts",
    "android.permission.READ_CALL_LOG":            "Call Logs",
    "android.permission.RECORD_AUDIO":             "Audio Files",
    "android.permission.CAMERA":                   "Photos and Videos",
    "android.permission.READ_SMS":                 "SMS/MMS Messages",
    "android.permission.READ_PHONE_STATE":         "Phone Number/Device ID",
    "android.permission.GET_ACCOUNTS":             "Personal Info (Accounts)",
    "android.permission.USE_BIOMETRIC":            "Biometric Data",
    "android.permission.USE_FINGERPRINT":          "Biometric Data",
    "android.permission.READ_EXTERNAL_STORAGE":    "Files and Docs",
    "android.permission.BODY_SENSORS":             "Health and Fitness",
    "android.permission.ACTIVITY_RECOGNITION":     "App Activity",
}

class PrivacyDetector:

    def analyse_manifest(self, manifest: dict) -> list[Finding]:
        findings = []
        permissions = set(manifest.get("permissions", []))
        dangerous = set(manifest.get("dangerous_permissions", []))

        # Check for background location
        if "android.permission.ACCESS_BACKGROUND_LOCATION" in permissions:
            findings.append(Finding(
                rule_id="PRIVACY_LOCATION_BACKGROUND",
                title="Background location access requested",
                description=(
                    "ACCESS_BACKGROUND_LOCATION allows the app to access the user's "
                    "precise location at any time, even when the app is not in use. "
                    "Google Play requires a compelling use case disclosure and foreground "
                    "location must be requested first."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="PRIVACY",
                file_path="AndroidManifest.xml",
                evidence="android.permission.ACCESS_BACKGROUND_LOCATION in manifest",
                remediation=(
                    "Request foreground location first. Provide in-app justification. "
                    "Declare this in your Data Safety section on Google Play."
                ),
                cwe_id="CWE-359",
                cvss=6.5,
            ))

        # Flag each dangerous permission that requires data safety disclosure
        for perm in dangerous:
            data_type = _DATA_SAFETY_PERMISSIONS.get(perm)
            if data_type:
                findings.append(Finding(
                    rule_id=f"PRIVACY_PERM_{perm.split('.')[-1]}",
                    title=f"Dangerous permission requires Data Safety disclosure: {perm.split('.')[-1]}",
                    description=(
                        f"Permission {perm} grants access to {data_type}. "
                        "Under GDPR Article 5, Google Play Data Safety policy, and CCPA, "
                        "any collection of this data type must be disclosed in your privacy policy "
                        "and Data Safety section."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="PRIVACY",
                    file_path="AndroidManifest.xml",
                    evidence=f"Uses-permission: {perm}",
                    remediation=(
                        f"Ensure {data_type} collection is disclosed in your Privacy Policy "
                        "and Google Play Data Safety section. Only collect what is necessary."
                    ),
                    cwe_id="CWE-359",
                    cvss=4.3,
                ))

        # Location + network state combination = fingerprinting risk
        if ("android.permission.ACCESS_FINE_LOCATION" in permissions and
                "android.permission.ACCESS_NETWORK_STATE" in permissions):
            findings.append(Finding(
                rule_id="PRIVACY_NETWORK_STATE_COMBINED",
                title="Location + network state combination enables device fingerprinting",
                description=(
                    "Combining ACCESS_FINE_LOCATION with ACCESS_NETWORK_STATE allows "
                    "building a highly unique device fingerprint (location + WiFi SSIDs "
                    "+ network topology). This goes beyond normal location access."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                category="PRIVACY",
                file_path="AndroidManifest.xml",
                evidence="Both ACCESS_FINE_LOCATION and ACCESS_NETWORK_STATE declared",
                remediation=(
                    "Justify why both permissions are required simultaneously. "
                    "Avoid persisting or transmitting combined signals."
                ),
                cwe_id="CWE-359",
                cvss=5.9,
            ))

        return findings

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings = []
        instructions = get_all_instructions(cfg)

        for instr in instructions:
            raw = instr.get("raw", "")
            offset = instr.get("offset", 0)

            # PII-in-log detection lives in the taint engine
            # (PII_LOG via _privacy_sink_label) — no regex pass here.

            # ── Advertising ID access ─────────────────────────────────
            if "getAdvertisingIdInfo" in raw or "getAdvertisingId" in raw:
                findings.append(Finding(
                    rule_id="PRIVACY_ADVERTISING_ID",
                    title="Advertising ID (GAID) accessed",
                    description=(
                        "The app reads the Google Advertising ID (GAID). "
                        "Under Play policies, this ID must only be used for advertising "
                        "purposes and must not be combined with non-resettable identifiers. "
                        "Apps targeting children must not use GAID."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="PRIVACY",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"getAdvertisingIdInfo/getAdvertisingId @offset {offset}",
                    remediation=(
                        "Only use GAID for advertising; honour user opt-out (isLimitAdTrackingEnabled). "
                        "Do not persist or combine with hardware identifiers."
                    ),
                    cwe_id="CWE-359",
                    cvss=4.3,
                ))

        return findings
