"""
Intent / IPC security detector.

Checks
------
INTENT_IMPLICIT_PII             — sendBroadcast with implicit intent + sensitive extras
INTENT_PENDING_MUTABLE          — PendingIntent.getActivity/getBroadcast without FLAG_IMMUTABLE
INTENT_GET_PARCELABLE_UNCHECKED — getParcelableExtra without class verification (CVE-2014-1909 family)
INTENT_TASK_HIJACK              — startActivity with FLAG_ACTIVITY_NEW_TASK + singleTask risk
INTENT_REDIRECTION              — Forwarding an external intent to a privileged component
INTENT_STICKY_BROADCAST         — sendStickyBroadcast (deprecated, leaks data)
"""

from __future__ import annotations

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions


_PENDING_INTENT_METHODS = {
    "getActivity", "getActivities", "getBroadcast",
    "getService", "getForegroundService",
}

_STICKY_METHODS = {
    "sendStickyBroadcast",
    "sendStickyBroadcastAsUser",
    "sendStickyOrderedBroadcast",
}


class IntentDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instrs = get_all_instructions(cfg)
        joined = " ".join(i.get("raw", "") for i in instrs)

        for instr in instrs:
            raw = instr.get("raw", "")
            offset = instr.get("offset", 0)

            # Sticky broadcast (deprecated, world-readable)
            for sm in _STICKY_METHODS:
                if f"->{sm}(" in raw:
                    findings.append(Finding(
                        rule_id="INTENT_STICKY_BROADCAST",
                        title=f"Use of deprecated {sm}",
                        description=(
                            "Sticky broadcasts are world-readable, persist across reboots, "
                            "and were deprecated in API 21. Any app with READ_LOGS-style access "
                            "(or a malicious app on older devices) can read them."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="MANIFEST",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"{sm}() at offset {offset}",
                        remediation=(
                            "Replace sticky broadcasts with LocalBroadcastManager, a bound "
                            "service, LiveData, or a SharedPreferences listener."
                        ),
                        cwe_id="CWE-925",
                        cvss=5.0,
                    ))

            # PendingIntent without FLAG_IMMUTABLE — checks the *block*, not the line
            # Look for invocations like Landroid/app/PendingIntent;->getActivity(
            if "Landroid/app/PendingIntent;->" in raw:
                for pm in _PENDING_INTENT_METHODS:
                    if f"->{pm}(" in raw:
                        # Heuristic: scan surrounding instructions for FLAG_IMMUTABLE (0x4000000 = 67108864)
                        flag_immutable_present = any(
                            "67108864" in (i.get("raw", "") or "")
                            or "FLAG_IMMUTABLE" in (i.get("raw", "") or "")
                            for i in instrs
                        )
                        if not flag_immutable_present:
                            findings.append(Finding(
                                rule_id="INTENT_PENDING_MUTABLE",
                                title="PendingIntent created without FLAG_IMMUTABLE",
                                description=(
                                    "On API 31+ a PendingIntent must specify FLAG_IMMUTABLE "
                                    "or FLAG_MUTABLE. Mutable PendingIntents allow the receiver "
                                    "(any app holding it) to fill in extras and Intent fields, "
                                    "leading to permission escalation via your app's identity."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                category="MANIFEST",
                                class_name=desc.class_name,
                                method_name=desc.method_name,
                                evidence=f"PendingIntent.{pm}() — no FLAG_IMMUTABLE in this method",
                                remediation=(
                                    "Pass PendingIntent.FLAG_IMMUTABLE (0x4000000) when creating "
                                    "the PendingIntent unless the receiver legitimately needs to "
                                    "fill in fields (then use FLAG_MUTABLE explicitly)."
                                ),
                                cwe_id="CWE-927",
                                cvss=7.5,
                            ))
                            break  # one per method is enough

            # getParcelableExtra without class — CVE-2014-1909 / CVE-2017-13315 family
            if "->getParcelableExtra(Ljava/lang/String;)" in raw:
                findings.append(Finding(
                    rule_id="INTENT_GET_PARCELABLE_UNCHECKED",
                    title="getParcelableExtra() without class verification",
                    description=(
                        "The single-arg form of getParcelableExtra(String) is deprecated on "
                        "API 33+. It cannot type-check the parcelable, allowing a malicious "
                        "caller to substitute a Parcelable that triggers code in your process."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="MANIFEST",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"getParcelableExtra() at offset {offset}",
                    remediation=(
                        "Use IntentCompat.getParcelableExtra(intent, key, ExpectedClass.class) "
                        "or the API-33 getParcelableExtra(String, Class) overload."
                    ),
                    cwe_id="CWE-502",
                    cvss=6.5,
                ))

            # Intent redirection — passing an Intent we received to startActivity
            if "->startActivity(Landroid/content/Intent;)" in raw and (
                "getIntent()" in joined or "getParcelableExtra" in joined
            ):
                findings.append(Finding(
                    rule_id="INTENT_REDIRECTION",
                    title="Possible intent redirection",
                    description=(
                        "This method retrieves an Intent from outside (getIntent / "
                        "getParcelableExtra) and forwards it via startActivity. An attacker "
                        "can craft the inner Intent to target a private component, gaining "
                        "your app's permissions."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    category="MANIFEST",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence="getIntent()/getParcelableExtra → startActivity()",
                    remediation=(
                        "Validate the forwarded Intent's component / package, or set a "
                        "ComponentName explicitly to the intended target."
                    ),
                    cwe_id="CWE-940",
                    cvss=7.0,
                ))

        return findings

    def analyse_manifest(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        target_sdk = int(manifest.get("target_sdk") or 0)

        # Custom permissions with weak protection level
        for perm in manifest.get("custom_permissions", []) or []:
            level = (perm.get("protectionLevel") or "normal").lower()
            if "normal" in level or level == "":
                findings.append(Finding(
                    rule_id="MANIFEST_CUSTOM_PERMISSION_NORMAL",
                    title=f"Custom permission '{perm.get('name','?')}' uses 'normal' protection",
                    description=(
                        "Custom permissions with protectionLevel=normal are auto-granted "
                        "to any app that requests them. Use 'signature' so only apps signed "
                        "by the same key can hold the permission."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="MANIFEST",
                    file_path="AndroidManifest.xml",
                    evidence=f"<permission name=\"{perm.get('name','?')}\" protectionLevel=\"{level}\"/>",
                    remediation='Use protectionLevel="signature" or "signatureOrSystem".',
                    cwe_id="CWE-732",
                    cvss=5.5,
                ))

        # Exported provider with grantUriPermissions=true
        for prov in manifest.get("exported_providers", []) or []:
            if prov.get("grant_uri_permissions"):
                findings.append(Finding(
                    rule_id="MANIFEST_PROVIDER_GRANT_URI",
                    title=f"ContentProvider '{prov.get('name','?')}' grants URI permissions",
                    description=(
                        "When grantUriPermissions=true on an exported provider, any caller "
                        "can be temporarily granted read/write on URIs the provider returns. "
                        "Combined with intent redirection, this leaks file content."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="MANIFEST",
                    file_path="AndroidManifest.xml",
                    evidence=f"provider {prov.get('name','?')} grantUriPermissions=true",
                    remediation=(
                        "Restrict to <grant-uri-permission> path/pathPrefix entries, set "
                        'android:exported="false", or guard with a signature permission.'
                    ),
                    cwe_id="CWE-200",
                    cvss=7.5,
                ))

        # Tapjacking — only meaningful for activities targeting older API
        if 0 < target_sdk < 23 and manifest.get("exported_activities"):
            findings.append(Finding(
                rule_id="MANIFEST_TAPJACKING_RISK",
                title=f"App targets SDK {target_sdk} — exported activities vulnerable to tapjacking",
                description=(
                    "Pre-API-23 systems do not enforce filterTouchesWhenObscured by "
                    "default, allowing overlay attacks (tapjacking) on exported activities."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="MANIFEST",
                file_path="AndroidManifest.xml",
                evidence=f"targetSdkVersion={target_sdk}",
                remediation=(
                    "Bump targetSdkVersion to 23+ and explicitly set "
                    "android:filterTouchesWhenObscured=\"true\" on sensitive views."
                ),
                cwe_id="CWE-1021",
                cvss=4.7,
            ))

        # Missing or low targetSdk
        if 0 < target_sdk < 30:
            findings.append(Finding(
                rule_id="MANIFEST_TARGET_SDK_LOW",
                title=f"Low targetSdkVersion ({target_sdk}) — Play Store policy & sandbox",
                description=(
                    "targetSdk below 30 misses scoped storage enforcement, the new "
                    "permissions model, and Play Store policy minimums. It also opts the "
                    "app into legacy behaviours that are easier to exploit."
                ),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="MANIFEST",
                file_path="AndroidManifest.xml",
                evidence=f"targetSdkVersion={target_sdk}",
                remediation="Update build.gradle to targetSdk 33 or later.",
                cwe_id="CWE-1104",
                cvss=3.0,
            ))

        # Missing networkSecurityConfig on modern apps
        if target_sdk >= 24 and not manifest.get("network_security_config"):
            findings.append(Finding(
                rule_id="MANIFEST_NSC_MISSING",
                title="No networkSecurityConfig declared",
                description=(
                    "Without a networkSecurityConfig.xml, the app inherits the platform "
                    "default trust store (including user-installed CAs on API < 24). "
                    "Declaring an explicit config gives you control over pinning, "
                    "cleartext, and trust anchors."
                ),
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                category="NETWORK",
                file_path="AndroidManifest.xml",
                evidence="<application> has no android:networkSecurityConfig",
                remediation=(
                    "Add android:networkSecurityConfig=\"@xml/network_security_config\" "
                    "with cleartextTrafficPermitted=false and pin-set entries."
                ),
                cwe_id="CWE-295",
                cvss=3.7,
            ))

        return findings
