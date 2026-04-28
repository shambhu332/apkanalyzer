"""
Third-party SDK risk inventory detector.

Identifies known analytics, advertising, tracking, and data-broker SDKs
by their class package prefix.  Flags data exfiltration risk proportional
to the SDK's known data collection practices.

This does NOT use the taint engine — it works purely on class names present
in the DEX, which is both fast and effective since SDK package names are
rarely obfuscated (they must match the manifest provider declarations).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from apkanalyzer.ir.models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SDKSpec:
    prefix: str           # Dalvik class prefix, e.g. "Lcom/facebook/ads/"
    name: str             # Human-readable SDK name
    category: str         # "ANALYTICS" | "ADVERTISING" | "TRACKING" | "CRASH" | "SOCIAL"
    risk: str             # "HIGH" | "MEDIUM" | "LOW"
    cwe_id: str
    data_collected: str   # What the SDK is known to collect
    remediation: str


SDK_CATALOGUE: list[SDKSpec] = [
    # ── Advertising / Tracking ────────────────────────────────────────
    SDKSpec("Lcom/google/android/gms/ads/", "Google Mobile Ads (AdMob)",
            "ADVERTISING", "HIGH", "CWE-359",
            "device ID, location, browsing/app usage, advertising ID",
            "Review AdMob data sharing settings; request consent via UMP SDK."),
    SDKSpec("Lcom/facebook/ads/", "Facebook Audience Network",
            "ADVERTISING", "HIGH", "CWE-359",
            "device ID, advertising ID, app events, purchase data",
            "Implement Facebook Limited Data Use (LDU) flag; enable restricted data processing."),
    SDKSpec("Lcom/applovin/", "AppLovin SDK",
            "ADVERTISING", "HIGH", "CWE-359",
            "device fingerprint, location, behavioral data",
            "Enable CCPA/GDPR consent flow via AppLovin MAX."),
    SDKSpec("Lcom/mopub/", "MoPub SDK",
            "ADVERTISING", "HIGH", "CWE-359",
            "device identifiers, location, ad interaction data",
            "MoPub is deprecated; migrate to AppLovin MAX or Google AdMob."),
    SDKSpec("Lcom/unity3d/ads/", "Unity Ads",
            "ADVERTISING", "MEDIUM", "CWE-359",
            "device ID, app usage, ad interaction",
            "Configure Unity Ads privacy consent flow."),
    SDKSpec("Lcom/chartboost/", "Chartboost SDK",
            "ADVERTISING", "MEDIUM", "CWE-359",
            "device ID, app session data",
            "Implement Chartboost GDPR consent."),
    SDKSpec("Lcom/ironsource/", "IronSource (Unity LevelPlay)",
            "ADVERTISING", "MEDIUM", "CWE-359",
            "device ID, advertising ID, app usage",
            "Implement consent management via Unity LevelPlay mediation."),
    SDKSpec("Lcom/vungle/", "Vungle (Liftoff) SDK",
            "ADVERTISING", "MEDIUM", "CWE-359",
            "device ID, advertising ID",
            "Configure GDPR/CCPA flags in Vungle SDK."),

    # ── Analytics ────────────────────────────────────────────────────
    SDKSpec("Lcom/google/firebase/analytics/", "Firebase Analytics",
            "ANALYTICS", "MEDIUM", "CWE-359",
            "device ID, user events, demographics (if enabled)",
            "Disable ad personalisation features if not needed; add GDPR consent check."),
    SDKSpec("Lcom/amplitude/", "Amplitude Analytics",
            "ANALYTICS", "MEDIUM", "CWE-359",
            "user events, device info, user properties",
            "Enable Amplitude's GDPR deletion API for data subject requests."),
    SDKSpec("Lcom/mixpanel/", "Mixpanel Analytics",
            "ANALYTICS", "MEDIUM", "CWE-359",
            "user events, device info, IP address",
            "Configure Mixpanel GDPR opt-out; implement consent gating."),
    SDKSpec("Lcom/segment/", "Segment (Twilio)",
            "ANALYTICS", "MEDIUM", "CWE-359",
            "user identity, events, traits",
            "Use Segment's consent management; implement deletion requests."),
    SDKSpec("Lio/sentry/", "Sentry Crash Reporting",
            "CRASH", "LOW", "CWE-200",
            "stack traces, device info, breadcrumbs (may contain PII)",
            "Enable Sentry PII scrubbing; review breadcrumb data for sensitive values."),
    SDKSpec("Lcom/bugsnag/", "Bugsnag Crash Reporting",
            "CRASH", "LOW", "CWE-200",
            "stack traces, device metadata, user context",
            "Configure Bugsnag's PII redaction; avoid logging sensitive user data."),
    SDKSpec("Lcom/crashlytics/", "Firebase Crashlytics",
            "CRASH", "LOW", "CWE-200",
            "crash reports, device info, custom keys",
            "Avoid setting sensitive values as Crashlytics custom keys."),

    # ── Social / Identity ─────────────────────────────────────────────
    SDKSpec("Lcom/facebook/", "Facebook SDK (Login/Share)",
            "SOCIAL", "HIGH", "CWE-359",
            "user profile, friends list, app events, device info",
            "Use Facebook's Limited Login; disable automatic event logging."),
    SDKSpec("Lcom/twitter/sdk/", "Twitter SDK",
            "SOCIAL", "MEDIUM", "CWE-359",
            "account info, tweet data",
            "Request minimal OAuth scopes; implement token rotation."),

    # ── Data brokers / fingerprinting ────────────────────────────────
    SDKSpec("Lcom/singular/", "Singular Attribution",
            "TRACKING", "HIGH", "CWE-359",
            "install attribution, device fingerprint, revenue",
            "Enable Singular's SKAN/privacy-preserving mode; disable device fingerprinting."),
    SDKSpec("Lcom/appsflyer/", "AppsFlyer Attribution",
            "TRACKING", "HIGH", "CWE-359",
            "install source, device ID, revenue, in-app events",
            "Enable AppsFlyer privacy mode; implement consent flag."),
    SDKSpec("Lcom/adjust/sdk/", "Adjust Attribution",
            "TRACKING", "HIGH", "CWE-359",
            "install attribution, click data, device ID",
            "Enable Adjust's GDPR right-to-be-forgotten API."),
    SDKSpec("Lcom/branch/", "Branch.io Attribution",
            "TRACKING", "HIGH", "CWE-359",
            "deep link attribution, device fingerprint, user identity",
            "Disable Branch fingerprinting; implement consent-based tracking."),
    SDKSpec("Lcom/kochava/", "Kochava Attribution",
            "TRACKING", "HIGH", "CWE-359",
            "install attribution, device ID, app usage",
            "Enable Kochava privacy profile mode."),

    # ── Location SDKs ─────────────────────────────────────────────────
    SDKSpec("Lcom/foursquare/pilgrim/", "Foursquare Pilgrim SDK",
            "TRACKING", "HIGH", "CWE-359",
            "precise and background location, venue visits",
            "Remove Pilgrim SDK if not core to product; add explicit consent."),
    SDKSpec("Lio/radar/", "Radar Location SDK",
            "TRACKING", "HIGH", "CWE-359",
            "precise GPS, geofence visits, trip data",
            "Implement Radar's consent management; limit location precision."),
]


class SDKDetector:
    """
    Scan class names from the DEX for known third-party SDK prefixes.
    Returns one finding per detected SDK.
    """

    def analyse_classes(self, class_names: list[str], package: str = "") -> list[Finding]:
        detected: dict[str, SDKSpec] = {}

        for cls in class_names:
            for spec in SDK_CATALOGUE:
                if cls.startswith(spec.prefix) and spec.prefix not in detected:
                    detected[spec.prefix] = spec
                    break

        findings = []
        for spec in detected.values():
            sev = Severity.HIGH if spec.risk == "HIGH" else (
                Severity.MEDIUM if spec.risk == "MEDIUM" else Severity.LOW
            )
            findings.append(Finding(
                rule_id=f"SDK_{spec.name.upper().replace(' ', '_').replace('(', '').replace(')', '')[:30]}",
                title=f"Third-party SDK detected: {spec.name}",
                description=(
                    f"{spec.name} ({spec.category}) is present in the APK. "
                    f"Known data collection: {spec.data_collected}. "
                    "Third-party SDKs may collect and transmit user data independently "
                    "of your privacy policy disclosures."
                ),
                severity=sev,
                confidence=Confidence.HIGH,
                category="SDK",
                file_path="DEX classes",
                evidence=f"Class prefix detected: {spec.prefix}",
                remediation=spec.remediation,
                cwe_id=spec.cwe_id,
                cvss=7.5 if spec.risk == "HIGH" else (5.3 if spec.risk == "MEDIUM" else 3.1),
            ))

        return findings
