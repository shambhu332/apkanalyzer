"""
Exodus-Privacy tracker DB detector.

What this is
------------
A curated list of trackers (analytics, advertising, fingerprinting, profiling)
adapted from the Exodus-Privacy ETIP open dataset. Each tracker is identified
by its Java/Kotlin package prefix, and surfaces as a privacy finding when the
prefix is present in the APK's class table.

The set differs from `sdk_detector.py` in scope: SDKDetector picks the very
biggest SDK families with detailed remediation guidance, this detector covers
the long tail (~120 entries) so privacy reports surface every embedded
tracker — comparable to MobSF's tracker section.

Tracker categories
------------------
- ANALYTICS    : event/usage analytics
- ADVERTISING  : ad-network SDKs
- IDENTIFIER   : fingerprinting / device-graph builders
- PROFILING    : behavioural targeting
- LOCATION     : continuous-location data brokers
- CRASH        : crash reporting (often funnels device metadata)
- PUSH         : push messaging (often piggybacks attribution)
"""

from __future__ import annotations

from dataclasses import dataclass

from apkanalyzer.ir.models import Finding, Severity, Confidence


@dataclass(frozen=True)
class TrackerSpec:
    name: str
    prefix: str        # Dalvik prefix
    category: str      # ANALYTICS / ADVERTISING / IDENTIFIER / ...
    homepage: str = "" # informational only


# Curated subset of the Exodus tracker list — the ~120 most-prevalent entries.
# Source attribution: https://reports.exodus-privacy.eu.org/ (open data, AGPLv3
# project; signatures adapted under fair-use for security analysis).
TRACKERS: list[TrackerSpec] = [
    # ── Top-tier analytics / advertising ─────────────────────────────────
    TrackerSpec("Google AdMob", "Lcom/google/android/gms/ads/", "ADVERTISING"),
    TrackerSpec("Google Firebase Analytics", "Lcom/google/firebase/analytics/", "ANALYTICS"),
    TrackerSpec("Google CrashLytics", "Lcom/google/firebase/crashlytics/", "CRASH"),
    TrackerSpec("Google DoubleClick", "Lcom/google/android/gms/ads/doubleclick/", "ADVERTISING"),
    TrackerSpec("Google Tag Manager", "Lcom/google/android/gms/tagmanager/", "ANALYTICS"),
    TrackerSpec("Google Conversion Tracking", "Lcom/google/ads/conversiontracking/", "ADVERTISING"),
    TrackerSpec("Facebook Login", "Lcom/facebook/login/", "IDENTIFIER"),
    TrackerSpec("Facebook Analytics", "Lcom/facebook/appevents/", "ANALYTICS"),
    TrackerSpec("Facebook Audience", "Lcom/facebook/ads/", "ADVERTISING"),
    TrackerSpec("Facebook Share", "Lcom/facebook/share/", "PROFILING"),
    TrackerSpec("Facebook Places", "Lcom/facebook/places/", "LOCATION"),

    # ── Big attribution networks ────────────────────────────────────────
    TrackerSpec("AppsFlyer", "Lcom/appsflyer/", "IDENTIFIER"),
    TrackerSpec("Adjust", "Lcom/adjust/sdk/", "IDENTIFIER"),
    TrackerSpec("Branch", "Lio/branch/", "IDENTIFIER"),
    TrackerSpec("Branch (legacy)", "Lcom/branch/", "IDENTIFIER"),
    TrackerSpec("Singular", "Lcom/singular/sdk/", "IDENTIFIER"),
    TrackerSpec("Kochava", "Lcom/kochava/", "IDENTIFIER"),
    TrackerSpec("Tenjin", "Lcom/tenjin/", "IDENTIFIER"),
    TrackerSpec("Tune", "Lcom/tune/", "IDENTIFIER"),

    # ── Ad networks ─────────────────────────────────────────────────────
    TrackerSpec("AppLovin", "Lcom/applovin/", "ADVERTISING"),
    TrackerSpec("Unity Ads", "Lcom/unity3d/ads/", "ADVERTISING"),
    TrackerSpec("ironSource", "Lcom/ironsource/", "ADVERTISING"),
    TrackerSpec("MoPub", "Lcom/mopub/", "ADVERTISING"),
    TrackerSpec("Vungle", "Lcom/vungle/", "ADVERTISING"),
    TrackerSpec("Chartboost", "Lcom/chartboost/", "ADVERTISING"),
    TrackerSpec("InMobi", "Lcom/inmobi/", "ADVERTISING"),
    TrackerSpec("Tapjoy", "Lcom/tapjoy/", "ADVERTISING"),
    TrackerSpec("AdColony", "Lcom/adcolony/", "ADVERTISING"),
    TrackerSpec("Smaato", "Lcom/smaato/", "ADVERTISING"),
    TrackerSpec("MyTarget", "Lcom/my/target/", "ADVERTISING"),
    TrackerSpec("Pangle (ByteDance)", "Lcom/bytedance/sdk/", "ADVERTISING"),
    TrackerSpec("Mintegral", "Lcom/mintegral/", "ADVERTISING"),
    TrackerSpec("Mintegral (legacy)", "Lcom/mbridge/", "ADVERTISING"),
    TrackerSpec("Fyber", "Lcom/fyber/", "ADVERTISING"),
    TrackerSpec("Yandex Ads", "Lcom/yandex/mobile/ads/", "ADVERTISING"),
    TrackerSpec("Verizon Media", "Lcom/verizon/ads/", "ADVERTISING"),
    TrackerSpec("Nend", "Lnet/nend/android/", "ADVERTISING"),
    TrackerSpec("LoopMe", "Lcom/loopme/", "ADVERTISING"),
    TrackerSpec("Startapp", "Lcom/startapp/", "ADVERTISING"),
    TrackerSpec("Outbrain", "Lcom/outbrain/", "ADVERTISING"),
    TrackerSpec("Taboola", "Lcom/taboola/", "ADVERTISING"),
    TrackerSpec("Maio", "Ljp/maio/sdk/", "ADVERTISING"),
    TrackerSpec("Yieldmo", "Lcom/yieldmo/", "ADVERTISING"),
    TrackerSpec("Criteo", "Lcom/criteo/publisher/", "ADVERTISING"),

    # ── Analytics ───────────────────────────────────────────────────────
    TrackerSpec("Mixpanel", "Lcom/mixpanel/android/", "ANALYTICS"),
    TrackerSpec("Amplitude", "Lcom/amplitude/", "ANALYTICS"),
    TrackerSpec("Segment", "Lcom/segment/analytics/", "ANALYTICS"),
    TrackerSpec("Heap", "Lcom/heapanalytics/android/", "ANALYTICS"),
    TrackerSpec("FullStory", "Lcom/fullstory/", "PROFILING"),
    TrackerSpec("Hotjar", "Lcom/hotjar/", "PROFILING"),
    TrackerSpec("ContentSquare", "Lcom/contentsquare/", "PROFILING"),
    TrackerSpec("AppDynamics", "Lcom/appdynamics/", "ANALYTICS"),
    TrackerSpec("New Relic", "Lcom/newrelic/agent/android/", "ANALYTICS"),
    TrackerSpec("Datadog RUM", "Lcom/datadog/android/", "ANALYTICS"),
    TrackerSpec("Adobe Analytics", "Lcom/adobe/marketing/", "ANALYTICS"),
    TrackerSpec("Adobe Mobile", "Lcom/adobe/mobile/", "ANALYTICS"),
    TrackerSpec("Localytics", "Lcom/localytics/android/", "ANALYTICS"),
    TrackerSpec("Flurry", "Lcom/flurry/android/", "ANALYTICS"),
    TrackerSpec("Yandex Metrica", "Lcom/yandex/metrica/", "ANALYTICS"),
    TrackerSpec("Countly", "Lly/count/android/sdk/", "ANALYTICS"),
    TrackerSpec("Matomo", "Lorg/matomo/sdk/", "ANALYTICS"),
    TrackerSpec("Plausible", "Lcom/plausible/sdk/", "ANALYTICS"),
    TrackerSpec("Smartlook", "Lcom/smartlook/sdk/", "PROFILING"),
    TrackerSpec("UXCam", "Lcom/uxcam/", "PROFILING"),
    TrackerSpec("Umeng", "Lcom/umeng/", "ANALYTICS"),
    TrackerSpec("Tencent MTA", "Lcom/tencent/stat/", "ANALYTICS"),
    TrackerSpec("Tencent Bugly", "Lcom/tencent/bugly/", "CRASH"),
    TrackerSpec("Mixin", "Lcom/mixin/android/", "ANALYTICS"),

    # ── Crash / monitoring ──────────────────────────────────────────────
    TrackerSpec("Sentry", "Lio/sentry/", "CRASH"),
    TrackerSpec("Bugsnag", "Lcom/bugsnag/android/", "CRASH"),
    TrackerSpec("Rollbar", "Lcom/rollbar/android/", "CRASH"),
    TrackerSpec("Embrace.io", "Lio/embrace/android/", "CRASH"),
    TrackerSpec("Instabug", "Lcom/instabug/", "CRASH"),
    TrackerSpec("Raygun", "Lcom/raygun/", "CRASH"),
    TrackerSpec("AppCenter", "Lcom/microsoft/appcenter/", "CRASH"),

    # ── Push / engagement ───────────────────────────────────────────────
    TrackerSpec("OneSignal", "Lcom/onesignal/", "PUSH"),
    TrackerSpec("Airship (Urban Airship)", "Lcom/urbanairship/", "PUSH"),
    TrackerSpec("Iterable", "Lcom/iterable/iterableapi/", "PUSH"),
    TrackerSpec("Braze (formerly Appboy)", "Lcom/braze/", "PUSH"),
    TrackerSpec("Appboy (legacy)", "Lcom/appboy/", "PUSH"),
    TrackerSpec("Pushwoosh", "Lcom/pushwoosh/", "PUSH"),
    TrackerSpec("Mparticle", "Lcom/mparticle/", "PUSH"),
    TrackerSpec("CleverTap", "Lcom/clevertap/android/sdk/", "PUSH"),
    TrackerSpec("Leanplum", "Lcom/leanplum/", "PUSH"),
    TrackerSpec("MoEngage", "Lcom/moengage/", "PUSH"),
    TrackerSpec("WebEngage", "Lcom/webengage/sdk/android/", "PUSH"),
    TrackerSpec("Smooch", "Lio/smooch/", "PUSH"),

    # ── Identity / fingerprinting ───────────────────────────────────────
    TrackerSpec("Fingerprint Pro", "Lcom/fingerprintjs/", "IDENTIFIER"),
    TrackerSpec("OpenX", "Lcom/openx/", "IDENTIFIER"),
    TrackerSpec("LiveRamp", "Lcom/liveramp/mobilesdk/", "IDENTIFIER"),
    TrackerSpec("ID5", "Lio/id5/sdk/", "IDENTIFIER"),
    TrackerSpec("Permutive", "Lcom/permutive/android/", "IDENTIFIER"),
    TrackerSpec("Zeotap", "Lcom/zeotap/", "IDENTIFIER"),
    TrackerSpec("Throtle", "Lcom/throtle/", "IDENTIFIER"),

    # ── Location / data brokers ─────────────────────────────────────────
    TrackerSpec("Foursquare Pilgrim", "Lcom/foursquare/pilgrim/", "LOCATION"),
    TrackerSpec("Radar", "Lio/radar/sdk/", "LOCATION"),
    TrackerSpec("Reveal Mobile (Pulse)", "Lcom/revealmobile/", "LOCATION"),
    TrackerSpec("X-Mode (Outlogic)", "Lio/xmode/", "LOCATION"),
    TrackerSpec("X-Mode (legacy)", "Lcom/xmode/", "LOCATION"),
    TrackerSpec("Predicio", "Lcom/predicio/", "LOCATION"),
    TrackerSpec("Cuebiq", "Lcom/cuebiq/", "LOCATION"),
    TrackerSpec("Tutela", "Lcom/tutela/", "LOCATION"),
    TrackerSpec("Sense360", "Lcom/sense360/", "LOCATION"),
    TrackerSpec("Sentiance", "Lcom/sentiance/sdk/", "LOCATION"),
    TrackerSpec("Gimbal", "Lcom/gimbal/", "LOCATION"),
    TrackerSpec("Bluedot", "Lau/com/bluedot/point/", "LOCATION"),

    # ── Profiling / engagement ──────────────────────────────────────────
    TrackerSpec("Optimizely", "Lcom/optimizely/ab/android/", "PROFILING"),
    TrackerSpec("LaunchDarkly", "Lcom/launchdarkly/", "PROFILING"),
    TrackerSpec("Apptimize", "Lcom/apptimize/", "PROFILING"),
    TrackerSpec("Apptentive", "Lcom/apptentive/android/sdk/", "PROFILING"),
    TrackerSpec("Taplytics", "Lcom/taplytics/sdk/", "PROFILING"),
    TrackerSpec("Customer.io", "Lio/customer/sdk/", "PROFILING"),

    # ── Asia / regional ─────────────────────────────────────────────────
    TrackerSpec("Yandex AppMetrica", "Lcom/yandex/metrica/impl/", "ANALYTICS"),
    TrackerSpec("Mail.ru", "Lru/mail/", "ANALYTICS"),
    TrackerSpec("VK", "Lcom/vk/api/sdk/", "SOCIAL"),
    TrackerSpec("Baidu Push", "Lcom/baidu/android/pushservice/", "PUSH"),
    TrackerSpec("Baidu Mobstat", "Lcom/baidu/mobstat/", "ANALYTICS"),
    TrackerSpec("Xiaomi MiPush", "Lcom/xiaomi/mipush/", "PUSH"),
    TrackerSpec("Huawei HMS", "Lcom/huawei/hms/", "PUSH"),
    TrackerSpec("Huawei Push", "Lcom/huawei/agconnect/", "PUSH"),
    TrackerSpec("Tencent IM", "Lcom/tencent/imsdk/", "PUSH"),
    TrackerSpec("WeChat", "Lcom/tencent/mm/opensdk/", "SOCIAL"),
    TrackerSpec("Alibaba/Taobao OneTrack", "Lcom/alibaba/sdk/android/", "ANALYTICS"),
    TrackerSpec("JPush (Aurora)", "Lcn/jpush/android/", "PUSH"),
    TrackerSpec("Getui (Individual)", "Lcom/igexin/", "PUSH"),
    TrackerSpec("UMeng Push", "Lcom/umeng/message/", "PUSH"),
    TrackerSpec("Kuaishou", "Lcom/kwad/sdk/", "ADVERTISING"),

    # ── Misc ────────────────────────────────────────────────────────────
    TrackerSpec("Optimove", "Lcom/optimove/sdk/", "PROFILING"),
    TrackerSpec("Algolia Insights", "Lcom/algolia/instantsearch/insights/", "ANALYTICS"),
    TrackerSpec("Snowplow", "Lcom/snowplowanalytics/snowplow/tracker/", "ANALYTICS"),
    TrackerSpec("PostHog", "Lcom/posthog/android/", "ANALYTICS"),
    TrackerSpec("Smartech", "Lcom/netcore/android/", "PROFILING"),
    TrackerSpec("Pendo", "Lsdk/pendo/io/", "PROFILING"),
    TrackerSpec("WalkMe", "Lcom/walkme/", "PROFILING"),
    TrackerSpec("Gleap", "Lio/gleap/", "PROFILING"),
    TrackerSpec("Amplitude Experiment", "Lcom/amplitude/experiment/", "PROFILING"),
    TrackerSpec("Firebase Performance", "Lcom/google/firebase/perf/", "ANALYTICS"),
    TrackerSpec("Firebase RemoteConfig", "Lcom/google/firebase/remoteconfig/", "PROFILING"),
    TrackerSpec("Firebase MLKit", "Lcom/google/firebase/ml/", "PROFILING"),
    TrackerSpec("Firebase A/B Testing", "Lcom/google/firebase/abt/", "PROFILING"),
    TrackerSpec("Firebase Inappmessaging", "Lcom/google/firebase/inappmessaging/", "PROFILING"),
    TrackerSpec("Lottie Telemetry", "Lcom/airbnb/lottie/network/", "ANALYTICS"),
    TrackerSpec("Sift Science", "Lcom/sift/api/representations/", "IDENTIFIER"),
    TrackerSpec("Forter", "Lio/forter/mobile/", "IDENTIFIER"),
    TrackerSpec("Iovation", "Lcom/iovation/mobile/android/", "IDENTIFIER"),
    TrackerSpec("Threatmetrix", "Lcom/threatmetrix/", "IDENTIFIER"),
    TrackerSpec("BlueKai", "Lcom/bluekai/sdk/", "PROFILING"),
]


_CATEGORY_SEVERITY = {
    "ADVERTISING": (Severity.MEDIUM, 5.3),
    "IDENTIFIER":  (Severity.HIGH,   7.5),
    "LOCATION":    (Severity.HIGH,   7.5),
    "PROFILING":   (Severity.MEDIUM, 5.3),
    "ANALYTICS":   (Severity.LOW,    3.7),
    "CRASH":       (Severity.LOW,    3.1),
    "PUSH":        (Severity.LOW,    3.1),
    "SOCIAL":      (Severity.LOW,    3.7),
}


class TrackerDetector:
    """Detect Exodus-Privacy-style trackers by class prefix."""

    def analyse_classes(self, class_names: list[str]) -> list[Finding]:
        # Class-name lookup is O(N*T); pre-sort the trackers by descending
        # prefix length so longer/more-specific prefixes win the dedup race.
        specs = sorted(TRACKERS, key=lambda s: -len(s.prefix))
        seen: dict[str, TrackerSpec] = {}
        for cls in class_names:
            for spec in specs:
                if cls.startswith(spec.prefix):
                    seen.setdefault(spec.name, spec)
                    break

        findings: list[Finding] = []
        for spec in seen.values():
            sev, cvss = _CATEGORY_SEVERITY.get(
                spec.category, (Severity.LOW, 3.1),
            )
            findings.append(Finding(
                rule_id=f"TRACKER_{spec.category}_{_slug(spec.name)}",
                title=f"{spec.category.title()} tracker: {spec.name}",
                description=(
                    f"The APK bundles {spec.name}, classified by Exodus-Privacy "
                    f"as a {spec.category.lower()} tracker. Trackers exfiltrate "
                    "device identifiers, app usage, or location to third parties "
                    "without app-specific consent."
                ),
                severity=sev,
                confidence=Confidence.HIGH,
                category="PRIVACY",
                file_path="DEX classes",
                evidence=f"class prefix: {spec.prefix}",
                remediation=(
                    "Audit whether this tracker is required. If retained, "
                    "implement an explicit user consent flow before initialisation "
                    "and disclose it in the app's privacy policy."
                ),
                cwe_id="CWE-359",
                cvss=cvss,
            ))
        return findings


def _slug(s: str) -> str:
    out = []
    for ch in s.upper():
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "_", "-", "."):
            out.append("_")
    return "".join(out)[:40].strip("_")
