"""
Confidence scoring and finding post-processing.

This module is the final gate before a finding is emitted.  It:
  1. Applies per-category confidence adjustment rules
  2. Suppresses findings that fall below the minimum confidence threshold
  3. Adds CVSS base scores where missing
  4. Marks findings from known-safe patterns as false positives
"""

from __future__ import annotations

import re
from apkanalyzer.ir.models import Finding, Confidence, Severity

# Classes whose presence strongly suggests this is library/test code.
# Only flag library class when the host class is the library, not when the
# host class is app code that *calls* a library.
_LIBRARY_CLASS_PATTERNS = [
    re.compile(r'^Lcom/google/(?!android/gms/ads)'),  # exclude ad SDK
    re.compile(r'^Lcom/facebook/'),
    re.compile(r'^Lcom/squareup/'),
    re.compile(r'^Lokhttp3/'),
    re.compile(r'^Lretrofit2/'),
    re.compile(r'^Lio/reactivex[23]?/'),
    re.compile(r'^Lorg/apache/'),
    re.compile(r'^Lcom/amazonaws/'),
    re.compile(r'^Lkotlinx?/'),
    re.compile(r'^Lcom/bumptech/glide/'),
    re.compile(r'^Lcom/github/'),
    re.compile(r'^Lcom/airbnb/'),
    re.compile(r'^Lcom/jakewharton/'),
    re.compile(r'^Lio/github/'),
    re.compile(r'^Lorg/greenrobot/'),
    # Analytics / crash reporting SDKs (but flag HIGH findings — they handle data)
    re.compile(r'^Lcom/mixpanel/'),
    re.compile(r'^Lcom/amplitude/'),
    re.compile(r'^Lcom/segment/'),
    re.compile(r'^Lcom/bugsnag/'),
    re.compile(r'^Lio/sentry/'),
    re.compile(r'^Lcom/crashlytics/'),
    # Firebase (keep HIGH severity — storage/network findings still matter)
    re.compile(r'^Lcom/google/firebase/(?!database|firestore|storage)'),
    # DI
    re.compile(r'^Ldagger/'),
    re.compile(r'^Lhilt_aggregated_deps/'),
    # Test infrastructure
    re.compile(r'^Lorg/junit/'),
    re.compile(r'^Lorg/mockito/'),
    re.compile(r'^Landroidx/test/'),
]

# Patterns that indicate test/debug infrastructure
# Use end-of-segment matching to avoid "DebugInfo" matching as debug context
_TEST_CLASS_PATTERN = re.compile(
    r'(?:^|/)(?i:test|mock|stub|fake|espresso|robolectric|junit)[/$]'
)
_DEBUG_CLASS_PATTERN = re.compile(
    r'(?:^|/)(?i:debug)[/$;]'  # Only match when "Debug" is a full segment
)
_BUILDCONFIG_PATTERN = re.compile(r'BuildConfig(?:\$|;|$)')

# Findings that should NEVER be downgraded even in library/test context
# because their exploit path does not depend on context
_NEVER_DOWNGRADE_RULES = frozenset({
    "CRYPTO_CONSTANT_KEY",
    "SECRET_AWS_KEY",
    "SECRET_PRIVATE_KEY_HEADER",
    "NETWORK_SSL_DISABLED",
    "NETWORK_TRUSTMANAGER_STUB",
    "WEBVIEW_JS_INTERFACE",
    "OBFUSC_DYNAMIC_DEX",
})

# Findings that are noisy enough that we always start them at LOW
# regardless of detector-assigned confidence
_NOISY_RULES = frozenset({
    "OBFUSC_REFLECTION_CLASS",
    "OBFUSC_DYNAMIC_PROXY",
    "ANTIANALYSIS_ROOT_CHECK",
    "ANTIANALYSIS_EMULATOR_CHECK",
    "NETWORK_RETROFIT_VERIFY",
    "CRYPTO_KEYSTORE_BYPASS",
})


def _is_library_class(class_name: str) -> bool:
    return any(p.search(class_name) for p in _LIBRARY_CLASS_PATTERNS)


def _is_test_context(class_name: str, method_name: str) -> bool:
    return (
        _TEST_CLASS_PATTERN.search(class_name) is not None
        or _TEST_CLASS_PATTERN.search(method_name) is not None
    )


def _is_debug_context(class_name: str, method_name: str) -> bool:
    return (
        _DEBUG_CLASS_PATTERN.search(class_name) is not None
        or _BUILDCONFIG_PATTERN.search(class_name) is not None
    )


def adjust_confidence(finding: Finding) -> Finding:
    """
    Mutate confidence based on context heuristics.
    Returns the (possibly adjusted) finding.
    """
    # Never-downgrade rules are immune to context adjustments
    if finding.rule_id in _NEVER_DOWNGRADE_RULES:
        return finding

    # Noisy rules: cap at MEDIUM regardless of what detector assigned
    if finding.rule_id in _NOISY_RULES:
        if finding.confidence == Confidence.HIGH:
            finding.confidence = Confidence.MEDIUM

    # Library code: still emit but lower confidence by one level
    if _is_library_class(finding.class_name or ""):
        # Exception: keep HIGH confidence for CRITICAL severity — lib bug is still a bug
        if finding.severity not in (Severity.CRITICAL,):
            if finding.confidence == Confidence.HIGH:
                finding.confidence = Confidence.MEDIUM
            elif finding.confidence == Confidence.MEDIUM:
                finding.confidence = Confidence.LOW

    # Test/debug code: these don't fire in production — downgrade
    if _is_test_context(finding.class_name or "", finding.method_name or ""):
        if finding.confidence == Confidence.HIGH:
            finding.confidence = Confidence.MEDIUM
        elif finding.confidence == Confidence.MEDIUM:
            finding.confidence = Confidence.LOW

    # Debug-named class segment: slight downgrade (BuildConfig.DEBUG guards)
    if _is_debug_context(finding.class_name or "", finding.method_name or ""):
        if finding.confidence == Confidence.HIGH:
            finding.confidence = Confidence.MEDIUM

    return finding


def filter_findings(
    findings: list[Finding],
    min_confidence: Confidence = Confidence.LOW,
    min_severity: Severity = Severity.INFO,
) -> list[Finding]:
    """
    Apply confidence adjustments and filter by thresholds.

    Parameters
    ----------
    findings       : raw findings from analysis modules
    min_confidence : drop findings below this confidence
    min_severity   : drop findings below this severity
    """
    confidence_rank = {
        Confidence.HIGH: 3,
        Confidence.MEDIUM: 2,
        Confidence.LOW: 1,
    }
    severity_rank = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }

    result = []
    for f in findings:
        f = adjust_confidence(f)
        if confidence_rank[f.confidence] < confidence_rank[min_confidence]:
            continue
        if severity_rank[f.severity] < severity_rank[min_severity]:
            continue
        result.append(f)

    # Stable, deterministic ordering — most severe / most confident first,
    # then by location. ThreadPool ordering would otherwise shuffle findings
    # between runs and produce noisy CI diffs.
    result.sort(key=lambda f: (
        -severity_rank[f.severity],
        -confidence_rank[f.confidence],
        f.rule_id,
        f.class_name,
        f.method_name,
        f.line_number,
        f.evidence,
    ))
    return result


def risk_grade(by_severity: dict) -> str:
    """
    Compute an overall app risk grade A–F from severity counts.

    F: any CRITICAL, or 3+ HIGH
    D: any HIGH, or 5+ MEDIUM
    C: 3+ MEDIUM
    B: any MEDIUM
    A: LOW/INFO only or clean
    """
    critical = by_severity.get("CRITICAL", 0)
    high = by_severity.get("HIGH", 0)
    medium = by_severity.get("MEDIUM", 0)

    if critical:
        return "F"
    if high >= 3:
        return "F"
    if high >= 1:
        return "D"
    if medium >= 5:
        return "D"
    if medium >= 3:
        return "C"
    if medium >= 1:
        return "B"
    return "A"


def summarise(findings: list[Finding]) -> dict:
    """Produce a summary count dict for report headers."""
    summary: dict = {
        "total": len(findings),
        "by_severity": {s.value: 0 for s in Severity},
        "by_confidence": {c.value: 0 for c in Confidence},
        "by_category": {},
    }
    for f in findings:
        summary["by_severity"][f.severity.value] += 1
        summary["by_confidence"][f.confidence.value] += 1
        summary["by_category"][f.category] = \
            summary["by_category"].get(f.category, 0) + 1
    summary["risk_grade"] = risk_grade(summary["by_severity"])
    summary["by_owasp"] = {}
    for f in findings:
        cat = getattr(f, "owasp_category", "")
        if cat:
            summary["by_owasp"][cat] = summary["by_owasp"].get(cat, 0) + 1
    return summary
