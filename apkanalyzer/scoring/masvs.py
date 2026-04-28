"""
OWASP MASVS (Mobile App Security Verification Standard) profile filter.

Profiles
--------
L1 — required baseline; covers cleartext, exported components, hardcoded
     secrets, debuggable, weak crypto algorithms, basic platform usage.
L2 — defence-in-depth on top of L1; adds anti-debugging, anti-tamper,
     sensitive-data-in-logs, advanced taint flows (PII → network/log/storage).
R  — resilience controls; adds obfuscation, root detection, emulator
     detection (these are typically opt-in only when L2 is also wanted).

A finding maps to a profile via a coarse rule-id classifier rather than a
hand-maintained per-rule table — categories shift, but the mapping is
stable enough that new rules in known categories inherit the right tier.

Matching strategy
-----------------
Rule IDs are matched using a hybrid scheme:
  1. Exact membership in a per-tier set, OR
  2. Prefix match against a per-tier prefix tuple.

The prefix list lets us catch families that grow over time (e.g. every
TAINT_<src>_TO_<sink> emitted by the taint engine, every STORAGE_EXTERNAL_*
variant from the storage detector) without having to re-list each new
sub-rule here.
"""

from __future__ import annotations

PROFILES = ("L1", "L2", "R")


# ── L1: required baseline ──────────────────────────────────────────────────
_L1_RULES = frozenset({
    # Manifest hygiene
    "MANIFEST_DEBUGGABLE",
    "MANIFEST_CLEARTEXT",
    "MANIFEST_NSC_MISSING",
    "MANIFEST_TARGET_SDK_LOW",
    "MANIFEST_TAPJACKING_RISK",
    "MANIFEST_CUSTOM_PERMISSION_NORMAL",
    "MANIFEST_PROVIDER_GRANT_URI",
    "DEEPLINK_UNPROTECTED",
    # Network
    "NETWORK_CLEARTEXT",
    "NETWORK_SSL_DISABLED",
    "NETWORK_TRUSTMANAGER_STUB",
    "NETWORK_OKHTTP_CUSTOM_VERIFIER",
    "NETWORK_OKHTTP_CERT_PINNER",
    "NETWORK_RETROFIT_VERIFY",
    "NETWORK_NSC_CLEARTEXT",
    "NETWORK_NSC_DOMAIN_CLEARTEXT",
    "NETWORK_NSC_USER_CA",
    "NETWORK_PINNING_MISSING",
    "NETWORK_PIN_EXPIRY",
    "NETWORK_WEAK_TLS",
    # Crypto
    "CRYPTO_WEAK_ALGORITHM",
    "CRYPTO_ECB_MODE",
    "CRYPTO_NO_PADDING",
    "CRYPTO_CONSTANT_KEY",
    "CRYPTO_WEAK_HASH",
    "CRYPTO_KEYSTORE_BYPASS",
    "CRYPTO_INSECURE_RANDOM",
    "CRYPTO_STATIC_IV",
    "CRYPTO_SMALL_KEY",
    # Storage
    "STORAGE_WORLD_READABLE",
    "STORAGE_BACKUP_ENABLED",
    # WebView
    "WEBVIEW_JS_ENABLED",
    "WEBVIEW_FILE_ACCESS",
    "WEBVIEW_JS_INTERFACE",
    "WEBVIEW_MIXED_CONTENT",
    "WEBVIEW_REMOTE_DEBUG",
    "WEBVIEW_UNSAFE_LOAD",
    # Intent hygiene
    "INTENT_PENDING_MUTABLE",
    "INTENT_GET_PARCELABLE_UNCHECKED",
    "INTENT_REDIRECTION",
    "INTENT_STICKY_BROADCAST",
})

# Prefix families that always belong in L1.
_L1_PREFIXES = (
    "MANIFEST_EXPORTED_",   # MANIFEST_EXPORTED_ACTIVITY/SERVICE/BROADCASTRECEIVER/PROVIDER
    "STORAGE_EXTERNAL_",    # STORAGE_EXTERNAL_PUBLIC, STORAGE_EXTERNAL_ISOLATED
    "STORAGE_PREFS_",
    "STORAGE_SQLITE_",
    "SECRET_",              # All hardcoded-secret rule IDs (AWS, Stripe, JWT, …)
    "DEEPLINK_",            # Deep-link hijack family
    "NATIVE_",              # ELF security flag findings (PIE/NX/RELRO/canary/symbols)
)


# ── L2: adds defence-in-depth ──────────────────────────────────────────────
_L2_ADD_RULES = frozenset({
    "PRIVACY_PII_IN_LOG",
    "PRIVACY_LOCATION_BACKGROUND",
    "PRIVACY_NETWORK_STATE_COMBINED",
    "PRIVACY_ADVERTISING_ID",
    "PRIVACY_CONSENT_MISSING",
    "LOG_SENSITIVE_LITERAL",
    "LOG_VERBOSE_DEBUG",
    "LOG_SYSTEM_OUT",
    "LOG_PRINT_STACKTRACE",
    "ANTIANALYSIS_ROOT_CHECK",
    "ANTIANALYSIS_EMULATOR_CHECK",
    "ANTIANALYSIS_FRIDA_DETECT",
    "ANTIANALYSIS_HOOK_DETECT",
    "ANTIANALYSIS_DEBUGGER_CHECK",
})

_L2_ADD_PREFIXES = (
    "TAINT_",   # All inter-procedural taint flows (TAINT_<SRC>_TO_<SINK>)
    "PII_",     # Legacy / generic PII rule IDs
)


# ── R: resilience controls ────────────────────────────────────────────────
_R_ADD_RULES = frozenset({
    "ANTIANALYSIS_PROC_CHECK",
    "ANTIANALYSIS_PORT_SCAN",
    "ANTIANALYSIS_PACKAGE_TAMPER",
    "ANTIANALYSIS_INTEGRITY_API",
})

_R_ADD_PREFIXES = (
    "OBFUSC_",  # OBFUSC_REFLECTION_*, OBFUSC_DYNAMIC_DEX, OBFUSC_DYNAMIC_PROXY, OBFUSC_LOAD_LIBRARY
)


def _matches(rule_id: str, exact: frozenset, prefixes: tuple) -> bool:
    if rule_id in exact:
        return True
    return any(rule_id.startswith(p) for p in prefixes)


def _rule_in_profile(rule_id: str, profile: str) -> bool:
    if profile == "L1":
        return _matches(rule_id, _L1_RULES, _L1_PREFIXES)
    if profile == "L2":
        return (
            _matches(rule_id, _L1_RULES, _L1_PREFIXES)
            or _matches(rule_id, _L2_ADD_RULES, _L2_ADD_PREFIXES)
        )
    if profile == "R":
        return (
            _matches(rule_id, _L1_RULES, _L1_PREFIXES)
            or _matches(rule_id, _L2_ADD_RULES, _L2_ADD_PREFIXES)
            or _matches(rule_id, _R_ADD_RULES, _R_ADD_PREFIXES)
        )
    # Unknown profile: pass-through (don't accidentally drop everything)
    return True


def filter_by_profile(findings: list, profile: str | None) -> list:
    """
    Return only the findings that belong to the requested MASVS profile.
    `findings` is a list of Finding objects (with .rule_id) or dicts.
    """
    if not profile:
        return findings
    profile = profile.upper()
    if profile not in PROFILES:
        return findings
    out = []
    for f in findings:
        rid = getattr(f, "rule_id", None) if not isinstance(f, dict) else f.get("rule_id")
        if rid is None:
            continue
        if _rule_in_profile(rid, profile):
            out.append(f)
    return out
