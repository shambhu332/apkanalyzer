"""
OWASP Mobile Top 10 2024 mapping.

Assigns each finding a category from M1–M10 based on its rule_id and category.
Reference: https://owasp.org/www-project-mobile-top-10/
"""

from __future__ import annotations

import re

# ── OWASP Mobile Top 10 2024 ─────────────────────────────────────────────────
OWASP_CATEGORIES = {
    "M1":  "M1: Improper Credential Usage",
    "M2":  "M2: Inadequate Supply Chain Security",
    "M3":  "M3: Insecure Authentication/Authorization",
    "M4":  "M4: Insufficient Input/Output Validation",
    "M5":  "M5: Insecure Communication",
    "M6":  "M6: Inadequate Privacy Controls",
    "M7":  "M7: Insufficient Binary Protections",
    "M8":  "M8: Security Misconfiguration",
    "M9":  "M9: Insecure Data Storage",
    "M10": "M10: Insufficient Cryptography",
}

# Exact rule_id → OWASP code  (checked first, most specific)
_EXACT_MAP: dict[str, str] = {
    # M1 — Credentials
    "CRYPTO_CONSTANT_KEY":               "M1",

    # M2 — Supply chain
    "OBFUSC_DYNAMIC_DEX":                "M2",
    "OBFUSC_LOAD_LIBRARY":               "M2",

    # M3 — Auth/Authz
    "DEEPLINK_UNPROTECTED":              "M3",
    "DEEPLINK_OAUTH_HIJACK":             "M3",
    "DEEPLINK_NO_AUTO_VERIFY":           "M3",
    "DEEPLINK_FRAGMENT_INJECTION":       "M3",
    "WEBVIEW_JS_INTERFACE":              "M3",

    # M4 — Input validation
    "DEEPLINK_JS_BRIDGE_ABUSE":          "M4",
    "DEEPLINK_SCHEME_DOWNGRADE":         "M4",
    "DEEPLINK_WILDCARD_HOST":            "M4",
    "DEEPLINK_NO_PATH_CONSTRAINT":       "M4",
    "WEBVIEW_MIXED_CONTENT":             "M4",

    # M5 — Communication
    "MANIFEST_CLEARTEXT":                "M5",
    "DEEPLINK_HTTP_SCHEME":              "M5",
    "NETWORK_SSL_DISABLED":              "M5",
    "NETWORK_TRUSTMANAGER_STUB":         "M5",
    "NETWORK_WEAK_TLS":                  "M5",
    "NETWORK_CLEARTEXT":                 "M5",
    "NETWORK_NSC_CLEARTEXT":             "M5",
    "NETWORK_NSC_DOMAIN_CLEARTEXT":      "M5",
    "NETWORK_NSC_USER_CA":               "M5",
    "NETWORK_PINNING_MISSING":           "M5",
    "NETWORK_PIN_EXPIRY":                "M5",
    "NETWORK_OKHTTP_CUSTOM_VERIFIER":    "M5",
    "NETWORK_OKHTTP_CERT_PINNER":        "M5",
    "NETWORK_RETROFIT_VERIFY":           "M5",

    # M7 — Binary protections
    "MANIFEST_DEBUGGABLE":               "M7",
    "WEBVIEW_REMOTE_DEBUG":              "M7",
    "OBFUSC_REFLECTION_CLASS":           "M7",
    "OBFUSC_REFLECTION_INVOKE":          "M7",
    "OBFUSC_DYNAMIC_PROXY":              "M7",

    # M8 — Misconfiguration
    "STORAGE_BACKUP_ENABLED":            "M8",
    "STORAGE_WORLD_READABLE":            "M8",
    "DEEPLINK_MIXED_SCHEMES":            "M8",

    # M9 — Data storage
    "STORAGE_PREFS_PLAINTEXT":           "M9",
    "STORAGE_SQLITE_PLAINTEXT":          "M9",
    "STORAGE_EXTERNAL_PUBLIC":           "M9",
    "STORAGE_EXTERNAL_ISOLATED":         "M9",

    # M10 — Cryptography
    "CRYPTO_ECB_MODE":                   "M10",
    "CRYPTO_WEAK_ALGORITHM":             "M10",
    "CRYPTO_WEAK_HASH":                  "M10",
    "CRYPTO_INSECURE_RANDOM":            "M10",
    "CRYPTO_STATIC_IV":                  "M10",
    "CRYPTO_NO_PADDING":                 "M10",
    "CRYPTO_SMALL_KEY":                  "M10",
    "CRYPTO_KEYSTORE_BYPASS":            "M10",
}

# Prefix rules (longest prefix wins — ordered longest-first below)
_PREFIX_MAP: list[tuple[str, str]] = [
    # M1
    ("SECRET_",                          "M1"),
    # M2
    ("SDK_",                             "M2"),
    # M4 — taint flows involving input validation
    ("TAINT_USER_INPUT_TO_EXEC",         "M4"),
    ("TAINT_USER_INPUT_TO_WEBVIEW",      "M4"),
    ("TAINT_USER_INPUT_TO_SQL",          "M4"),
    ("TAINT_INTENT_TO_EXEC",             "M4"),
    ("TAINT_INTENT_TO_WEBVIEW",          "M4"),
    ("TAINT_CONTENT_URI_TO_SQL",         "M4"),
    ("TAINT_DEEP_LINK_DATA_TO_WEBVIEW",  "M4"),
    ("TAINT_DEEP_LINK_DATA_TO_SQL",      "M4"),
    ("TAINT_DEEP_LINK_DATA_TO_EXEC",     "M4"),
    # M5 — communication taint
    ("TAINT_DEVICE_ID_TO_NETWORK",       "M5"),
    ("TAINT_LOCATION_TO_NETWORK",        "M5"),
    ("TAINT_ACCOUNT_TO_NETWORK",         "M5"),
    ("TAINT_DEEP_LINK_DATA_TO_NETWORK",  "M5"),
    ("TAINT_DEEP_LINK_DATA_TO_OPEN",     "M5"),
    ("TAINT_CONTENT_URI_TO_OPEN",        "M5"),
    ("TAINT_INTENT_TO_OPEN",             "M5"),
    ("NETWORK_",                         "M5"),
    # M6 — privacy
    ("TAINT_CONTACT_TO_",                "M6"),
    ("TAINT_LOCATION_TO_",               "M6"),
    ("TAINT_DEVICE_ID_TO_",              "M6"),
    ("TAINT_ACCOUNT_TO_",                "M6"),
    ("TAINT_CLIPBOARD_TO_",              "M6"),
    ("PRIVACY_",                         "M6"),
    # M7 — binary protections
    ("OBFUSC_",                          "M7"),
    ("ANTIANALYSIS_",                    "M7"),
    # M8 — misconfiguration
    ("MANIFEST_EXPORTED_",               "M8"),
    ("MANIFEST_",                        "M8"),
    ("DEEPLINK_",                        "M8"),
    ("STORAGE_EXTERNAL",                 "M8"),
    # M9 — data storage
    ("STORAGE_",                         "M9"),
    ("TAINT_USER_INPUT_TO_STORAGE",      "M9"),
    ("TAINT_INTENT_TO_STORAGE",          "M9"),
    # M10
    ("CRYPTO_",                          "M10"),
]

# Category fallback
_CATEGORY_MAP: dict[str, str] = {
    "CRYPTO":       "M10",
    "NETWORK":      "M5",
    "STORAGE":      "M9",
    "SECRETS":      "M1",
    "TAINT":        "M6",  # generic taint — privacy catch-all
    "MANIFEST":     "M8",
    "WEBVIEW":      "M4",
    "OBFUSCATION":  "M7",
    "PRIVACY":      "M6",
    "SDK":          "M2",
    "DEEPLINK":     "M8",
    "ANTIANALYSIS": "M7",
}


def _taint_sink_to_owasp(rule_id: str) -> str | None:
    """
    Infer OWASP category from taint rule_id by examining the sink component.

    Taint rule IDs follow TAINT_{SOURCE}_TO_{SINK} or TAINT_{SOURCE}_{SINK_CATEGORY}.
    """
    upper = rule_id.upper()
    if "EXEC" in upper or "COMMAND" in upper:
        return "M4"
    if "WEBVIEW" in upper or "JS_INJECT" in upper:
        return "M4"
    if "SQL" in upper or "SQL_INJECT" in upper:
        return "M4"
    if "OPEN_REDIRECT" in upper or "DEEPLINK_REDIRECT" in upper:
        return "M5"
    if "NETWORK_OUT" in upper or "NETWORK" in upper:
        return "M5"
    if "STORAGE" in upper or "FILE_WRITE" in upper or "PREFS" in upper:
        return "M9"
    if "PENDING_INTENT" in upper:
        return "M8"
    if "LOG" in upper:
        return "M6"
    return None


def assign_owasp(rule_id: str, category: str) -> str:
    """Return the OWASP Mobile Top 10 2024 full category string for a finding."""
    # 1. Exact match
    code = _EXACT_MAP.get(rule_id)
    if code:
        return OWASP_CATEGORIES[code]

    # 2. Prefix match (longest-first order guaranteed by list)
    for prefix, code in _PREFIX_MAP:
        if rule_id.startswith(prefix):
            return OWASP_CATEGORIES[code]

    # 3. Smart taint sink inference
    if rule_id.startswith("TAINT_"):
        sink_code = _taint_sink_to_owasp(rule_id)
        if sink_code:
            return OWASP_CATEGORIES[sink_code]

    # 4. Category fallback
    code = _CATEGORY_MAP.get(category, "")
    return OWASP_CATEGORIES.get(code, "")


def owasp_coverage(findings: list) -> dict[str, int]:
    """
    Count findings per OWASP category.
    findings should be Finding objects (with .owasp_category attribute).
    """
    counts: dict[str, int] = {v: 0 for v in OWASP_CATEGORIES.values()}
    for f in findings:
        cat = getattr(f, "owasp_category", "")
        if cat in counts:
            counts[cat] += 1
    return {k: v for k, v in counts.items() if v > 0}
