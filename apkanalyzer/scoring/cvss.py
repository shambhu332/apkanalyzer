"""
CVSS 3.1 vector string generator.

Produces CVSS 3.1 base metric vectors for findings based on their rule_id,
severity, category, and sink/source labels.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

from apkanalyzer.ir.models import Severity


# AV: Attack Vector  — N(etwork)|A(djacent)|L(ocal)|P(hysical)
# AC: Attack Complexity — L(ow)|H(igh)
# PR: Privileges Required — N(one)|L(ow)|H(igh)
# UI: User Interaction — N(one)|R(equired)
# S:  Scope — U(nchanged)|C(hanged)
# C/I/A: Confidentiality/Integrity/Availability Impact — N|L|H


def _vector(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N") -> str:
    return (
        f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}"
        f"/S:{s}/C:{c}/I:{i}/A:{a}"
    )


# Precomputed vectors for common finding types
_RULE_VECTORS: dict[str, str] = {
    # ── Secrets ────────────────────────────────────────────────────────
    "SECRET_AWS_KEY":              _vector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "SECRET_AWS_SECRET":           _vector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "SECRET_GOOGLE_API_KEY":       _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "SECRET_PRIVATE_KEY_HEADER":   _vector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "SECRET_JWT":                  _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "SECRET_FIREBASE_KEY":         _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "SECRET_STRIPE_KEY":           _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "SECRET_SLACK_TOKEN":          _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "SECRET_GITHUB_PAT":           _vector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="L"),
    "SECRET_DB_CONN_STRING":       _vector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    "SECRET_GENERIC_API_KEY":      _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="L", a="N"),

    # ── Crypto ─────────────────────────────────────────────────────────
    "CRYPTO_ECB_MODE":             _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "CRYPTO_WEAK_ALGORITHM":       _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "CRYPTO_WEAK_HASH":            _vector(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="H", a="N"),
    "CRYPTO_CONSTANT_KEY":         _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "CRYPTO_INSECURE_RANDOM":      _vector(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="L", a="N"),
    "CRYPTO_STATIC_IV":            _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "CRYPTO_NO_PADDING":           _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "CRYPTO_SMALL_KEY":            _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "CRYPTO_KEYSTORE_BYPASS":      _vector(av="L", ac="H", pr="L", ui="N", s="U", c="H", i="N", a="N"),

    # ── Network ────────────────────────────────────────────────────────
    "NETWORK_CLEARTEXT":           _vector(av="A", ac="H", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "NETWORK_SSL_DISABLED":        _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "NETWORK_TRUSTMANAGER_STUB":   _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "NETWORK_WEAK_TLS":            _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "NETWORK_NSC_CLEARTEXT":       _vector(av="A", ac="H", pr="N", ui="N", s="U", c="H", i="L", a="N"),
    "NETWORK_NSC_DOMAIN_CLEARTEXT":_vector(av="A", ac="H", pr="N", ui="R", s="U", c="H", i="L", a="N"),
    "NETWORK_NSC_USER_CA":         _vector(av="L", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "NETWORK_PINNING_MISSING":     _vector(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="L", a="N"),
    "NETWORK_PIN_EXPIRY":          _vector(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "NETWORK_OKHTTP_CUSTOM_VERIFIER": _vector(av="N", ac="H", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "NETWORK_OKHTTP_CERT_PINNER":  _vector(av="N", ac="H", pr="N", ui="N", s="U", c="N", i="N", a="N"),
    "NETWORK_RETROFIT_VERIFY":     _vector(av="N", ac="H", pr="N", ui="N", s="U", c="L", i="N", a="N"),

    # ── Storage ────────────────────────────────────────────────────────
    "STORAGE_WORLD_READABLE":      _vector(av="L", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),
    "STORAGE_PREFS_PLAINTEXT":     _vector(av="L", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),
    "STORAGE_SQLITE_PLAINTEXT":    _vector(av="L", ac="L", pr="L", ui="N", s="U", c="L", i="N", a="N"),
    "STORAGE_EXTERNAL_PUBLIC":     _vector(av="L", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "STORAGE_EXTERNAL_ISOLATED":   _vector(av="L", ac="H", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    "STORAGE_BACKUP_ENABLED":      _vector(av="P", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),

    # ── Manifest ───────────────────────────────────────────────────────
    "MANIFEST_DEBUGGABLE":         _vector(av="P", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"),
    "MANIFEST_CLEARTEXT":          _vector(av="A", ac="H", pr="N", ui="N", s="U", c="H", i="L", a="N"),

    # ── Deep link / web link vulnerabilities ───────────────────────────
    "DEEPLINK_UNPROTECTED":        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    "DEEPLINK_HTTP_SCHEME":        _vector(av="A", ac="H", pr="N", ui="R", s="U", c="H", i="L", a="N"),
    "DEEPLINK_NO_AUTO_VERIFY":     _vector(av="N", ac="L", pr="N", ui="R", s="U", c="N", i="H", a="N"),
    "DEEPLINK_WILDCARD_HOST":      _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    "DEEPLINK_NO_PATH_CONSTRAINT": _vector(av="N", ac="H", pr="N", ui="R", s="U", c="L", i="L", a="N"),
    "DEEPLINK_OAUTH_HIJACK":       _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N"),
    "DEEPLINK_MIXED_SCHEMES":      _vector(av="N", ac="H", pr="N", ui="R", s="U", c="L", i="L", a="N"),
    "DEEPLINK_FRAGMENT_INJECTION": _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "DEEPLINK_JS_BRIDGE_ABUSE":    _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "DEEPLINK_SCHEME_DOWNGRADE":   _vector(av="A", ac="H", pr="N", ui="R", s="U", c="L", i="L", a="N"),

    # ── WebView ────────────────────────────────────────────────────────
    "WEBVIEW_JS_INTERFACE":        _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="H"),
    "WEBVIEW_FILE_ACCESS":         _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="N", a="N"),
    "WEBVIEW_REMOTE_DEBUG":        _vector(av="P", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "WEBVIEW_UNSAFE_LOAD":         _vector(av="A", ac="H", pr="N", ui="R", s="U", c="H", i="L", a="N"),
    "WEBVIEW_MIXED_CONTENT":       _vector(av="A", ac="H", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    "WEBVIEW_JS_ENABLED":          _vector(av="N", ac="H", pr="N", ui="R", s="U", c="L", i="L", a="N"),

    # ── Obfuscation ────────────────────────────────────────────────────
    "OBFUSC_DYNAMIC_DEX":          _vector(av="N", ac="H", pr="N", ui="N", s="C", c="H", i="H", a="L"),
    "OBFUSC_REFLECTION_INVOKE":    _vector(av="N", ac="H", pr="L", ui="N", s="U", c="L", i="L", a="N"),
    "OBFUSC_REFLECTION_CLASS":     _vector(av="N", ac="H", pr="L", ui="N", s="U", c="L", i="N", a="N"),
    "OBFUSC_LOAD_LIBRARY":         _vector(av="L", ac="H", pr="L", ui="N", s="U", c="L", i="L", a="N"),
    "OBFUSC_DYNAMIC_PROXY":        _vector(av="N", ac="H", pr="L", ui="N", s="U", c="N", i="L", a="N"),
}

# Taint source→sink vector overrides (most specific flows)
_TAINT_VECTORS: dict[tuple[str, str], str] = {
    # Privacy leaks
    ("DEVICE_ID",     "NETWORK_OUT"):       _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    ("LOCATION",      "NETWORK_OUT"):       _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    ("ACCOUNT",       "NETWORK_OUT"):       _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    ("CONTACT",       "NETWORK_OUT"):       _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    ("CLIPBOARD",     "NETWORK_OUT"):       _vector(av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"),
    # Code execution
    ("USER_INPUT",    "EXEC"):              _vector(av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"),
    ("INTENT",        "EXEC"):              _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="H"),
    ("DEEP_LINK_DATA","EXEC"):              _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="H"),
    # WebView injection
    ("INTENT",        "WEBVIEW"):           _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    ("USER_INPUT",    "WEBVIEW"):           _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    ("DEEP_LINK_DATA","WEBVIEW"):           _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="N"),
    ("DEEP_LINK_DATA","WEBVIEW_JS_INJECT"): _vector(av="N", ac="L", pr="N", ui="R", s="C", c="H", i="H", a="H"),
    # SQL injection
    ("INTENT",        "SQL_INJECT"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N"),
    ("USER_INPUT",    "SQL_INJECT"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N"),
    ("DEEP_LINK_DATA","SQL_INJECT"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N"),
    ("CONTENT_URI",   "SQL_INJECT"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="H", a="N"),
    # Open redirect
    ("DEEP_LINK_DATA","OPEN_REDIRECT"):     _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    ("DEEP_LINK_DATA","DEEPLINK_REDIRECT"): _vector(av="N", ac="L", pr="N", ui="R", s="U", c="N", i="H", a="N"),
    ("CONTENT_URI",   "OPEN_REDIRECT"):     _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    ("INTENT",        "OPEN_REDIRECT"):     _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    # Network leaks from deep link data
    ("DEEP_LINK_DATA","NETWORK_OUT"):       _vector(av="N", ac="L", pr="N", ui="R", s="U", c="H", i="N", a="N"),
    # File path traversal
    ("INTENT",        "FILE_WRITE"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    ("USER_INPUT",    "FILE_WRITE"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    ("DEEP_LINK_DATA","FILE_WRITE"):        _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    # Pending intent hijacking
    ("INTENT",        "PENDING_INTENT"):    _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    ("USER_INPUT",    "PENDING_INTENT"):    _vector(av="N", ac="L", pr="N", ui="R", s="U", c="L", i="H", a="N"),
    # Log exfiltration
    ("DEVICE_ID",     "LOG"):               _vector(av="L", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),
    ("ACCOUNT",       "LOG"):               _vector(av="L", ac="L", pr="L", ui="N", s="U", c="H", i="N", a="N"),
    ("LOCATION",      "LOG"):               _vector(av="L", ac="L", pr="L", ui="N", s="U", c="L", i="N", a="N"),
}

# Severity-based fallback vectors
_SEVERITY_FALLBACKS = {
    "CRITICAL": _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="N"),
    "HIGH":     _vector(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="N", a="N"),
    "MEDIUM":   _vector(av="L", ac="L", pr="L", ui="N", s="U", c="L", i="L", a="N"),
    "LOW":      _vector(av="L", ac="H", pr="L", ui="R", s="U", c="L", i="N", a="N"),
    "INFO":     _vector(av="L", ac="H", pr="H", ui="R", s="U", c="N", i="N", a="N"),
}


def assign_vector(rule_id: str, severity: Severity,
                  taint_source: str = "", taint_sink: str = "") -> str:
    """Return a CVSS 3.1 vector string for a finding."""
    if taint_source and taint_sink:
        key = (taint_source, taint_sink)
        if key in _TAINT_VECTORS:
            return _TAINT_VECTORS[key]

    # Exact rule match
    if rule_id in _RULE_VECTORS:
        return _RULE_VECTORS[rule_id]

    # Prefix match (longest prefix wins)
    best_match = ""
    best_vec = ""
    for prefix, vec in _RULE_VECTORS.items():
        if rule_id.startswith(prefix.rstrip("_")) and len(prefix) > len(best_match):
            best_match = prefix
            best_vec = vec
    if best_vec:
        return best_vec

    return _SEVERITY_FALLBACKS.get(severity.value, _SEVERITY_FALLBACKS["MEDIUM"])
