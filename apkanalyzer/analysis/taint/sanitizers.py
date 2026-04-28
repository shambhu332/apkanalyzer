"""
Taint sanitizer definitions.

A sanitizer is a method call that transforms tainted data in a way that
neutralizes (or reduces the severity of) a specific sink type.

When a tainted value passes through a sanitizer before reaching a sink,
the finding confidence is downgraded from HIGH → MEDIUM instead of
being emitted at full confidence.

Sanitizer categories
--------------------
HTML_ESCAPE    — neutralizes XSS sinks (WEBVIEW, LOG)
URL_ENCODE     — reduces injection risk in URL sinks
SQL_ESCAPE     — reduces SQL injection risk in STORAGE sinks
CRYPTO_HASH    — irreversible transformation (one-way, non-reversible)
BASE64_ENCODE  — encoding (NOT encryption — still decodable by attacker)
ENCRYPT        — strong encryption (reduces STORAGE/NETWORK risk)
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class SanitizerSpec:
    class_pattern: str
    method_pattern: str
    label: str            # sanitizer category
    neutralizes: set[str] = None  # which sink labels this sanitizer neutralizes

    def __post_init__(self):
        if self.neutralizes is None:
            object.__setattr__(self, "neutralizes", set())


DEFAULT_SANITIZERS: list[SanitizerSpec] = [
    # ── HTML / XSS sanitizers ─────────────────────────────────────────
    SanitizerSpec(
        "Landroid/text/Html;", "escapeHtml",
        "HTML_ESCAPE", neutralizes={"WEBVIEW", "LOG"},
    ),
    SanitizerSpec(
        "Lorg/apache/commons/lang/StringEscapeUtils;", "escapeHtml",
        "HTML_ESCAPE", neutralizes={"WEBVIEW", "LOG"},
    ),
    SanitizerSpec(
        "Lorg/apache/commons/text/StringEscapeUtils;", "escapeHtml4",
        "HTML_ESCAPE", neutralizes={"WEBVIEW", "LOG"},
    ),

    # ── URL encoders ──────────────────────────────────────────────────
    SanitizerSpec(
        "Ljava/net/URLEncoder;", "encode",
        "URL_ENCODE", neutralizes={"NETWORK_OUT", "WEBVIEW"},
    ),
    SanitizerSpec(
        "Landroid/net/Uri;", "encode",
        "URL_ENCODE", neutralizes={"NETWORK_OUT", "WEBVIEW"},
    ),

    # ── SQL parameterization ──────────────────────────────────────────
    # Using query() with selection args (parameterized) rather than rawQuery is safe
    SanitizerSpec(
        "Landroid/database/sqlite/SQLiteDatabase;", "query",
        "SQL_ESCAPE", neutralizes={"STORAGE", "SQL_INJECT"},
    ),

    # ── Cryptographic hashing (one-way, reduces value of the data) ────
    SanitizerSpec(
        "Ljava/security/MessageDigest;", "digest",
        "CRYPTO_HASH", neutralizes={"NETWORK_OUT", "STORAGE", "LOG"},
    ),
    SanitizerSpec(
        "Lcom/google/common/hash/Hashing;", "*",
        "CRYPTO_HASH", neutralizes={"NETWORK_OUT", "STORAGE", "LOG"},
    ),

    # ── Base64 (encoding only — NOT a security sanitizer, downgrade only) ─
    SanitizerSpec(
        "Landroid/util/Base64;", "encode",
        "BASE64_ENCODE", neutralizes=set(),  # doesn't neutralize, just flags
    ),
    SanitizerSpec(
        "Ljava/util/Base64;", "encode",
        "BASE64_ENCODE", neutralizes=set(),
    ),

    # ── Strong encryption ─────────────────────────────────────────────
    SanitizerSpec(
        "Ljavax/crypto/Cipher;", "doFinal",
        "ENCRYPT", neutralizes={"STORAGE", "NETWORK_OUT", "LOG"},
    ),

    # Bouncy Castle Cipher.doFinal — same shape as the JCA Cipher above
    SanitizerSpec(
        "Lorg/bouncycastle/crypto/BufferedBlockCipher;", "doFinal",
        "ENCRYPT", neutralizes={"STORAGE", "NETWORK_OUT", "LOG"},
    ),

    # ── HTML escapers (Jsoup, AndroidX HtmlCompat, Kotlin) ────────────
    SanitizerSpec(
        "Landroidx/core/text/HtmlCompat;", "fromHtml",
        "HTML_ESCAPE", neutralizes={"WEBVIEW"},  # parses, doesn't escape — keep narrow
    ),
    SanitizerSpec(
        "Lorg/jsoup/parser/Parser;", "unescapeEntities",
        "HTML_ESCAPE", neutralizes=set(),  # decoder, not encoder — informational only
    ),
    SanitizerSpec(
        "Lorg/owasp/html/PolicyFactory;", "sanitize",
        "HTML_ESCAPE", neutralizes={"WEBVIEW", "LOG"},
    ),

    # ── Kotlin URL encode helpers ─────────────────────────────────────
    SanitizerSpec(
        "Lio/ktor/http/CodecsKt;", "encodeURLPath",
        "URL_ENCODE", neutralizes={"NETWORK_OUT"},
    ),
    SanitizerSpec(
        "Lio/ktor/http/CodecsKt;", "encodeURLQueryComponent",
        "URL_ENCODE", neutralizes={"NETWORK_OUT"},
    ),

    # ── Bouncy Castle digests ─────────────────────────────────────────
    SanitizerSpec(
        "Lorg/bouncycastle/crypto/digests/SHA256Digest;", "doFinal",
        "CRYPTO_HASH", neutralizes={"NETWORK_OUT", "STORAGE", "LOG"},
    ),

    # ── Parameterised SQL via SupportSQLiteDatabase (Room) ────────────
    SanitizerSpec(
        "Landroidx/sqlite/db/SupportSQLiteDatabase;", "query",
        "SQL_ESCAPE", neutralizes={"SQL_INJECT", "STORAGE"},
    ),

    # ── Path normalisation (path traversal) ───────────────────────────
    # File.getCanonicalPath() resolves "../" before being passed to a
    # FILE_WRITE sink — defenders typically pair it with a whitelist
    # check, so we only neutralise FILE_WRITE.
    SanitizerSpec(
        "Ljava/io/File;", "getCanonicalPath",
        "PATH_NORMALIZE", neutralizes={"FILE_WRITE"},
    ),
    SanitizerSpec(
        "Ljava/io/File;", "getCanonicalFile",
        "PATH_NORMALIZE", neutralizes={"FILE_WRITE"},
    ),
]


def build_sanitizer_index(
    extra: list[SanitizerSpec] | None = None,
) -> dict[str, list[SanitizerSpec]]:
    all_san = list(DEFAULT_SANITIZERS)
    if extra:
        all_san.extend(extra)
    index: dict[str, list[SanitizerSpec]] = {}
    for spec in all_san:
        index.setdefault(spec.class_pattern, []).append(spec)
    return index
