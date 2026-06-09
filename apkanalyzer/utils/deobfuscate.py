"""
String deobfuscation helpers.

What this is
------------
Best-effort static decoders for the small set of string-obfuscation patterns
that account for the vast majority of "encrypted" strings in real Android apps:

  * Base64 (with and without URL safety, with and without padding)
  * Hex
  * Single-byte XOR (1..255 keys, only one-of-a-kind ciphertexts)
  * Caesar / ROT-13 style fixed-shift permutations of ASCII
  * Java string.intern / new String(byte[]) / new String(byte[], charset)
  * Simple charset reverses (`new StringBuilder(s).reverse().toString()`)

The decoders are intentionally conservative — they only return a value when
the decoded result is overwhelmingly likely to be a "real" string (mostly
printable ASCII, no embedded NULs, plausible length). False positives in
this module pollute the reflection edge synthesiser with garbage class
names; false negatives only mean we keep treating the string as opaque,
which is the pre-existing behaviour. False negative is always preferred.

Public API
----------
    try_decode(seed: str, invoke_raw: str) -> Optional[str]
        Given a string constant and the raw `invoke-*` instruction line that
        consumes it (used to pick the right decoder by callee name), return
        a decoded string or None if no decoder applies.

    deobfuscate_strings(strings: Iterable[str]) -> dict[str, str]
        Bulk best-effort decode of an entire string pool. Yields
        original → decoded for every entry where a decoder produced a
        plausible result. Used by detectors that scan the static string
        pool (secret detection, rule engine).
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import string
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


# A decoded string is "plausible" if:
#  * it is at least 3 characters long,
#  * at least 80 % of its bytes are printable ASCII,
#  * it contains no embedded NULs.
# These thresholds are deliberately strict: detector-side false positives
# are far more expensive than missing one obfuscated string.
_PRINTABLE = set(string.printable) - {"\x0b", "\x0c"}


def _is_plausible(s: str) -> bool:
    if len(s) < 3 or len(s) > 4096:
        return False
    if "\x00" in s:
        return False
    printable = sum(1 for c in s if c in _PRINTABLE)
    return printable / max(1, len(s)) >= 0.80


# ---------------------------------------------------------------------------
# Individual decoders
# ---------------------------------------------------------------------------

_B64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


def _decode_base64(seed: str) -> Optional[str]:
    if len(seed) < 8 or len(seed) % 4 not in (0, 2, 3):
        return None
    if not _B64_RE.match(seed):
        return None
    try:
        # Try standard then URL-safe; tolerate missing padding.
        padding = "=" * ((4 - len(seed) % 4) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(seed + padding)
            except (binascii.Error, ValueError):
                continue
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    decoded = raw.decode("latin-1")
                except UnicodeDecodeError:
                    continue
            if _is_plausible(decoded):
                return decoded
    except Exception:
        return None
    return None


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def _decode_hex(seed: str) -> Optional[str]:
    if len(seed) < 6 or len(seed) % 2 != 0 or not _HEX_RE.match(seed):
        return None
    try:
        raw = bytes.fromhex(seed)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw.decode("latin-1", errors="replace")
        return decoded if _is_plausible(decoded) else None
    except ValueError:
        return None


def _decode_xor_single_byte(seed: str) -> Optional[str]:
    """
    Try every 1..255 single-byte XOR key. Returns the first decoded string
    that's plausible. Skipped for short seeds because random ASCII makes
    every key look equally noisy.
    """
    if len(seed) < 8:
        return None
    raw = seed.encode("latin-1", errors="replace")
    best: Optional[str] = None
    best_score = 0
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in raw).decode("latin-1", errors="replace")
        if not _is_plausible(decoded):
            continue
        # Prefer decodings rich in alphanumerics + slashes (class-name shapes).
        score = sum(1 for c in decoded if c.isalnum() or c in "./_")
        if score > best_score:
            best_score = score
            best = decoded
    return best


def _decode_rot(seed: str, shift: int) -> Optional[str]:
    decoded = []
    for c in seed:
        if "a" <= c <= "z":
            decoded.append(chr((ord(c) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            decoded.append(chr((ord(c) - ord("A") + shift) % 26 + ord("A")))
        else:
            decoded.append(c)
    out = "".join(decoded)
    return out if _is_plausible(out) else None


def _decode_reverse(seed: str) -> Optional[str]:
    out = seed[::-1]
    return out if _is_plausible(out) else None


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

def try_decode(seed: str, invoke_raw: str) -> Optional[str]:
    """
    Best-effort decode dispatched by the consumer's class/method name.

    Heuristics:
    * If invoke_raw looks like a Base64 / Hex helper, try those decoders first.
    * Otherwise try every applicable decoder; return the first plausible result.

    Returns None when no decoder produces a credible string.
    """
    if not seed:
        return None

    raw = invoke_raw or ""

    # Decoder ordering hints from the consumer's API name.
    hint = raw.lower()
    decoders: list = []
    if "base64" in hint:
        decoders.append(_decode_base64)
    if "hex" in hint or "tohex" in hint or "fromhex" in hint:
        decoders.append(_decode_hex)
    if "reverse" in hint:
        decoders.append(_decode_reverse)
    if "xor" in hint:
        decoders.append(_decode_xor_single_byte)
    if "rot" in hint or "caesar" in hint:
        decoders.extend([lambda s, k=k: _decode_rot(s, k) for k in (13, 1, 3, 5, 7)])

    # If no hint matched, try the full panel — but in a stable order so a
    # caller scanning many strings sees deterministic results.
    if not decoders:
        decoders = [
            _decode_base64,
            _decode_hex,
            _decode_reverse,
            lambda s: _decode_rot(s, 13),
        ]

    for fn in decoders:
        try:
            out = fn(seed)
        except Exception:
            continue
        if out and out != seed and _is_plausible(out):
            return out
    return None


def deobfuscate_strings(strings: Iterable[str]) -> dict[str, str]:
    """
    Bulk decoder: walks an iterable of strings and returns a dict mapping
    each obfuscated input to its plausible decoded form.

    Used by the secret scanner and rule engine to find embedded
    Base64/hex-encoded URLs, API keys, and class names that the literal
    DEX string pool would otherwise hide.
    """
    out: dict[str, str] = {}
    for s in strings:
        if not isinstance(s, str) or len(s) < 8 or len(s) > 4096:
            continue
        # We don't have an `invoke_raw` here — pass empty so try_decode
        # falls through to the panel of generic decoders.
        decoded = try_decode(s, "")
        if decoded is not None and decoded != s:
            out[s] = decoded
    return out
