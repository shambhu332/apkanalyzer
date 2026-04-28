"""Entropy utilities re-exported for convenience."""

from apkanalyzer.analysis.detectors.secret_detector import (
    shannon_entropy,
    _BASE64_CHARS as BASE64_CHARS,
    _HEX_CHARS as HEX_CHARS,
)

__all__ = ["shannon_entropy", "BASE64_CHARS", "HEX_CHARS"]
