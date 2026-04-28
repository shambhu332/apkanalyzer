"""
Resource scanner — `res/values*/`, `res/raw/`, `assets/`.

Why this exists
---------------
The DEX string pool catches secrets/URLs baked into compiled code, and the
SecretDetector walks decompiled `.smali` for the same patterns. Neither of
those reaches Android *resources*, where developers actually park:

  • API base URLs in `res/values/strings.xml`
  • Firebase / OAuth client IDs in `res/values/strings.xml` (because the
    Google services Gradle plugin generates them there)
  • Webview HTML/JS in `assets/` that can hardcode tokens or load over http
  • Bundled JSON configs in `res/raw/` with environment-specific endpoints

apktool already unpacks these to `ctx.unpacked_dir` for us. We just walk
the tree, hand the contents to SecretDetector for the secret/key checks,
and emit a small set of resource-specific findings (cleartext URL in
strings.xml, http:// scheme in webview HTML, etc.).

Findings
--------
RES_CLEARTEXT_URL_IN_STRINGS    — http:// URL in res/values*/*.xml
RES_HARDCODED_API_KEY_IN_RES    — secret pattern hit in any resource file
RES_WEBVIEW_HTML_HTTP           — assets/*.html or assets/*.js loads http:// resource
RES_RAW_PRIVATE_KEY             — PEM/PKCS8 private key shipped in res/raw or assets
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from apkanalyzer.analysis.detectors.secret_detector import SecretDetector
from apkanalyzer.ir.models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

# Files we'll touch. Anything outside this list gets ignored — keeps the
# scan bounded on apps that ship hundreds of MB of asset blobs (games,
# offline-map apps).
_TEXT_SUFFIXES = {".xml", ".json", ".txt", ".properties", ".html", ".htm",
                  ".js", ".css", ".yaml", ".yml", ".ini", ".conf", ".cfg",
                  ".pem", ".key", ".crt", ".env"}

_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB per file — bigger files almost never hold secrets
_MAX_FILES = 2000                  # hard cap on files scanned

_HTTP_URL_RE = re.compile(r'http://[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%-]+')
_PRIVATE_KEY_RE = re.compile(
    r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----'
)
# Localhost / RFC1918 / link-local we treat as informational rather than
# real cleartext-URL findings — devs intentionally point to dev hosts here.
_LOCALHOST_RE = re.compile(
    r'http://(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|localhost|0\.0\.0\.0)',
    re.IGNORECASE,
)


class ResourceScanner:

    def __init__(self) -> None:
        self._secret = SecretDetector()

    def scan(self, unpacked_dir: str | None) -> list[Finding]:
        if not unpacked_dir:
            return []
        root = Path(unpacked_dir)
        if not root.is_dir():
            return []

        findings: list[Finding] = []
        for kind, sub in (("values", "res"), ("raw", "res/raw"), ("assets", "assets")):
            base = root / sub
            if not base.exists():
                continue
            findings.extend(self._scan_tree(base, root, kind))
            if len(findings) > 5000:
                logger.warning("ResourceScanner truncating after 5000 findings")
                break

        # Dedup — secret patterns can fire identically across locale variants
        # of strings.xml (values-en, values-fr…). Keep the first seen.
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.evidence or "", f.file_path or "")
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _scan_tree(self, base: Path, root: Path, kind: str) -> list[Finding]:
        findings: list[Finding] = []
        scanned = 0
        for path in self._iter_files(base):
            if scanned >= _MAX_FILES:
                break
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                content = path.read_text(errors="replace")
            except OSError:
                continue
            scanned += 1
            rel = str(path.relative_to(root))

            # Strings.xml gets structured parsing so we can attribute findings
            # to a specific @string name; everything else is byte-grep.
            if kind == "values" and path.name.startswith("strings") and path.suffix == ".xml":
                findings.extend(self._scan_strings_xml(content, rel))
            else:
                findings.extend(self._scan_text_blob(content, rel, kind))

            # Universal: any secret pattern hit in any resource is worth flagging
            for f in self._secret.scan_file(content, rel):
                # Re-tag rule_id so resource-bucket findings don't collide
                # with smali-bucket SECRET_* findings of the same pattern.
                f.rule_id = f"RES_{f.rule_id}"
                findings.append(f)
        return findings

    def _iter_files(self, base: Path) -> Iterable[Path]:
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            yield path

    def _scan_strings_xml(self, content: str, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            tree = ET.fromstring(content)
        except ET.ParseError:
            return findings
        for el in tree.iter():
            if el.tag != "string":
                continue
            name = el.attrib.get("name", "?")
            value = (el.text or "").strip()
            if not value:
                continue

            for m in _HTTP_URL_RE.finditer(value):
                url = m.group(0)
                if _LOCALHOST_RE.match(url):
                    continue
                findings.append(Finding(
                    rule_id="RES_CLEARTEXT_URL_IN_STRINGS",
                    title=f"Cleartext http:// URL in @string/{name}",
                    description=(
                        "A non-localhost http:// URL is hardcoded in a resource string. "
                        "If the app references this @string for a network call, traffic "
                        "is sent unencrypted unless usesCleartextTraffic=false in the manifest "
                        "*and* the call goes through a stack that honours that flag."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="NETWORK",
                    file_path=rel,
                    evidence=f'<string name="{name}">{url}</string>',
                    remediation=(
                        "Switch to https://. If the host is on an internal network, set "
                        "android:usesCleartextTraffic=false at the manifest level and "
                        "scope per-domain exemptions in network_security_config.xml."
                    ),
                    cwe_id="CWE-319",
                    cvss=7.4,
                ))

            if _PRIVATE_KEY_RE.search(value):
                findings.append(self._key_leak(rel, f'@string/{name}'))

        return findings

    def _scan_text_blob(self, content: str, rel: str, kind: str) -> list[Finding]:
        findings: list[Finding] = []

        # Webview-scheme http:// in HTML/JS we load locally
        if rel.endswith((".html", ".htm", ".js")):
            for m in _HTTP_URL_RE.finditer(content):
                url = m.group(0)
                if _LOCALHOST_RE.match(url):
                    continue
                findings.append(Finding(
                    rule_id="RES_WEBVIEW_HTML_HTTP",
                    title=f"http:// resource referenced from local {Path(rel).suffix} asset",
                    description=(
                        "Local webview content references a non-TLS resource. When loaded "
                        "into a WebView with mixed-content allowed (the Android default "
                        "before API 26), this enables a network attacker to inject script "
                        "into the webview context."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="WEBVIEW",
                    file_path=rel,
                    evidence=url[:200],
                    remediation=(
                        "Replace with https://, and call WebSettings.setMixedContentMode("
                        "MIXED_CONTENT_NEVER_ALLOW) on the WebView."
                    ),
                    cwe_id="CWE-319",
                    cvss=5.9,
                ))
                if len(findings) > 50:
                    break  # one HTML/JS file shouldn't dominate the report

        if _PRIVATE_KEY_RE.search(content):
            findings.append(self._key_leak(rel, "<file>"))

        return findings

    @staticmethod
    def _key_leak(rel: str, evidence: str) -> Finding:
        return Finding(
            rule_id="RES_RAW_PRIVATE_KEY",
            title=f"Private key shipped in resources: {rel}",
            description=(
                "A PEM/PKCS8 private key block is bundled inside the APK. Anyone who "
                "downloads the APK can extract it. Private keys must live on the server, "
                "not in the client artifact."
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="SECRETS",
            file_path=rel,
            evidence=evidence,
            remediation=(
                "Remove the key from the build artifact. If a client signing key is "
                "genuinely needed, derive it on-device or fetch it after authentication."
            ),
            cwe_id="CWE-798",
            cvss=9.1,
        )
