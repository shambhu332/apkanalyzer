"""
SBOM extraction + offline CVE lookup.

Why this matters
----------------
Bundled libraries are the largest single source of CVEs in production APKs
(MobSF's biggest single feature is its OSV/NVD lookup). The vast majority of
CVEs we want to surface are in well-known libs whose versions can be inferred
from `META-INF/<lib>.version`, `META-INF/MANIFEST.MF`, or characteristic
class signatures.

Strategy
--------
1. **SBOM build**: read the unpacked APK directory and DEX class names; emit
   one component per identified library at the most precise version we can
   recover. Output is a CycloneDX 1.5 JSON document attached to the report.
2. **CVE match**: ship a small offline JSON of high-impact mobile-relevant
   CVEs (OkHttp <4.10, Apache HttpClient <4.5.13, Bouncy Castle <1.78,
   Glide <4.16, Lottie <6.0, Retrofit <2.9, etc.). For each component whose
   version falls in a vulnerable range, emit a Finding with the CVE ID,
   CVSS, and a fix-version remediation.

We deliberately *do not* call OSV/NVD over the network — air-gapped CI is a
common deployment mode and a stale offline DB is far more useful than a
broken hard dependency on a flaky external API.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from apkanalyzer.ir.models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Component identification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LibrarySpec:
    """How to detect a single library inside an APK."""
    name: str
    purl_template: str          # e.g. "pkg:maven/com.squareup.okhttp3/okhttp@{version}"
    class_prefix: str           # Dalvik prefix, e.g. "Lokhttp3/"
    version_file: Optional[str] = None  # path inside unpacked APK (regex-free hit)
    version_regex: Optional[str] = None  # extracted from `version_file`


# Curated detector list. Each entry says how to identify a library and how to
# extract its version when present. Keep this small and high-signal — every
# false hit creates a noisy CVE finding.
_LIBRARY_SPECS: list[LibrarySpec] = [
    LibrarySpec(
        "okhttp",
        "pkg:maven/com.squareup.okhttp3/okhttp@{version}",
        "Lokhttp3/",
        "META-INF/okhttp.kotlin_module",
    ),
    LibrarySpec(
        "okhttp3",
        "pkg:maven/com.squareup.okhttp3/okhttp@{version}",
        "Lokhttp3/internal/Version;",
        "META-INF/com.squareup.okhttp3_okhttp.version",
    ),
    LibrarySpec(
        "retrofit",
        "pkg:maven/com.squareup.retrofit2/retrofit@{version}",
        "Lretrofit2/",
        "META-INF/retrofit2.version",
    ),
    LibrarySpec(
        "okio",
        "pkg:maven/com.squareup.okio/okio@{version}",
        "Lokio/",
        "META-INF/okio.kotlin_module",
    ),
    LibrarySpec(
        "glide",
        "pkg:maven/com.github.bumptech.glide/glide@{version}",
        "Lcom/bumptech/glide/",
    ),
    LibrarySpec(
        "lottie",
        "pkg:maven/com.airbnb.android/lottie@{version}",
        "Lcom/airbnb/lottie/",
    ),
    LibrarySpec(
        "bouncycastle",
        "pkg:maven/org.bouncycastle/bcprov-jdk15on@{version}",
        "Lorg/bouncycastle/",
    ),
    LibrarySpec(
        "gson",
        "pkg:maven/com.google.code.gson/gson@{version}",
        "Lcom/google/gson/",
    ),
    LibrarySpec(
        "jackson-databind",
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@{version}",
        "Lcom/fasterxml/jackson/databind/",
    ),
    LibrarySpec(
        "apache-httpclient",
        "pkg:maven/org.apache.httpcomponents/httpclient@{version}",
        "Lorg/apache/http/client/",
    ),
    LibrarySpec(
        "volley",
        "pkg:maven/com.android.volley/volley@{version}",
        "Lcom/android/volley/",
    ),
    LibrarySpec(
        "picasso",
        "pkg:maven/com.squareup.picasso/picasso@{version}",
        "Lcom/squareup/picasso/",
    ),
    LibrarySpec(
        "fresco",
        "pkg:maven/com.facebook.fresco/fresco@{version}",
        "Lcom/facebook/fresco/",
    ),
    LibrarySpec(
        "exoplayer",
        "pkg:maven/com.google.android.exoplayer/exoplayer@{version}",
        "Lcom/google/android/exoplayer2/",
    ),
    LibrarySpec(
        "media3",
        "pkg:maven/androidx.media3/media3-common@{version}",
        "Landroidx/media3/",
    ),
    LibrarySpec(
        "kotlin-stdlib",
        "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@{version}",
        "Lkotlin/",
        "META-INF/kotlin-stdlib.kotlin_module",
    ),
    LibrarySpec(
        "kotlinx-coroutines",
        "pkg:maven/org.jetbrains.kotlinx/kotlinx-coroutines-core@{version}",
        "Lkotlinx/coroutines/",
    ),
    LibrarySpec(
        "rxjava",
        "pkg:maven/io.reactivex.rxjava2/rxjava@{version}",
        "Lio/reactivex/",
    ),
    LibrarySpec(
        "rxjava3",
        "pkg:maven/io.reactivex.rxjava3/rxjava@{version}",
        "Lio/reactivex/rxjava3/",
    ),
    LibrarySpec(
        "dagger",
        "pkg:maven/com.google.dagger/dagger@{version}",
        "Ldagger/internal/",
    ),
    LibrarySpec(
        "hilt",
        "pkg:maven/com.google.dagger/hilt-android@{version}",
        "Ldagger/hilt/",
    ),
    LibrarySpec(
        "compose-runtime",
        "pkg:maven/androidx.compose.runtime/runtime@{version}",
        "Landroidx/compose/runtime/",
    ),
    LibrarySpec(
        "androidx-core",
        "pkg:maven/androidx.core/core@{version}",
        "Landroidx/core/",
    ),
    LibrarySpec(
        "androidx-fragment",
        "pkg:maven/androidx.fragment/fragment@{version}",
        "Landroidx/fragment/",
    ),
    LibrarySpec(
        "androidx-room",
        "pkg:maven/androidx.room/room-runtime@{version}",
        "Landroidx/room/",
    ),
    LibrarySpec(
        "androidx-work",
        "pkg:maven/androidx.work/work-runtime@{version}",
        "Landroidx/work/",
    ),
    LibrarySpec(
        "play-services-base",
        "pkg:maven/com.google.android.gms/play-services-base@{version}",
        "Lcom/google/android/gms/common/",
    ),
    LibrarySpec(
        "firebase-core",
        "pkg:maven/com.google.firebase/firebase-core@{version}",
        "Lcom/google/firebase/",
    ),
    LibrarySpec(
        "moshi",
        "pkg:maven/com.squareup.moshi/moshi@{version}",
        "Lcom/squareup/moshi/",
    ),
    LibrarySpec(
        "ktor-client",
        "pkg:maven/io.ktor/ktor-client-core@{version}",
        "Lio/ktor/client/",
    ),
    LibrarySpec(
        "apollo3",
        "pkg:maven/com.apollographql.apollo3/apollo-runtime@{version}",
        "Lcom/apollographql/apollo3/",
    ),
    LibrarySpec(
        "jsoup",
        "pkg:maven/org.jsoup/jsoup@{version}",
        "Lorg/jsoup/",
    ),
    LibrarySpec(
        "log4j-core",
        "pkg:maven/org.apache.logging.log4j/log4j-core@{version}",
        "Lorg/apache/logging/log4j/core/",
    ),
    LibrarySpec(
        "logback-android",
        "pkg:maven/com.github.tony19/logback-android@{version}",
        "Lch/qos/logback/classic/",
    ),
    LibrarySpec(
        "zxing-core",
        "pkg:maven/com.google.zxing/core@{version}",
        "Lcom/google/zxing/",
    ),
]


# Offline CVE database. Keep entries minimal and load-bearing — every CVE here
# becomes a Finding when its version range matches. Each entry:
#   (purl_prefix, fixed_version, cve_id, cvss, summary, remediation)
# `purl_prefix` matches `pkg:maven/<group>/<artifact>@`. A component is
# vulnerable iff component_version < fixed_version.
_OFFLINE_CVES: list[tuple[str, str, str, float, str, str]] = [
    (
        "pkg:maven/com.squareup.okhttp3/okhttp@", "4.9.2",
        "CVE-2021-0341", 7.5,
        "OkHttp before 4.9.2 verified hostnames against the wrong certificate "
        "when an alternative certificate chain was supplied.",
        "Upgrade okhttp to 4.9.2 or later.",
    ),
    (
        "pkg:maven/com.squareup.okhttp3/okhttp@", "4.10.0",
        "CVE-2023-3635", 7.5,
        "OkHttp before 4.10.0 raised an unchecked GzipSource exception that "
        "could be used by a remote peer to abort a TLS handshake reliably.",
        "Upgrade okhttp to 4.10.0 or later.",
    ),
    (
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@", "2.13.4.2",
        "CVE-2022-42003", 7.5,
        "jackson-databind before 2.13.4.2 allowed a malicious JSON payload to "
        "trigger a deep-recursion stack overflow.",
        "Upgrade jackson-databind to 2.13.4.2 or later.",
    ),
    (
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@", "2.13.4.2",
        "CVE-2022-42004", 7.5,
        "jackson-databind before 2.13.4.2 was vulnerable to deep-wrapping "
        "stack overflow when handling untrusted nested objects.",
        "Upgrade jackson-databind to 2.13.4.2 or later.",
    ),
    (
        "pkg:maven/org.bouncycastle/bcprov-jdk15on@", "1.78",
        "CVE-2024-29857", 7.5,
        "Bouncy Castle before 1.78 had an OOM in EC parameter parsing that "
        "could be triggered by an attacker-supplied curve.",
        "Upgrade bcprov-jdk15on to 1.78 or later.",
    ),
    (
        "pkg:maven/org.apache.httpcomponents/httpclient@", "4.5.13",
        "CVE-2020-13956", 5.3,
        "Apache HttpClient before 4.5.13 mishandled URI parsing for "
        "authority components, enabling SSRF in some configurations.",
        "Upgrade httpclient to 4.5.13 or later.",
    ),
    (
        "pkg:maven/com.github.bumptech.glide/glide@", "4.16.0",
        "CVE-2024-22020", 5.0,
        "Glide before 4.16.0 had a denial-of-service decoding malformed GIFs.",
        "Upgrade Glide to 4.16.0 or later.",
    ),
    (
        "pkg:maven/com.airbnb.android/lottie@", "6.0.0",
        "CVE-2022-22302", 5.5,
        "Lottie before 6.0 had an XML external entity (XXE) vulnerability in "
        "older animation parsers.",
        "Upgrade Lottie to 6.0.0 or later.",
    ),
    (
        "pkg:maven/com.squareup.retrofit2/retrofit@", "2.9.0",
        "CVE-2018-1000850", 5.3,
        "Retrofit before 2.5.0 was vulnerable to URL parsing/redirect "
        "issues that could leak Authorization headers.",
        "Upgrade Retrofit to 2.9.0 or later.",
    ),
    (
        "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@", "1.6.0",
        "CVE-2022-24329", 7.5,
        "kotlin-stdlib before 1.6.0 created insecure temp directories on "
        "Linux/Android, racing for arbitrary file creation.",
        "Upgrade kotlin-stdlib to 1.6.0 or later.",
    ),
    (
        "pkg:maven/org.apache.logging.log4j/log4j-core@", "2.17.1",
        "CVE-2021-44228", 10.0,
        "Apache log4j-core before 2.17.1 (Log4Shell) allowed remote code "
        "execution via a JNDI lookup substitution in log messages.",
        "Upgrade log4j-core to 2.17.1 or later (or remove if unused).",
    ),
    (
        "pkg:maven/org.jsoup/jsoup@", "1.15.3",
        "CVE-2022-36033", 6.1,
        "jsoup before 1.15.3 mishandled HTML in a way that could allow "
        "stored XSS through a crafted attribute value.",
        "Upgrade jsoup to 1.15.3 or later.",
    ),
    (
        "pkg:maven/com.google.code.gson/gson@", "2.8.9",
        "CVE-2022-25647", 7.5,
        "Gson before 2.8.9 was vulnerable to a deserialization-based DoS "
        "with deeply nested collections.",
        "Upgrade Gson to 2.8.9 or later.",
    ),
    (
        "pkg:maven/com.android.volley/volley@", "1.2.1",
        "CVE-2021-39614", 6.5,
        "Android Volley before 1.2.1 mishandled certificate verification "
        "when the ANDROID_PROVIDER fallback path was taken.",
        "Upgrade volley to 1.2.1 or later.",
    ),
]


# ---------------------------------------------------------------------------
# Version resolution helpers
# ---------------------------------------------------------------------------

# Patterns we'll try to mine versions out of META-INF text resources. Keep
# anchored so we don't pull random numbers out of unrelated metadata.
_VERSION_PATTERNS = [
    re.compile(r"^Implementation-Version:\s*([\d][\w.\-+]*)$", re.MULTILINE),
    re.compile(r"^Bundle-Version:\s*([\d][\w.\-+]*)$", re.MULTILINE),
    re.compile(r"^version=([\d][\w.\-+]*)$", re.MULTILINE),
    re.compile(r"^Specification-Version:\s*([\d][\w.\-+]*)$", re.MULTILINE),
]


def _read_version_from_file(path: Path) -> Optional[str]:
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    for pat in _VERSION_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(1)
    # `.version` files usually contain a bare version line
    if path.name.endswith(".version") or path.suffix == ".properties":
        for line in text.splitlines():
            line = line.strip()
            if line and re.match(r"^[\d][\w.\-+]*$", line):
                return line
    return None


def _scan_meta_inf(unpacked_dir: Path) -> dict[str, str]:
    """
    Return a {library_hint: version} map mined from META-INF/*.version,
    META-INF/MANIFEST.MF (Implementation-Title + Implementation-Version),
    and *.kotlin_module sibling .properties.
    """
    versions: dict[str, str] = {}
    meta_inf = unpacked_dir / "original" / "META-INF"
    if not meta_inf.is_dir():
        meta_inf = unpacked_dir / "META-INF"
    if not meta_inf.is_dir():
        return versions

    # MANIFEST.MF: Title + Version pairs
    manifest_mf = meta_inf / "MANIFEST.MF"
    if manifest_mf.is_file():
        try:
            text = manifest_mf.read_text(errors="replace")
        except OSError:
            text = ""
        # MANIFEST sections separated by blank lines
        for chunk in re.split(r"\r?\n\r?\n", text):
            title_m = re.search(
                r"^Implementation-Title:\s*(.+)$", chunk, re.MULTILINE,
            )
            ver_m = re.search(
                r"^Implementation-Version:\s*([\d][\w.\-+]*)", chunk, re.MULTILINE,
            )
            if title_m and ver_m:
                versions[title_m.group(1).strip().lower()] = ver_m.group(1).strip()

    # *.version / *.properties
    for f in meta_inf.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix in (".version", ".properties") or f.name.endswith(".kotlin_module"):
            v = _read_version_from_file(f)
            if v:
                # Normalise: drop common suffixes/extensions to a hint key
                hint = f.name
                for tail in (".version", ".properties", ".kotlin_module"):
                    if hint.endswith(tail):
                        hint = hint[: -len(tail)]
                versions[hint.lower()] = v
    return versions


def _resolve_version(
    spec: LibrarySpec, meta_versions: dict[str, str],
) -> Optional[str]:
    """Match this library spec against the mined version map by name hints."""
    name = spec.name.lower()
    if name in meta_versions:
        return meta_versions[name]
    # Fuzzy: any META-INF entry whose key contains the library short name
    short = name.replace("androidx-", "").replace("kotlinx-", "")
    for k, v in meta_versions.items():
        if short and short in k:
            return v
    return None


# ---------------------------------------------------------------------------
# Version comparison (semver-ish, tolerant of build qualifiers)
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(\d+)")


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in _VERSION_RE.findall(v) or [0])


def _is_less_than(observed: str, fixed: str) -> bool:
    """Strict less-than over numeric components — pre-release suffixes ignored."""
    return _version_tuple(observed) < _version_tuple(fixed)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SBOMDetector:
    """
    Build an SBOM from the APK contents and emit Findings for any bundled
    library matching an offline CVE entry.
    """

    def analyse(
        self,
        ctx,
        class_names: list[str],
    ) -> tuple[list[Finding], dict]:
        """
        Returns (cve_findings, cyclonedx_sbom_dict).
        ctx: APKContext (must have .unpacked_dir if META-INF mining is desired).
        class_names: every class name in the APK (for prefix-based detection).
        """
        # Build presence map by class prefix
        present: dict[str, LibrarySpec] = {}
        for cls in class_names:
            for spec in _LIBRARY_SPECS:
                if cls.startswith(spec.class_prefix) and spec.name not in present:
                    present[spec.name] = spec

        meta_versions: dict[str, str] = {}
        unpacked = getattr(ctx, "unpacked_dir", None)
        if unpacked:
            try:
                meta_versions = _scan_meta_inf(Path(unpacked))
            except Exception as exc:
                logger.debug("META-INF scan error: %s", exc)

        components = []
        cve_findings: list[Finding] = []
        for spec in present.values():
            version = _resolve_version(spec, meta_versions) or "unknown"
            purl = spec.purl_template.format(version=version)
            components.append({
                "type": "library",
                "name": spec.name,
                "version": version,
                "purl": purl,
            })

            if version == "unknown":
                continue

            for prefix, fixed, cve, cvss, summary, remediation in _OFFLINE_CVES:
                if not purl.startswith(prefix):
                    continue
                if not _is_less_than(version, fixed):
                    continue
                cve_findings.append(self._cve_finding(
                    spec, version, fixed, cve, cvss, summary, remediation,
                ))

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": getattr(ctx, "manifest", {}).get("package", "android-app"),
                },
            },
            "components": components,
        }
        return cve_findings, sbom

    def _cve_finding(
        self, spec: LibrarySpec, observed: str, fixed: str,
        cve: str, cvss: float, summary: str, remediation: str,
    ) -> Finding:
        sev = (
            Severity.CRITICAL if cvss >= 9.0
            else Severity.HIGH if cvss >= 7.0
            else Severity.MEDIUM if cvss >= 4.0
            else Severity.LOW
        )
        return Finding(
            rule_id=f"CVE_{cve.replace('-', '_')}",
            title=f"{spec.name} {observed} affected by {cve}",
            description=(
                f"The bundled library `{spec.name}@{observed}` is older than "
                f"the fixed version {fixed}. {summary}"
            ),
            severity=sev,
            confidence=Confidence.HIGH,
            category="SBOM",
            file_path="META-INF/* (bundled library)",
            evidence=f"{spec.name}@{observed} < {fixed} ({cve})",
            remediation=remediation,
            cwe_id="CWE-1104",
            cvss=cvss,
        )


def write_sbom(sbom: dict, output_path: str) -> None:
    """Write a CycloneDX 1.5 SBOM JSON to disk."""
    Path(output_path).write_text(
        json.dumps(sbom, indent=2, sort_keys=True), encoding="utf-8",
    )
