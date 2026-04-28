"""
Deep link and web link vulnerability detector.

Covers manifest-level misconfigurations and bytecode patterns:
  - HTTP (non-HTTPS) deep link schemes              DEEPLINK_HTTP_SCHEME
  - App Link without autoVerify                     DEEPLINK_NO_AUTO_VERIFY
  - Wildcard / missing host in deep link            DEEPLINK_WILDCARD_HOST
  - No path constraint (full URI space exposed)     DEEPLINK_NO_PATH_CONSTRAINT
  - OAuth / auth callback scheme hijack             DEEPLINK_OAUTH_HIJACK
  - Mixed custom + http/https schemes               DEEPLINK_MIXED_SCHEMES
  - Fragment injection via PreferenceActivity       DEEPLINK_FRAGMENT_INJECTION
  - JavaScript injection via deep link URL          DEEPLINK_JS_BRIDGE_ABUSE
  - Open redirect through Intent construction       DEEPLINK_INTENT_OPEN_REDIRECT
  - URL scheme stripping / downgrade                DEEPLINK_SCHEME_DOWNGRADE
"""

from __future__ import annotations

import re
from apkanalyzer.ir.models import Finding, Severity, Confidence
from apkanalyzer.ir.cfg_builder import get_all_instructions

_OAUTH_KEYWORDS = frozenset(
    ["oauth", "auth", "callback", "redirect", "login", "sso", "token", "authorize"]
)

_FRAGMENT_EXTRAS = frozenset([
    ":android:show_fragment",
    ":android:no_headers",
    ":android:show_fragment_arguments",
    ":android:starting_fragment_token",
])

_JS_BRIDGE_METHODS = frozenset([
    "addJavascriptInterface",
    "evaluateJavascript",
])


def _comp_schemes(comp: dict) -> set[str]:
    return {dl["scheme"] for dl in comp.get("deep_links", [])}


class DeeplinkDetector:
    """Comprehensive deep link and web link vulnerability detector."""

    # ------------------------------------------------------------------ #
    # Manifest-level checks
    # ------------------------------------------------------------------ #

    def analyse_manifest(self, manifest: dict) -> list[Finding]:
        findings: list[Finding] = []
        all_lists = [
            (manifest.get("exported_activities", []), "Activity"),
            (manifest.get("exported_services", []), "Service"),
            (manifest.get("exported_receivers", []), "BroadcastReceiver"),
        ]

        for comp_list, label in all_lists:
            for comp in comp_list:
                comp_name = comp["name"]
                deep_links = comp.get("deep_links", [])
                schemes = _comp_schemes(comp)

                # --- mixed schemes (custom + http/https on same component) ---
                has_web = bool({"http", "https"} & schemes)
                has_custom = bool(schemes - {"http", "https"})
                if has_web and has_custom:
                    findings.append(Finding(
                        rule_id="DEEPLINK_MIXED_SCHEMES",
                        title=f"Mixed custom and HTTP(S) schemes on {label}",
                        description=(
                            f"{comp_name} registers both a custom URI scheme "
                            f"({', '.join(sorted(schemes - {'http','https'}))}) and "
                            "http/https. An attacker can trigger the http/https handler "
                            "by crafting a universal link while also exploiting the "
                            "custom-scheme handler that lacks verification."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="DEEPLINK",
                        file_path="AndroidManifest.xml",
                        evidence=f"schemes: {sorted(schemes)} on {comp_name}",
                        remediation=(
                            "Separate http/https App Links from custom scheme handlers "
                            "into distinct components. Ensure each uses appropriate "
                            "verification (autoVerify for App Links, permission for custom)."
                        ),
                        cwe_id="CWE-939",
                        cvss=5.4,
                    ))

                for dl in deep_links:
                    scheme = dl["scheme"]
                    host = dl["host"]
                    uri = dl["uri"]

                    # --- HTTP (non-HTTPS) deep link ---
                    if scheme == "http":
                        findings.append(Finding(
                            rule_id="DEEPLINK_HTTP_SCHEME",
                            title=f"Deep link uses insecure HTTP scheme: {uri}",
                            description=(
                                f"{comp_name} registers an http:// deep link. "
                                "HTTP deep links can be intercepted via MITM attacks, "
                                "allowing an attacker to serve a malicious redirect URI "
                                "or capture sensitive parameters passed in the URL."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="DEEPLINK",
                            file_path="AndroidManifest.xml",
                            evidence=f"<data android:scheme=\"http\" android:host=\"{host}\">",
                            remediation=(
                                "Replace http:// with https:// and enable "
                                "android:autoVerify=\"true\" with a valid "
                                ".well-known/assetlinks.json on the domain."
                            ),
                            cwe_id="CWE-319",
                            cvss=7.4,
                        ))

                    # --- http/https App Link without autoVerify ---
                    if scheme in ("http", "https") and not dl.get("auto_verify"):
                        findings.append(Finding(
                            rule_id="DEEPLINK_NO_AUTO_VERIFY",
                            title=f"App Link without autoVerify: {uri}",
                            description=(
                                f"{comp_name} registers an {scheme}:// intent-filter "
                                "without android:autoVerify=\"true\". Without verification, "
                                "any installed application can register itself as a handler "
                                "for the same URL, intercepting deep link traffic "
                                "(link hijacking / confused deputy)."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="DEEPLINK",
                            file_path="AndroidManifest.xml",
                            evidence=(
                                f"<intent-filter> (no autoVerify) with "
                                f"<data scheme=\"{scheme}\" host=\"{host}\">"
                            ),
                            remediation=(
                                "Add android:autoVerify=\"true\" to the intent-filter "
                                "and publish a valid Digital Asset Links file at "
                                f"https://{host or 'yourdomain.com'}/.well-known/assetlinks.json"
                            ),
                            cwe_id="CWE-940",
                            cvss=6.5,
                        ))

                    # --- Wildcard / empty host ---
                    if not host or host in ("*", ".*", ""):
                        findings.append(Finding(
                            rule_id="DEEPLINK_WILDCARD_HOST",
                            title=f"Deep link with wildcard/missing host: {uri}",
                            description=(
                                f"{comp_name} registers a deep link with no host "
                                "restriction. Any host matches, meaning a malicious app "
                                "or website can craft a URI with a malicious host to "
                                "trigger this component, enabling open redirect and "
                                "parameter injection."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="DEEPLINK",
                            file_path="AndroidManifest.xml",
                            evidence=f"<data android:scheme=\"{scheme}\"> (no host attribute)",
                            remediation=(
                                "Always specify android:host with a specific domain. "
                                "Avoid wildcard hosts. Use android:pathPattern to "
                                "further restrict matching URIs."
                            ),
                            cwe_id="CWE-20",
                            cvss=7.1,
                        ))

                    # --- No path constraint ---
                    if host and not dl.get("has_path_constraint"):
                        # Only flag if host is specific (wildcard already flagged above)
                        if host not in ("*", ""):
                            findings.append(Finding(
                                rule_id="DEEPLINK_NO_PATH_CONSTRAINT",
                                title=f"Deep link has no path restriction: {uri}",
                                description=(
                                    f"{comp_name} matches any path under "
                                    f"{scheme}://{host}/. Without a pathPattern or "
                                    "pathPrefix, the entire URI space under this host "
                                    "is routed into the app, expanding the attack surface "
                                    "for parameter injection and open redirect."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                category="DEEPLINK",
                                file_path="AndroidManifest.xml",
                                evidence=f"<data scheme=\"{scheme}\" host=\"{host}\"> (no path/pathPrefix/pathPattern)",
                                remediation=(
                                    "Add android:pathPrefix or android:pathPattern to "
                                    "restrict which paths trigger this component."
                                ),
                                cwe_id="CWE-183",
                                cvss=4.3,
                            ))

                    # --- OAuth / auth callback hijack ---
                    scheme_lower = scheme.lower()
                    host_lower = (host or "").lower()
                    uri_lower = uri.lower()
                    if any(kw in scheme_lower or kw in host_lower for kw in _OAUTH_KEYWORDS):
                        findings.append(Finding(
                            rule_id="DEEPLINK_OAUTH_HIJACK",
                            title=f"OAuth/auth callback URI susceptible to hijacking: {uri}",
                            description=(
                                f"{comp_name} registers a URI scheme that appears to be "
                                "an OAuth or authentication callback "
                                f"({uri}). Custom URI scheme OAuth callbacks can be "
                                "intercepted by any app that registers the same scheme. "
                                "An attacker can steal authorization codes and tokens."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.MEDIUM,
                            category="DEEPLINK",
                            file_path="AndroidManifest.xml",
                            evidence=f"callback URI: {uri} on {comp_name}",
                            remediation=(
                                "Use App Links (https:// with autoVerify) instead of "
                                "custom URI schemes for OAuth callbacks (RFC 8252 §7.2). "
                                "Validate the `state` parameter and use PKCE."
                            ),
                            cwe_id="CWE-601",
                            cvss=8.1,
                        ))

        return findings

    # ------------------------------------------------------------------ #
    # Bytecode-level checks
    # ------------------------------------------------------------------ #

    def analyse_method(
        self,
        cfg,
        desc,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple] = set()

        if cfg is None:
            return findings

        for instr in get_all_instructions(cfg):
            mnemonic = instr.get("mnemonic", "")
            raw = instr.get("raw", "") or ""
            operands = instr.get("operands", []) or []

            # Operand values (decoded strings, register names, etc.)
            op_values = [
                op.get("value") if isinstance(op, dict) else op
                for op in operands
            ]

            # --- Fragment injection (deprecated PreferenceActivity) ---
            if mnemonic.startswith("const-string"):
                for val in op_values:
                    if isinstance(val, str) and val in _FRAGMENT_EXTRAS:
                        key = ("DEEPLINK_FRAGMENT_INJECTION", desc.class_name)
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                rule_id="DEEPLINK_FRAGMENT_INJECTION",
                                title="Fragment injection via deep link extra",
                                description=(
                                    "The class references the "
                                    f"'{val}' Intent extra, associated with the "
                                    "deprecated PreferenceActivity fragment injection "
                                    "vulnerability. An attacker can supply an arbitrary "
                                    "fragment class name via deep link to load unintended "
                                    "fragments with elevated context."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                category="DEEPLINK",
                                class_name=desc.class_name,
                                method_name=desc.method_name,
                                evidence=f"const-string \"{val}\"",
                                remediation=(
                                    "Override isValidFragment() to return false, or "
                                    "migrate from PreferenceActivity to "
                                    "PreferenceFragmentCompat. Never load fragment class "
                                    "names from Intent extras without allowlisting."
                                ),
                                cwe_id="CWE-470",
                                cvss=8.1,
                            ))

            # --- JavaScript bridge abuse via deep link ---
            if mnemonic.startswith("invoke") and any(m in raw for m in _JS_BRIDGE_METHODS):
                key = ("DEEPLINK_JS_BRIDGE_ABUSE", desc.class_name, desc.method_name)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        rule_id="DEEPLINK_JS_BRIDGE_ABUSE",
                        title="JavaScript bridge registered in WebView",
                        description=(
                            "A JavaScript interface or evaluateJavascript call is "
                            "present in a method that may handle deep link data. "
                            "If the WebView URL is controlled by a deep link parameter, "
                            "an attacker can execute arbitrary JavaScript in the app's "
                            "WebView context, potentially accessing the Java bridge."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="DEEPLINK",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"invoke: {raw[:160]}",
                        remediation=(
                            "Validate all URLs loaded into WebView against an "
                            "allowlist of trusted domains before loading. "
                            "Remove addJavascriptInterface from components that "
                            "handle deep link data, or enforce strict origin checks."
                        ),
                        cwe_id="CWE-749",
                        cvss=8.8,
                    ))

            # --- Scheme downgrade (https → http via string manipulation) ---
            if mnemonic.startswith("const-string"):
                for val in op_values:
                    if not isinstance(val, str):
                        continue
                    if val.lower().startswith("http://") and re.search(r'https?://', val, re.I):
                        key = ("DEEPLINK_SCHEME_DOWNGRADE", val[:60])
                        if key not in seen:
                            seen.add(key)
                            findings.append(Finding(
                                rule_id="DEEPLINK_SCHEME_DOWNGRADE",
                                title="Hardcoded HTTP URL in deep link handler",
                                description=(
                                    "A hardcoded http:// URL is used in bytecode "
                                    "within this method. If this URL is used as a "
                                    "redirect target or base URL for deep link "
                                    "handling, it is vulnerable to MITM attacks."
                                ),
                                severity=Severity.MEDIUM,
                                confidence=Confidence.LOW,
                                category="DEEPLINK",
                                class_name=desc.class_name,
                                method_name=desc.method_name,
                                evidence=f"const-string \"{val[:80]}\"",
                                remediation=(
                                    "Replace http:// redirect targets with https://. "
                                    "Never use hardcoded URLs for deep link redirects; "
                                    "use server-side configuration."
                                ),
                                cwe_id="CWE-319",
                                cvss=4.8,
                            ))

        return findings
