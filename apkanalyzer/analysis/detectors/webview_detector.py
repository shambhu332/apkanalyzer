"""
WebView security detector.

Checks
------
WEBVIEW_JS_ENABLED          — setJavaScriptEnabled(true) without addJavascriptInterface guard
WEBVIEW_JS_INTERFACE        — addJavascriptInterface — exposes Java objects to JS (RCE risk)
WEBVIEW_FILE_ACCESS         — setAllowFileAccess(true) or setAllowUniversalAccessFromFileURLs
WEBVIEW_UNSAFE_LOAD         — loadUrl() with external, non-https URL
WEBVIEW_REMOTE_DEBUG        — WebView.setWebContentsDebuggingEnabled(true) in release
WEBVIEW_MIXED_CONTENT       — setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)
WEBVIEW_CONTENT_ACCESS      — setAllowContentAccess(true) combined with JS
"""

from __future__ import annotations

import logging
import re

from apkanalyzer.ir.models import (
    CFGMethod,
    MethodDescriptor,
    Finding,
    Severity,
    Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions

logger = logging.getLogger(__name__)

# MIXED_CONTENT_ALWAYS_ALLOW = 0; MIXED_CONTENT_NEVER_ALLOW = 1;
# MIXED_CONTENT_COMPATIBILITY_MODE = 2
_MIXED_CONTENT_ALWAYS_ALLOW = 0


class WebViewDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instructions = get_all_instructions(cfg)

        # Boolean register tracking: reg_name -> bool value (True=1, False=0)
        bool_regs: dict[str, bool] = {}
        # Integer register tracking for setMixedContentMode
        int_regs: dict[str, int] = {}

        js_enabled = False
        has_js_interface = False
        has_content_access = False

        for instr in instructions:
            raw = instr.get("raw", "")
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)
            operands = instr.get("operands", [])

            # Track const registers so we can resolve boolean/int arguments
            if mnemonic in ("const/4", "const/16", "const", "const/high16"):
                if len(operands) >= 2:
                    reg = str(operands[0].get("value", ""))
                    val = operands[1].get("value", None)
                    if val is not None:
                        bool_regs[reg] = bool(val)
                        int_regs[reg] = int(val)
                continue

            if not mnemonic.startswith("invoke"):
                continue

            # ── JavaScript enabled ────────────────────────────────────
            if "setJavaScriptEnabled" in raw:
                bool_val = self._bool_arg(instr, bool_regs)
                if bool_val is False:
                    continue  # explicitly false — no issue
                js_enabled = True
                # Only emit finding at end when we know if JS interface is also set

            # ── addJavascriptInterface ────────────────────────────────
            elif "addJavascriptInterface" in raw:
                has_js_interface = True
                interface_name = self._second_string_arg(instr, reg_strings)
                findings.append(Finding(
                    rule_id="WEBVIEW_JS_INTERFACE",
                    title="addJavascriptInterface exposes Java object to JavaScript",
                    description=(
                        "addJavascriptInterface binds a Java object to JavaScript. "
                        "If any content loaded (including ads or redirects) is "
                        "attacker-controlled, it can invoke arbitrary Java reflection "
                        "and achieve RCE on Android < 4.2 (API 17)."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="WEBVIEW",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=(
                        f"addJavascriptInterface(\"{interface_name or '?'}\") "
                        f"@offset {offset}"
                    ),
                    remediation=(
                        "Annotate exposed methods with @JavascriptInterface (API >= 17). "
                        "Restrict the interface to methods that do NOT handle sensitive data. "
                        "Load only trusted, HTTPS-pinned content."
                    ),
                    cwe_id="CWE-749",
                    cvss=9.8,
                ))

            # ── File access ───────────────────────────────────────────
            elif "setAllowFileAccess" in raw or "setAllowUniversalAccessFromFileURLs" in raw:
                bool_val = self._bool_arg(instr, bool_regs)
                if bool_val is False:
                    continue  # explicitly disabled — no issue
                method = (
                    "setAllowUniversalAccessFromFileURLs"
                    if "Universal" in raw else "setAllowFileAccess"
                )
                severity = (
                    Severity.CRITICAL if "Universal" in raw else Severity.HIGH
                )
                findings.append(Finding(
                    rule_id="WEBVIEW_FILE_ACCESS",
                    title=f"WebView {method} enabled",
                    description=(
                        f"{method}(true) allows JavaScript in the WebView to read "
                        "local files via file:// URIs, potentially exfiltrating "
                        "app-private data. setAllowUniversalAccessFromFileURLs is "
                        "especially dangerous as it bypasses same-origin policy."
                    ),
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    category="WEBVIEW",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"{method}(true) @offset {offset}",
                    remediation=(
                        "Set both setAllowFileAccess(false) and "
                        "setAllowUniversalAccessFromFileURLs(false) unless "
                        "file access is strictly required and sandboxed."
                    ),
                    cwe_id="CWE-200",
                    cvss=8.1 if "Universal" in raw else 7.5,
                ))

            # ── Content access (combined with JS is dangerous) ────────
            elif "setAllowContentAccess" in raw:
                bool_val = self._bool_arg(instr, bool_regs)
                if bool_val is False:
                    continue
                has_content_access = True

            # ── setMixedContentMode ───────────────────────────────────
            elif "setMixedContentMode" in raw:
                int_val = self._int_arg(instr, int_regs)
                if int_val == _MIXED_CONTENT_ALWAYS_ALLOW:
                    findings.append(Finding(
                        rule_id="WEBVIEW_MIXED_CONTENT",
                        title="WebView setMixedContentMode(ALWAYS_ALLOW) — HTTP in HTTPS page",
                        description=(
                            "MIXED_CONTENT_ALWAYS_ALLOW permits loading HTTP resources "
                            "inside an HTTPS page. Passive content (images) leaks the "
                            "page context; active content (scripts) enables full MITM injection."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="WEBVIEW",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"setMixedContentMode(0/ALWAYS_ALLOW) @offset {offset}",
                        remediation=(
                            "Use MIXED_CONTENT_NEVER_ALLOW (1) or "
                            "MIXED_CONTENT_COMPATIBILITY_MODE (2) for legacy support."
                        ),
                        cwe_id="CWE-319",
                        cvss=7.4,
                    ))

            # ── Remote debug ──────────────────────────────────────────
            elif "setWebContentsDebuggingEnabled" in raw:
                bool_val = self._bool_arg(instr, bool_regs)
                if bool_val is False:
                    continue
                findings.append(Finding(
                    rule_id="WEBVIEW_REMOTE_DEBUG",
                    title="WebView remote debugging enabled",
                    description=(
                        "setWebContentsDebuggingEnabled(true) allows Chrome DevTools "
                        "to connect over USB and inspect WebView content, including "
                        "cookies, localStorage, and JavaScript context. Must not ship "
                        "in release builds."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="WEBVIEW",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"setWebContentsDebuggingEnabled(true) @offset {offset}",
                    remediation=(
                        "Wrap this call in `if (BuildConfig.DEBUG)` so it is "
                        "never enabled in release builds."
                    ),
                    cwe_id="CWE-489",
                    cvss=5.5,
                ))

            # ── Unsafe loadUrl ────────────────────────────────────────
            elif "Landroid/webkit/WebView;->loadUrl" in raw:
                url_val = self._first_string_arg(instr, reg_strings)
                if url_val and url_val.startswith("http://"):
                    findings.append(Finding(
                        rule_id="WEBVIEW_UNSAFE_LOAD",
                        title="WebView loads cleartext HTTP URL",
                        description=(
                            f'WebView.loadUrl("{url_val[:80]}") loads a non-TLS URL. '
                            "Content can be intercepted and modified in transit."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="WEBVIEW",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f'loadUrl("{url_val[:80]}") @offset {offset}',
                        remediation="Use https:// URLs exclusively.",
                        cwe_id="CWE-319",
                        cvss=7.4,
                    ))

        # ── JS enabled without interface: emit combined finding ────────
        if js_enabled and not has_js_interface:
            # Content access + JS enabled = higher risk
            sev = Severity.MEDIUM if has_content_access else Severity.LOW
            findings.append(Finding(
                rule_id="WEBVIEW_JS_ENABLED",
                title="JavaScript enabled in WebView"
                      + (" with content access" if has_content_access else ""),
                description=(
                    "setJavaScriptEnabled(true) allows JavaScript execution in WebView. "
                    + ("setAllowContentAccess(true) additionally lets JS read content:// "
                       "URIs, potentially accessing app data via ContentProviders. "
                       if has_content_access else "")
                    + "XSS in loaded content can steal session data."
                ),
                severity=sev,
                confidence=Confidence.MEDIUM,
                category="WEBVIEW",
                class_name=desc.class_name,
                method_name=desc.method_name,
                evidence="setJavaScriptEnabled(true)" + (
                    " + setAllowContentAccess(true)" if has_content_access else ""
                ),
                remediation=(
                    "Disable JavaScript if not required. If required, ensure "
                    "only trusted HTTPS content is loaded and sanitize any "
                    "data injected via evaluateJavascript()."
                ),
                cwe_id="CWE-79",
                cvss=5.4 if has_content_access else 4.3,
            ))

        return findings

    # ------------------------------------------------------------------

    def _extract_arg_reg(self, instr: dict, arg_index: int = 0) -> str | None:
        """Extract the register name for the nth argument (0-based, skipping 'this')."""
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            # Skip 'this' register (index 0 for virtual calls)
            args = regs[1:]
            if arg_index < len(args):
                return args[arg_index]
        except (ValueError, IndexError):
            pass
        return None

    def _bool_arg(self, instr: dict, bool_regs: dict[str, bool]) -> bool | None:
        reg = self._extract_arg_reg(instr, 0)
        if reg is not None and reg in bool_regs:
            return bool_regs[reg]
        return None

    def _int_arg(self, instr: dict, int_regs: dict[str, int]) -> int | None:
        reg = self._extract_arg_reg(instr, 0)
        if reg is not None and reg in int_regs:
            return int_regs[reg]
        return None

    def _first_string_arg(
        self, instr: dict, reg_strings: dict[str, str]
    ) -> str | None:
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            for reg in regs[1:]:
                if reg in reg_strings:
                    return reg_strings[reg]
        except (ValueError, IndexError):
            pass
        return None

    def _second_string_arg(
        self, instr: dict, reg_strings: dict[str, str]
    ) -> str | None:
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            found = 0
            for reg in regs[1:]:
                if reg in reg_strings:
                    found += 1
                    if found == 2:
                        return reg_strings[reg]
        except (ValueError, IndexError):
            pass
        return None
