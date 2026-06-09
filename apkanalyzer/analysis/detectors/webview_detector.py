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

Constant propagation
--------------------
The detector formerly walked instructions in offset order with a single
flat const-register dict. That misses any pattern where the boolean
argument is set in one block and the WebView setter is invoked in a
different block — which is the *common* case for Kotlin/Java idioms like::

    boolean js = BuildConfig.RELEASE ? false : true;     // block B0
    settings.setJavaScriptEnabled(js);                   // block B5

This module now runs a proper monotone forward analysis: each block's
entry state is the meet (intersection-on-equality) of its predecessors'
exit states, with TOP = "register holds known constant X" and BOTTOM =
"register's value is not statically resolvable". Joins where two
predecessors disagree on a register's value drop it to BOTTOM, which
correctly suppresses findings whose triggering const is path-dependent.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Optional

from apkanalyzer.ir.models import (
    CFGMethod,
    MethodDescriptor,
    Finding,
    Severity,
    Confidence,
)

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
        if not cfg.blocks:
            return []

        # Compute per-instruction const-register state via a CFG worklist.
        # Returns dict: instr_offset → {reg → int_value}.
        per_instr_consts = self._propagate_consts(cfg)

        findings: list[Finding] = []
        js_enabled = False
        has_js_interface = False
        has_content_access = False

        # Walk every block (order doesn't matter here — each instruction
        # carries its own already-joined const state). We still need a
        # stable order for the post-loop "JS without interface" check, so
        # iterate blocks by id, then instructions by offset.
        for block_id in sorted(cfg.blocks.keys(), key=lambda b: int(b) if str(b).isdigit() else b):
            block = cfg.blocks[block_id]
            for instr in block.instructions:
                raw = instr.get("raw", "")
                mnemonic = instr.get("mnemonic", "")
                offset = instr.get("offset", 0)
                consts_here = per_instr_consts.get(offset, {})

                if not mnemonic.startswith("invoke"):
                    continue

                # ── JavaScript enabled ────────────────────────────────────
                if "setJavaScriptEnabled" in raw:
                    bool_val = self._bool_arg(instr, consts_here)
                    if bool_val is False:
                        continue
                    js_enabled = True

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
                    bool_val = self._bool_arg(instr, consts_here)
                    if bool_val is False:
                        continue
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
                    bool_val = self._bool_arg(instr, consts_here)
                    if bool_val is False:
                        continue
                    has_content_access = True

                # ── setMixedContentMode ───────────────────────────────────
                elif "setMixedContentMode" in raw:
                    int_val = self._int_arg(instr, consts_here)
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
                    bool_val = self._bool_arg(instr, consts_here)
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
    # Cross-block constant propagation
    # ------------------------------------------------------------------

    def _propagate_consts(self, cfg: CFGMethod) -> dict[int, dict[str, int]]:
        """
        Forward dataflow over the CFG that tracks per-register int constants.

        Lattice
        -------
            TOP                            ← register has not been assigned
            v ∈ ℤ                         ← register holds known constant v
            BOTTOM (absent from dict)     ← register's value is unknown

        Transfer functions
        ------------------
            const/4, const/16, const, const/high16   → reg ← v
            move / move-object  vDst, vSrc           → vDst ← state[vSrc]
            move-result*       vDst                  → vDst is BOTTOM
                                                       (return values aren't
                                                       statically known here)
            invoke-*                                 → no change to caller regs
            anything else writing reg                → BOTTOM (drop reg)

        Join (meet at block entry)
        --------------------------
            For each register in any predecessor:
              - if all predecessors agree on the same value → keep value
              - otherwise → BOTTOM

        Returns
        -------
        Dict mapping each instruction's offset to the const-register state
        that holds *immediately before* the instruction executes. Callers
        consume this as `consts_here.get(reg)` to resolve invoke arguments.
        """
        # Per-block (entry, exit) states. None = unvisited; dict = known.
        block_in: dict[str, Optional[dict[str, int]]] = {bid: None for bid in cfg.blocks}
        block_out: dict[str, dict[str, int]] = {bid: {} for bid in cfg.blocks}
        per_instr: dict[int, dict[str, int]] = {}

        # Initialise worklist with entry block (or any block with no preds).
        worklist: deque[str] = deque()
        if cfg.entry_block:
            block_in[cfg.entry_block] = {}
            worklist.append(cfg.entry_block)
        else:
            for bid in cfg.blocks:
                block_in[bid] = {}
                worklist.append(bid)

        # Build predecessor map once (CFG only stores successors).
        preds: dict[str, list[str]] = {bid: [] for bid in cfg.blocks}
        for bid, block in cfg.blocks.items():
            for succ in block.successors:
                if succ in preds:
                    preds[succ].append(bid)

        # Iteration cap mirrors the taint engine's worklist guard. Const
        # propagation converges much faster than taint (smaller lattice),
        # but a guard keeps a malformed CFG from spinning forever.
        max_iters = max(200, len(cfg.blocks) * 20)
        iters = 0

        while worklist and iters < max_iters:
            iters += 1
            bid = worklist.popleft()
            block = cfg.blocks.get(bid)
            if block is None:
                continue
            in_state = dict(block_in[bid] or {})
            cur = dict(in_state)

            for instr in block.instructions:
                offset = instr.get("offset", 0)
                # Snapshot the state BEFORE the instruction so callers see
                # the consts available to the invoke's argument registers.
                per_instr[offset] = dict(cur)
                self._apply_instr(instr, cur)

            # Push to successors and re-queue any whose entry state changed.
            block_out[bid] = cur
            for succ in block.successors:
                if succ not in cfg.blocks:
                    continue
                merged = self._meet(block_in[succ], cur)
                if merged != block_in[succ]:
                    block_in[succ] = merged
                    if succ not in worklist:
                        worklist.append(succ)

        return per_instr

    @staticmethod
    def _meet(
        existing: Optional[dict[str, int]],
        incoming: dict[str, int],
    ) -> dict[str, int]:
        """
        Lattice meet of two register states. Unvisited block (existing=None)
        adopts the incoming state outright. Otherwise keep only registers
        whose values agree — disagreements drop to BOTTOM (omit).
        """
        if existing is None:
            return dict(incoming)
        out: dict[str, int] = {}
        for reg, val in existing.items():
            if reg in incoming and incoming[reg] == val:
                out[reg] = val
        return out

    @staticmethod
    def _apply_instr(instr: dict, state: dict[str, int]) -> None:
        """In-place apply this instruction's transfer function to `state`."""
        mnemonic = instr.get("mnemonic", "")
        operands = instr.get("operands", [])

        # Constants
        if mnemonic in ("const/4", "const/16", "const", "const/high16",
                        "const-wide/16", "const-wide/32", "const-wide"):
            if len(operands) >= 2:
                reg = str(operands[0].get("value", ""))
                val = operands[1].get("value", None)
                if reg and isinstance(val, (int, bool)):
                    state[reg] = int(val)
            return

        # move / move-object: forward the source's known value (if any)
        if mnemonic.startswith("move") and "result" not in mnemonic and "exception" not in mnemonic:
            if len(operands) >= 2:
                dst = str(operands[0].get("value", ""))
                src = str(operands[1].get("value", ""))
                if dst:
                    if src in state:
                        state[dst] = state[src]
                    else:
                        state.pop(dst, None)
            return

        # move-result*: return values aren't const-resolved here, drop dst
        if mnemonic.startswith("move-result"):
            if operands:
                dst = str(operands[0].get("value", ""))
                if dst:
                    state.pop(dst, None)
            return

        # invoke-*: caller registers are not directly written, do nothing
        if mnemonic.startswith("invoke"):
            return

        # Conservative default: any other writer of operand[0] drops it.
        if operands:
            dst = str(operands[0].get("value", ""))
            if dst and dst.startswith(("v", "p")):
                state.pop(dst, None)

    # ------------------------------------------------------------------
    # Argument-resolution helpers
    # ------------------------------------------------------------------

    def _extract_arg_reg(self, instr: dict, arg_index: int = 0) -> str | None:
        """Extract the register name for the nth argument (0-based, skipping 'this')."""
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            args = regs[1:]
            if arg_index < len(args):
                return args[arg_index]
        except (ValueError, IndexError):
            pass
        return None

    def _bool_arg(self, instr: dict, consts: dict[str, int]) -> bool | None:
        reg = self._extract_arg_reg(instr, 0)
        if reg is not None and reg in consts:
            return bool(consts[reg])
        return None

    def _int_arg(self, instr: dict, consts: dict[str, int]) -> int | None:
        reg = self._extract_arg_reg(instr, 0)
        if reg is not None and reg in consts:
            return consts[reg]
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
