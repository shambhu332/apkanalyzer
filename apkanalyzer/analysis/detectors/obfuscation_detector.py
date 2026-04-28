"""
Obfuscation and dynamic code loading detector.

Checks
------
OBFUSC_REFLECTION_CLASS   — Class.forName() used (dynamic class resolution)
OBFUSC_REFLECTION_INVOKE  — Method.invoke() used (reflective method call)
OBFUSC_DYNAMIC_DEX        — DexClassLoader / PathClassLoader / InMemoryDexClassLoader
OBFUSC_LOAD_LIBRARY       — System.loadLibrary / Runtime.load (native code loading)
OBFUSC_DYNAMIC_PROXY      — java.lang.reflect.Proxy.newProxyInstance
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

# Framework classes that legitimately use reflection internally.
# If the HOST class (the class containing the instruction) is one of these,
# we skip the finding entirely — the framework is responsible, not the app.
_FRAMEWORK_HOST_PREFIXES = (
    "Lretrofit2/",
    "Lokhttp3/",
    "Lcom/squareup/",
    "Ldagger/",
    "Lhilt_aggregated_deps/",
    "Lcom/google/dagger/",
    "Lkotlin/reflect/",
    "Lcom/google/gson/",
    "Lcom/fasterxml/jackson/",
    "Landroidx/room/",
    "Lcom/bumptech/glide/",
    "Lcom/squareup/moshi/",
    "Lcom/google/firebase/",
    "Lcom/facebook/",
    "Lio/reactivex/",
    "Lio/reactivex3/",
    "Lcom/google/android/gms/",
    "Lorg/greenrobot/eventbus/",
)

# Known safe classes that are legitimately loaded via Class.forName
_SAFE_FORNAME_PREFIXES = (
    "com.google.", "androidx.", "android.", "kotlin.", "java.",
    "org.json", "org.xmlpull", "com.squareup", "retrofit2.",
    "com.fasterxml.jackson", "okhttp3.",
)

# If DexClassLoader path arg contains these, it's from external/network — HIGH risk
_SUSPICIOUS_DEX_PATH_PATTERNS = re.compile(
    r'(?i)(getExternalStorage|/sdcard|/mnt/|http[s]?://|/tmp/|/data/local)',
)

# DI / mocking frameworks that legitimately use Proxy.newProxyInstance
_PROXY_FRAMEWORK_PATTERNS = (
    "Lretrofit2/", "Ldagger/", "Lmockito/", "Lorg/mockito/",
    "Ljava/lang/reflect/Proxy",
)


def _is_framework_host(class_name: str) -> bool:
    return any(class_name.startswith(p) for p in _FRAMEWORK_HOST_PREFIXES)


class ObfuscationDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []

        # If the entire class is a known framework class, skip — not app code
        if _is_framework_host(desc.class_name):
            return findings

        instructions = get_all_instructions(cfg)

        # Track the last string arg for context
        recent_strings: list[str] = []
        for v in reg_strings.values():
            recent_strings.append(v)

        for instr in instructions:
            raw = instr.get("raw", "")
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)

            if not mnemonic.startswith("invoke"):
                continue

            # ── Class.forName ─────────────────────────────────────────
            if "Ljava/lang/Class;->forName" in raw:
                # Check if the class name being loaded is known-safe
                class_arg = self._first_string_arg(instr, reg_strings)
                is_safe_class = class_arg and any(
                    class_arg.startswith(p) for p in _SAFE_FORNAME_PREFIXES
                )
                confidence = Confidence.LOW if is_safe_class else Confidence.MEDIUM
                findings.append(Finding(
                    rule_id="OBFUSC_REFLECTION_CLASS",
                    title=f"Reflective class loading via Class.forName()"
                          + (f": {class_arg}" if class_arg else ""),
                    description=(
                        "Class.forName() dynamically resolves classes at runtime, "
                        "which can hide API usage from static analysis or load "
                        "attacker-controlled classes if the name is not validated."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=confidence,
                    category="OBFUSCATION",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Class.forName({class_arg or '?'}) @offset {offset}",
                    remediation=(
                        "Avoid reflection for security-sensitive operations. "
                        "If required, validate class names against a strict allowlist."
                    ),
                    cwe_id="CWE-470",
                    cvss=5.3,
                ))

            # ── Method.invoke ─────────────────────────────────────────
            elif "Ljava/lang/reflect/Method;->invoke" in raw:
                findings.append(Finding(
                    rule_id="OBFUSC_REFLECTION_INVOKE",
                    title="Reflective method invocation via Method.invoke()",
                    description=(
                        "Method.invoke() bypasses normal access controls and can "
                        "invoke private/protected methods. Combined with Class.forName, "
                        "it enables arbitrary code execution if the method name or "
                        "class is attacker-controlled."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="OBFUSCATION",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Method.invoke() @offset {offset}",
                    remediation=(
                        "Replace reflective calls with direct typed calls where possible. "
                        "Never pass untrusted data as method names or arguments."
                    ),
                    cwe_id="CWE-470",
                    cvss=5.3,
                ))

            # ── Dynamic DEX loading ───────────────────────────────────
            elif any(loader in raw for loader in (
                "Ldalvik/system/DexClassLoader;",
                "Ldalvik/system/PathClassLoader;",
                "Ldalvik/system/InMemoryDexClassLoader;",
            )):
                loader_name = "DexClassLoader"
                if "InMemory" in raw:
                    loader_name = "InMemoryDexClassLoader"
                elif "PathClassLoader" in raw:
                    loader_name = "PathClassLoader"

                # Check if a suspicious path is in reg_strings (external storage)
                suspicious_path = any(
                    _SUSPICIOUS_DEX_PATH_PATTERNS.search(v)
                    for v in reg_strings.values()
                )
                severity = Severity.CRITICAL if suspicious_path else Severity.HIGH
                description_extra = (
                    " The DEX path appears to reference external storage or a "
                    "network location — a strong indicator of malicious payload delivery."
                    if suspicious_path else
                    " Verify the DEX origin is app-bundled and integrity-verified."
                )

                findings.append(Finding(
                    rule_id="OBFUSC_DYNAMIC_DEX",
                    title=f"Dynamic DEX loading via {loader_name}",
                    description=(
                        f"{loader_name} loads executable code from an external path "
                        "or memory buffer at runtime. This is used for hot-patching "
                        "but also to load malware payloads and hide code from static "
                        f"analysis.{description_extra}"
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH if suspicious_path else Confidence.MEDIUM,
                    category="OBFUSCATION",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"{loader_name} @offset {offset}",
                    remediation=(
                        "Dynamic DEX loading should not appear in production apps. "
                        "If required for hot-patching, use signed, integrity-verified "
                        "DEX files from app-private storage only."
                    ),
                    cwe_id="CWE-829",
                    cvss=9.3 if suspicious_path else 7.5,
                ))

            # ── Native library loading ────────────────────────────────
            elif ("Ljava/lang/System;->loadLibrary" in raw or
                    "Ljava/lang/Runtime;->load" in raw):
                lib_name = self._first_string_arg(instr, reg_strings)
                # Bundled named libraries are expected; loadLibrary("foo") is fine
                # Runtime.load() with a path is more suspicious
                is_path_load = "Runtime;->load" in raw and not "loadLibrary" in raw
                findings.append(Finding(
                    rule_id="OBFUSC_LOAD_LIBRARY",
                    title=f"Native library loaded: {lib_name or '?'}",
                    description=(
                        "System.loadLibrary() or Runtime.load() loads a native (.so) "
                        "library. Native code bypasses Android's Java security model. "
                        + ("Runtime.load() with an explicit path can load libraries "
                           "from arbitrary locations — ensure the path is not attacker-controllable."
                           if is_path_load else
                           "Ensure the library is bundled with the APK and not downloaded.")
                    ),
                    severity=Severity.MEDIUM if is_path_load else Severity.LOW,
                    confidence=Confidence.MEDIUM if is_path_load else Confidence.LOW,
                    category="OBFUSCATION",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"{'Runtime.load' if is_path_load else 'loadLibrary'}({lib_name or '?'}) @offset {offset}",
                    remediation=(
                        "Ensure native libraries are bundled in the APK (not downloaded) "
                        "and verify their integrity before loading."
                    ),
                    cwe_id="CWE-114",
                    cvss=5.9 if is_path_load else 3.1,
                ))

            # ── Dynamic proxy ─────────────────────────────────────────
            elif "Ljava/lang/reflect/Proxy;->newProxyInstance" in raw:
                # Suppress if the caller is clearly a DI/Retrofit context
                is_di_context = any(
                    p in desc.class_name for p in _PROXY_FRAMEWORK_PATTERNS
                )
                if is_di_context:
                    continue
                findings.append(Finding(
                    rule_id="OBFUSC_DYNAMIC_PROXY",
                    title="Dynamic proxy created via Proxy.newProxyInstance()",
                    description=(
                        "Proxy.newProxyInstance() intercepts all interface method calls. "
                        "Used legitimately in DI frameworks (Retrofit, Dagger), but "
                        "also abused by malware to hook security-sensitive APIs."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    category="OBFUSCATION",
                    class_name=desc.class_name,
                    method_name=desc.method_name,
                    evidence=f"Proxy.newProxyInstance() @offset {offset}",
                    remediation=(
                        "Audit all InvocationHandler implementations to ensure they "
                        "do not intercept or log security-sensitive data."
                    ),
                    cwe_id="CWE-470",
                    cvss=3.7,
                ))

        return findings

    def _first_string_arg(self, instr: dict, reg_strings: dict) -> str | None:
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
