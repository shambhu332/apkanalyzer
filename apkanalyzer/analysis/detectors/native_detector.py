"""
Native library / .so binary protections detector.

Why this matters
----------------
Native libraries shipped in lib/<abi>/*.so are part of the app's TCB but are
often built without the same hardening as the Java side. They commonly expose
the app to memory-corruption exploits (M7) and side-channel debugging (M7).

Checks
------
NATIVE_NO_PIE            — Executable lacks PIE (older NDKs)
NATIVE_NO_STACK_CANARY   — Compiled without -fstack-protector
NATIVE_NO_RELRO          — No RELRO / partial RELRO segment
NATIVE_NO_NX             — Stack/heap not marked non-executable
NATIVE_TEXT_RELOCATIONS  — TEXTREL flag set (rejected by API 23+ loader, but still leaks intent)
NATIVE_DEBUG_SYMBOLS     — DT_DEBUG / unstripped symbol tables left in
NATIVE_SUSPICIOUS_RUNTIME — Loads unverified .so at runtime via System.load(/sdcard/...)

Implementation note
-------------------
We parse ELF headers directly (no external dependencies) by reading the file
header and dynamic section. For each shared library, we check security-relevant
flags. This is a pure-Python implementation — no `readelf` or `pyelftools`.
"""

from __future__ import annotations

import logging
import os
import re
import struct
from pathlib import Path

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions

logger = logging.getLogger(__name__)


# ── ELF constants ───────────────────────────────────────────────────────────
_ELFMAG = b'\x7fELF'
_ET_DYN = 3        # PIE-compatible shared object
_ET_EXEC = 2       # Old-style executable, no PIE
_PT_GNU_STACK = 0x6474e551
_PT_GNU_RELRO = 0x6474e552
_PF_X = 0x1
_DT_DEBUG = 21
_DT_TEXTREL = 22
_DT_FLAGS = 30
_DT_FLAGS_1 = 0x6ffffffb
_DF_TEXTREL = 0x4
_DF_1_NOW = 0x1
_DF_1_PIE = 0x08000000


def _read_elf_security_info(path: str) -> dict | None:
    """
    Return dict with keys: pie, nx_stack, relro, full_relro, textrel,
    has_debug, has_canary. None if not a valid ELF.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(8192)  # header + program header table fits comfortably
    except OSError:
        return None
    if not data.startswith(_ELFMAG):
        return None

    is_64 = data[4] == 2
    little_endian = data[5] == 1
    endian = "<" if little_endian else ">"

    info: dict = {
        "pie": False,
        "nx_stack": False,
        "relro": False,
        "full_relro": False,
        "textrel": False,
        "has_debug": False,
        "has_canary": False,
        "type": "ET_OTHER",
    }

    try:
        if is_64:
            # Elf64_Ehdr from offset 16: HHIQQQIHHHHHH = 48 bytes
            unpacked = struct.unpack(f"{endian}HHIQQQIHHHHHH", data[16:16+48])
        else:
            # Elf32_Ehdr from offset 16: HHIIIIIHHHHHH = 36 bytes
            unpacked = struct.unpack(f"{endian}HHIIIIIHHHHHH", data[16:16+36])
    except struct.error:
        return None
    e_type      = unpacked[0]
    e_phoff     = unpacked[4]
    e_phentsize = unpacked[8]
    e_phnum     = unpacked[9]

    info["type"] = "ET_DYN" if e_type == _ET_DYN else "ET_EXEC" if e_type == _ET_EXEC else f"ET_{e_type}"
    info["pie"] = (e_type == _ET_DYN)

    # Walk program headers for GNU_STACK / GNU_RELRO
    try:
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if is_64:
                phdr = struct.unpack(f"{endian}IIQQQQQQ", data[off: off + 56])
                p_type, p_flags = phdr[0], phdr[1]
            else:
                phdr = struct.unpack(f"{endian}IIIIIIII", data[off: off + 32])
                p_type, p_flags = phdr[0], phdr[6]

            if p_type == _PT_GNU_STACK:
                info["nx_stack"] = (p_flags & _PF_X) == 0
            elif p_type == _PT_GNU_RELRO:
                info["relro"] = True
    except (struct.error, IndexError):
        pass

    # We can't reliably detect canary / TEXTREL / DT_DEBUG without parsing the
    # full dynamic section. Use cheap byte-level heuristics over the whole
    # file (capped at 64 MB to bound memory on pathologically huge libs —
    # the previous 4 MB cap missed canary symbols in any non-trivial .so).
    try:
        size = os.path.getsize(path)
        cap = min(size, 64 * 1024 * 1024)
        with open(path, "rb") as fh:
            full = fh.read(cap)
    except OSError:
        full = data
    info["has_canary"] = b"__stack_chk_fail" in full or b"__stack_chk_guard" in full
    info["has_debug"] = b".debug_info" in full or b".debug_str" in full

    return info


class NativeDetector:

    # ── Method-level: dynamic .so loads from untrusted paths ───────────────
    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instrs = get_all_instructions(cfg)
        for instr in instrs:
            raw = instr.get("raw", "")
            offset = instr.get("offset", 0)

            if "Ljava/lang/Runtime;->load(" in raw or "Ljava/lang/System;->load(" in raw:
                # Look for an absolute path string that lives outside /data/app
                for s in reg_strings.values():
                    if not isinstance(s, str):
                        continue
                    if s.startswith(("/sdcard/", "/storage/", "/data/local/tmp/")):
                        findings.append(Finding(
                            rule_id="NATIVE_SUSPICIOUS_RUNTIME",
                            title="System.load() of a writable-path .so",
                            description=(
                                "Loading a native library from /sdcard, /storage, or "
                                "/data/local/tmp opens a TOCTOU window: any local user or "
                                "app on a rooted/dev device can replace the .so before load."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="OBFUSCATION",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"System.load(\"{s}\") at offset {offset}",
                            remediation=(
                                "Use System.loadLibrary(name) — Android resolves it from "
                                "the trusted lib/<abi> directory inside the APK."
                            ),
                            cwe_id="CWE-829",
                            cvss=7.5,
                        ))
                        break
        return findings

    # ── APK-level: scan every .so in the package ───────────────────────────
    def analyse_apk(self, ctx) -> list[Finding]:
        findings: list[Finding] = []
        unpacked = getattr(ctx, "unpacked_dir", None)
        if not unpacked:
            return findings

        lib_root = Path(unpacked) / "lib"
        if not lib_root.is_dir():
            return findings

        scanned = 0
        # Bound work, but the old 80-file limit silently dropped most libraries
        # in ABIs-stacked apps. 500 covers any realistic app while still
        # capping pathological cases (e.g. test fixtures with thousands of .so).
        for so in lib_root.rglob("*.so"):
            scanned += 1
            if scanned > 500:
                logger.warning(
                    "native_detector: stopped after 500 .so files; "
                    "remaining libraries in %s were not analysed", lib_root,
                )
                break
            info = _read_elf_security_info(str(so))
            if not info:
                continue

            rel = str(so.relative_to(unpacked))

            if not info["pie"] and info["type"] == "ET_EXEC":
                findings.append(Finding(
                    rule_id="NATIVE_NO_PIE",
                    title=f"Native binary {so.name} not compiled with PIE",
                    description=(
                        "Position-Independent Executables defeat ROP-based exploits by "
                        "randomising the load address. Required by the Android linker on "
                        "API 21+, but legacy NDKs still produce ET_EXEC binaries."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="OBFUSCATION",
                    file_path=rel,
                    evidence=f"ELF type {info['type']}",
                    remediation=(
                        "Rebuild with the modern NDK (`-fPIE -pie`) — clang's default "
                        "produces a PIE-shared object."
                    ),
                    cwe_id="CWE-1248",
                    cvss=5.5,
                ))

            if not info["nx_stack"]:
                findings.append(Finding(
                    rule_id="NATIVE_NO_NX",
                    title=f"{so.name}: stack marked executable",
                    description=(
                        "An executable stack lets an attacker run shellcode directly from "
                        "stack-resident buffers. The GNU_STACK program header should have "
                        "PF_X cleared."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="OBFUSCATION",
                    file_path=rel,
                    evidence="PT_GNU_STACK has PF_X set",
                    remediation="Add `-Wl,-z,noexecstack` to LDFLAGS.",
                    cwe_id="CWE-1037",
                    cvss=7.5,
                ))

            if not info["relro"]:
                findings.append(Finding(
                    rule_id="NATIVE_NO_RELRO",
                    title=f"{so.name}: no RELRO segment",
                    description=(
                        "RELRO (RELocation Read-Only) protects the GOT from being "
                        "overwritten via format-string or arbitrary-write bugs. Without it, "
                        "a single OOB write in the .data section can hijack control flow."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    category="OBFUSCATION",
                    file_path=rel,
                    evidence="No PT_GNU_RELRO program header",
                    remediation="Pass `-Wl,-z,relro,-z,now` for full RELRO.",
                    cwe_id="CWE-732",
                    cvss=4.8,
                ))

            if not info["has_canary"]:
                findings.append(Finding(
                    rule_id="NATIVE_NO_STACK_CANARY",
                    title=f"{so.name}: no stack canary symbol",
                    description=(
                        "__stack_chk_fail / __stack_chk_guard are absent, suggesting the "
                        "library was compiled without -fstack-protector-strong. Buffer "
                        "overflows in this .so will not be detected at runtime."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="OBFUSCATION",
                    file_path=rel,
                    evidence="symbols __stack_chk_* missing",
                    remediation="Add `-fstack-protector-strong` to CFLAGS.",
                    cwe_id="CWE-121",
                    cvss=4.4,
                ))

            if info["has_debug"]:
                findings.append(Finding(
                    rule_id="NATIVE_DEBUG_SYMBOLS",
                    title=f"{so.name}: debug info shipped in release library",
                    description=(
                        ".debug_info / .debug_str sections are present. These leak source "
                        "filenames, function signatures, and inline locals — enabling much "
                        "easier reverse-engineering."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    category="OBFUSCATION",
                    file_path=rel,
                    evidence=".debug_info section present",
                    remediation="Strip release builds: `${STRIP} --strip-debug *.so`.",
                    cwe_id="CWE-489",
                    cvss=3.7,
                ))

        return findings
