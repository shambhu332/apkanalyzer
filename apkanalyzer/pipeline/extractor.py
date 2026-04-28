"""
APK extraction and initial parsing.

Responsibilities
----------------
- Open the APK with androguard
- Extract assets, resources, and raw Smali via apktool (optional, for richer analysis)
- Build the string pool from the DEX string table
- Return a structured APKContext object used by all downstream stages

Why a string pool?
------------------
Many vulnerability checks need to know what string was passed to an API call.
Rather than re-scanning the DEX for each check, we build a single
{register, string} map per method during the extraction phase.

Why apktool (optional)?
-----------------------
androguard doesn't decode all resource types (e.g., network_security_config.xml,
res/raw/*.json).  We invoke apktool as a subprocess when available, falling back
gracefully if it is not installed.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class APKContext:
    """All artefacts produced during extraction, consumed by analysis stages."""
    apk_path: str
    apk: object             # androguard APK
    dx: object              # androguard Analysis
    dex_files: list         # list of androguard DalvikVMFormat

    # String pool: class_name → method_name → {register: string_value}
    # Populated by build_string_pool()
    string_pool: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)

    # All string literals in the DEX (for secret scanning)
    all_strings: list[str] = field(default_factory=list)

    # Unpacked APK directory (set if apktool ran successfully)
    unpacked_dir: Optional[str] = None

    # Parsed AndroidManifest fields
    manifest: dict = field(default_factory=dict)

    # Raw network_security_config.xml content (if available)
    network_security_config_xml: Optional[str] = None


def load_apk(apk_path: str) -> APKContext:
    """
    Open an APK with androguard and build the initial APKContext.
    This is the entry point for the pipeline.
    """
    from androguard.misc import AnalyzeAPK

    logger.info("Loading APK: %s", apk_path)
    apk, dex_files, dx = AnalyzeAPK(apk_path)

    ctx = APKContext(
        apk_path=apk_path,
        apk=apk,
        dx=dx,
        dex_files=dex_files if isinstance(dex_files, list) else [dex_files],
    )

    ctx.all_strings = _extract_all_strings(dx)
    ctx.string_pool = _build_string_pool(dx)

    logger.info(
        "Loaded: %d classes, %d methods, %d unique strings",
        sum(1 for _ in dx.get_classes()),
        sum(1 for _ in dx.get_methods()),
        len(ctx.all_strings),
    )

    return ctx


def unpack_with_apktool(ctx: APKContext) -> None:
    """
    Run apktool to unpack the APK into a temporary directory.
    Populates ctx.unpacked_dir on success.
    Silently skips if apktool is not on PATH.
    """
    apktool = shutil.which("apktool")
    if not apktool:
        logger.warning("apktool not found on PATH — skipping resource decoding")
        return

    tmp = tempfile.mkdtemp(prefix="apkanalyzer_")
    cmd = [apktool, "d", "-f", "-o", tmp, ctx.apk_path]
    # Big resource-heavy apps (Spotify, banking apps with many splits) blow
    # past 120s on slow CI runners. Allow override via env without forcing
    # everyone to fork.
    try:
        timeout = int(os.environ.get("APKANALYZER_APKTOOL_TIMEOUT", "120"))
    except ValueError:
        timeout = 120
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=timeout)
        ctx.unpacked_dir = tmp
        logger.info("apktool unpacked to %s", tmp)

        # Extract network_security_config.xml if present
        nsc_path = Path(tmp) / "res" / "xml" / "network_security_config.xml"
        if nsc_path.exists():
            ctx.network_security_config_xml = nsc_path.read_text()
            logger.info("Found network_security_config.xml")
    except subprocess.CalledProcessError as exc:
        logger.warning("apktool failed: %s", exc.stderr[:200] if exc.stderr else exc)
    except subprocess.TimeoutExpired:
        logger.warning("apktool timed out")
    except Exception as exc:
        logger.warning("apktool error: %s", exc)


def _extract_all_strings(dx) -> list[str]:
    """Extract all string literals from the DEX string table."""
    strings = []
    try:
        for string_analysis in dx.get_strings():
            s = string_analysis.get_orig_value()
            if s and isinstance(s, str) and len(s) >= 4:
                strings.append(s)
    except Exception as exc:
        logger.debug("String extraction error: %s", exc)
    return strings


def _build_string_pool(dx) -> dict[str, dict[str, dict[str, str]]]:
    """
    Build a nested dict: class_name → method_name → {register: string_value}

    This is built by scanning const-string instructions in each method's
    bytecode.  It enables O(1) string lookup during taint and detector analysis.
    """
    pool: dict[str, dict[str, dict[str, str]]] = {}
    try:
        for method_analysis in dx.get_methods():
            try:
                raw = method_analysis.get_method() if hasattr(method_analysis, "get_method") else method_analysis
                class_name = raw.get_class_name()
                method_name = raw.get_name()
            except Exception:
                continue

            reg_map: dict[str, str] = {}
            try:
                for bb in method_analysis.get_basic_blocks().get():
                    for instr in bb.get_instructions():
                        name = instr.get_name().lower()
                        if name in ("const-string", "const-string/jumbo"):
                            operands = instr.get_operands()
                            if len(operands) >= 2:
                                reg = str(operands[0][2])
                                val = str(operands[1][2])
                                reg_map[reg] = val
            except Exception:
                pass

            if reg_map:
                pool.setdefault(class_name, {})[method_name] = reg_map

    except Exception as exc:
        logger.debug("String pool build error: %s", exc)

    return pool
