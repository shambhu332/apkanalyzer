"""
Smali-level analysis utilities.

Used when JADX decompilation fails or when we need to verify findings
at the bytecode level to avoid decompiler-introduced artefacts.

The Smali parser provides:
  - String constant extraction from .smali files
  - Opcode-level search for specific invocations
  - Register type tracking within a single method
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_CONST_STRING_RE = re.compile(r'\s+const-string[/\w]* (v\d+|p\d+), "([^"]*)"')
_INVOKE_RE = re.compile(
    r'\s+(invoke-\w+)\s+\{([^}]*)\},\s+([^;]+);->(\w+)(\([^)]*\)[^\s]+)'
)
_MOVE_RESULT_RE = re.compile(r'\s+move-result(?:-object|-wide)?\s+(v\d+|p\d+)')
_METHOD_RE = re.compile(r'^\.method\s+(.+?)\s+(\w+)\(([^)]*)\)(.*)')
_CLASS_RE = re.compile(r'^\.class\s+.+?\s+(L[^;]+;)')


def extract_strings_from_smali_dir(smali_dir: str | Path) -> list[str]:
    """
    Walk a directory of .smali files and extract all string literals.
    Deduplicates before returning.
    """
    seen: set[str] = set()
    smali_dir = Path(smali_dir)

    for smali_file in smali_dir.rglob("*.smali"):
        try:
            content = smali_file.read_text(errors="replace")
            for m in _CONST_STRING_RE.finditer(content):
                s = m.group(2)
                if s and s not in seen:
                    seen.add(s)
        except OSError as exc:
            logger.debug("Cannot read %s: %s", smali_file, exc)

    return list(seen)


def find_invocations(
    smali_dir: str | Path,
    class_pattern: str,
    method_pattern: str,
) -> list[dict]:
    """
    Find all call sites matching class/method patterns in Smali code.

    Returns list of dicts:
        {file, line, class_name, method_name, descriptor, registers, context_lines}
    """
    import fnmatch
    results = []
    smali_dir = Path(smali_dir)

    for smali_file in smali_dir.rglob("*.smali"):
        try:
            lines = smali_file.read_text(errors="replace").splitlines()
        except OSError:
            continue

        current_class = ""
        for idx, line in enumerate(lines):
            # Track current class
            cm = _CLASS_RE.match(line)
            if cm:
                current_class = cm.group(1)
                continue

            im = _INVOKE_RE.match(line)
            if not im:
                continue

            invoke_class = im.group(3).strip()
            invoke_method = im.group(4)

            if (fnmatch.fnmatch(invoke_class, class_pattern) and
                    fnmatch.fnmatch(invoke_method, method_pattern)):
                context = lines[max(0, idx - 2): idx + 3]
                results.append({
                    "file": str(smali_file),
                    "line": idx + 1,
                    "class_name": invoke_class,
                    "method_name": invoke_method,
                    "descriptor": im.group(5),
                    "registers": [r.strip() for r in im.group(2).split(",")],
                    "context_lines": context,
                })

    return results


def build_register_string_map(smali_method_lines: list[str]) -> dict[str, str]:
    """
    Build register→string map for a single Smali method body.
    Used to resolve string arguments to invocations.
    """
    reg_map: dict[str, str] = {}
    for line in smali_method_lines:
        m = _CONST_STRING_RE.match(line)
        if m:
            reg_map[m.group(1)] = m.group(2)
    return reg_map
