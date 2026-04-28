"""
Plugin loader — scans a directory for Python files containing BaseDetector subclasses
and returns instantiated detector objects ready to drop into the pipeline.

Usage
-----
  from apkanalyzer.plugins.loader import load_plugins
  plugins = load_plugins()          # loads from default plugins/ directory
  plugins = load_plugins("/path/to/custom/plugins")
"""

from __future__ import annotations

import ast
import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Optional

from apkanalyzer.plugins.base import BaseDetector

logger = logging.getLogger(__name__)

_DEFAULT_PLUGINS_DIR = Path(__file__).parent.parent.parent / "plugins"

# Imports we refuse to load. The list is conservative: it blocks the obvious
# "shell out / talk to network / poke memory" surface, but does not try to be
# exhaustive — a sufficiently determined plugin author can always work around
# a static check, and the goal here is to catch ACCIDENTAL hazards (a plugin
# pulled in from the internet that calls subprocess) rather than implement a
# real sandbox.
_DENIED_TOP_LEVEL_MODULES = frozenset({
    "subprocess", "socket", "ctypes", "ctypes.util",
    "multiprocessing", "asyncio.subprocess",
    "pty", "pickle", "shelve",
    "urllib", "urllib.request", "http", "http.client",
    "ftplib", "telnetlib", "smtplib", "imaplib", "poplib",
    "paramiko", "fabric", "requests",
})

# Builtins we refuse — eval/exec/__import__ are the classic escape hatches,
# and `compile` chained with eval is the same hazard.
_DENIED_BUILTINS = frozenset({
    "eval", "exec", "compile", "__import__", "open",
    "breakpoint", "input",
})

# Set APKANALYZER_TRUST_PLUGINS=1 to bypass the AST scan.
_TRUST_ENV = "APKANALYZER_TRUST_PLUGINS"


class PluginRejected(Exception):
    """Raised when a plugin file fails the safety scan."""


def _scan_for_dangers(source: str, file_path: Path) -> list[str]:
    """
    Static AST scan. Returns a list of human-readable rejection reasons;
    an empty list means the plugin passed.

    We deliberately fail closed: if the file cannot be parsed we reject it.
    """
    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as exc:
        return [f"syntax error: {exc}"]

    issues: list[str] = []

    for node in ast.walk(tree):
        # `import os, subprocess`
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".", 1)[0]
                if alias.name in _DENIED_TOP_LEVEL_MODULES or top in _DENIED_TOP_LEVEL_MODULES:
                    issues.append(
                        f"line {node.lineno}: imports denied module {alias.name!r}"
                    )

        # `from os import system`
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            top = module.split(".", 1)[0]
            if module in _DENIED_TOP_LEVEL_MODULES or top in _DENIED_TOP_LEVEL_MODULES:
                issues.append(
                    f"line {node.lineno}: imports denied module {module!r}"
                )
            # `from os import *` — even if `os` itself is allowed, star imports
            # let arbitrary names enter the module namespace.
            for alias in node.names:
                if alias.name == "*":
                    issues.append(
                        f"line {node.lineno}: star import from {module!r} not allowed"
                    )

        # eval / exec / __import__ / compile — name-call form
        elif isinstance(node, ast.Call):
            target = node.func
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                # Catch `os.system(...)` even when `os` happens to be in scope
                # via some other path. Walk the chain back to the root.
                root = target
                parts: list[str] = []
                while isinstance(root, ast.Attribute):
                    parts.append(root.attr)
                    root = root.value
                if isinstance(root, ast.Name):
                    parts.append(root.id)
                    qualified = ".".join(reversed(parts))
                    if qualified.startswith("os.") and qualified.split(".", 2)[1] in (
                        "system", "popen", "execv", "execve", "execvp", "spawnl", "spawnv"
                    ):
                        issues.append(f"line {node.lineno}: call to {qualified}()")
            if name in _DENIED_BUILTINS:
                issues.append(f"line {node.lineno}: call to builtin {name}()")

        # Walrus assignment `(x := __import__('os'))` is caught by the Call rule
        # above because the call still appears in the AST.

    return issues


def load_plugins(plugins_dir: Optional[str] = None) -> list[BaseDetector]:
    """
    Dynamically load all BaseDetector subclasses from Python files in plugins_dir.

    Each .py file is imported as a module.  Any class that subclasses BaseDetector
    (and is not BaseDetector itself) is instantiated and returned.

    Safety: every plugin file is AST-scanned for denied imports and builtins
    before exec_module is called. Files that fail the scan are skipped with
    a warning. To disable the scan (CI / known-trusted plugins) set
    APKANALYZER_TRUST_PLUGINS=1.
    """
    directory = Path(plugins_dir) if plugins_dir else _DEFAULT_PLUGINS_DIR

    if not directory.exists():
        logger.debug("Plugins directory not found: %s", directory)
        return []

    trust_all = os.environ.get(_TRUST_ENV, "").lower() in ("1", "true", "yes")

    detectors: list[BaseDetector] = []
    for py_file in sorted(directory.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read plugin %s: %s", py_file, exc)
            continue

        if not trust_all:
            issues = _scan_for_dangers(source, py_file)
            if issues:
                logger.warning(
                    "Refusing to load plugin %s: %s",
                    py_file.name, "; ".join(issues),
                )
                continue

        try:
            module_name = f"apkanalyzer_plugin_{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                try:
                    if (isinstance(obj, type) and
                            issubclass(obj, BaseDetector) and
                            obj is not BaseDetector):
                        instance = obj()
                        detectors.append(instance)
                        logger.info(
                            "Loaded plugin: %s (%s) from %s",
                            instance.name, attr_name, py_file.name,
                        )
                except TypeError:
                    pass  # abstract class or non-instantiable
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", py_file, exc)

    return detectors
