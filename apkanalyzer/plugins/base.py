"""
Base class for APKAnalyzer custom detector plugins.

To write a plugin:
  1. Create a .py file in the plugins/ directory at the project root
  2. Subclass BaseDetector
  3. Implement at least one of the analyse_* methods

Example
-------
# plugins/my_detector.py

from apkanalyzer.plugins.base import BaseDetector
from apkanalyzer.ir.models import Finding, Severity, Confidence

class MyDetector(BaseDetector):
    name = "my_detector"
    description = "Checks for my custom pattern"

    def analyse_method(self, cfg, desc, reg_strings):
        findings = []
        for instr in self._all_instructions(cfg):
            if "dangerous_call" in instr.get("raw", ""):
                findings.append(Finding(
                    rule_id="CUSTOM_DANGEROUS_CALL",
                    title="Dangerous call detected",
                    ...
                ))
        return findings
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from apkanalyzer.ir.models import CFGMethod, MethodDescriptor, Finding
from apkanalyzer.ir.cfg_builder import get_all_instructions


class BaseDetector(ABC):
    """
    Abstract base for all custom detector plugins.

    Subclasses override one or more analyse_* methods.  All methods
    default to returning [] so a plugin only needs to implement what it needs.
    """

    #: Short identifier used in logging and reports (override in subclass)
    name: str = "unnamed_plugin"
    #: Human-readable description shown in --plugins list
    description: str = ""

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        """Called for every reachable, non-test method in the APK."""
        return []

    def analyse_manifest(self, manifest: dict) -> list[Finding]:
        """Called once with the parsed AndroidManifest data."""
        return []

    def analyse_classes(
        self,
        class_names: list[str],
        package: str = "",
    ) -> list[Finding]:
        """Called with the full list of class names from the DEX."""
        return []

    # Convenience helper — plugins can call this instead of importing directly
    def _all_instructions(self, cfg: CFGMethod) -> list[dict[str, Any]]:
        return get_all_instructions(cfg)
