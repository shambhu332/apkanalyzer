"""
Example APKAnalyzer plugin.

Copy this file, rename it, and implement your own checks.
Detectors in this directory are auto-loaded during analysis.
"""

from apkanalyzer.plugins.base import BaseDetector
from apkanalyzer.ir.models import Finding, Severity, Confidence


class ExampleDetector(BaseDetector):
    name = "example_detector"
    description = "Example plugin — detects hardcoded 'example.com' URLs"

    def analyse_method(self, cfg, desc, reg_strings):
        findings = []
        for instr in self._all_instructions(cfg):
            if "const-string" in instr.get("mnemonic", ""):
                for val in reg_strings.values():
                    if "example.com" in val.lower():
                        findings.append(Finding(
                            rule_id="CUSTOM_EXAMPLE_URL",
                            title="Hardcoded example.com URL",
                            description="Found a hardcoded example.com URL — replace with production endpoint.",
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            category="CUSTOM",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"URL: {val[:80]}",
                            remediation="Replace with production endpoint from config.",
                            cwe_id="CWE-200",
                            cvss=0.0,
                        ))
        return findings
