"""
YAML-driven rule engine.

Loads rules from rules/*.yaml and applies them to Smali files via regex.
This provides a lightweight second pass that catches patterns the AST-based
detectors might miss in obfuscated or unusual bytecode.

Rules fire only when:
  1. The pattern matches a line in a reachable .smali file
  2. The class containing the match is not a test/library class
  3. The same finding has not already been emitted by a higher-fidelity detector

This prevents double-counting while providing a safety net for pattern-based
detection.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from apkanalyzer.ir.models import Finding, Severity, Confidence

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent.parent.parent / "rules"

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}
_CONFIDENCE_MAP = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
}

from apkanalyzer.utils.test_class import is_test_class as _is_test_class


class Rule:
    __slots__ = (
        "rule_id", "title", "severity", "confidence", "cwe", "cvss",
        "category", "description", "remediation", "_pattern", "multiline",
    )

    def __init__(self, data: dict) -> None:
        self.rule_id: str = data["id"]
        self.title: str = data["title"]
        self.severity: Severity = _SEVERITY_MAP.get(data.get("severity", "MEDIUM"), Severity.MEDIUM)
        self.confidence: Confidence = _CONFIDENCE_MAP.get(data.get("confidence", "LOW"), Confidence.LOW)
        self.cwe: str = data.get("cwe", "")
        self.cvss: float = float(data.get("cvss", 0.0))
        self.category: str = data.get("category", "GENERAL")
        self.description: str = data.get("description", "").strip()
        self.remediation: str = data.get("remediation", "").strip()
        # Multi-line patterns let a rule span several smali instructions —
        # e.g., to assert that an `invoke-virtual …setHostnameVerifier` is
        # followed within a few lines by `ALLOW_ALL_HOSTNAME_VERIFIER`.
        self.multiline: bool = bool(data.get("multiline", False))
        self._pattern: Optional[re.Pattern] = None
        pattern_str = data.get("smali_pattern", "")
        if pattern_str:
            flags = re.DOTALL | re.MULTILINE if self.multiline else 0
            try:
                self._pattern = re.compile(pattern_str, flags)
            except re.error as exc:
                logger.warning("Invalid regex in rule %s: %s", self.rule_id, exc)

    def matches(self, text: str) -> bool:
        return bool(self._pattern and self._pattern.search(text))


class RuleEngine:
    """
    Loads all YAML rule files from the rules/ directory and applies them
    to Smali source files.  Supports hot-reload via reload().
    """

    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self.rules: list[Rule] = []
        self._rules_dir: str = rules_dir or str(_RULES_DIR)
        self._mtimes: dict[str, float] = {}
        self._load_rules(self._rules_dir)

    def _load_rules(self, rules_dir: str) -> None:
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            logger.warning("Rules directory not found: %s", rules_dir)
            return

        new_rules: list[Rule] = []
        new_mtimes: dict[str, float] = {}
        for yaml_file in sorted(rules_path.glob("*.yaml")):
            try:
                new_mtimes[str(yaml_file)] = yaml_file.stat().st_mtime
                data = yaml.safe_load(yaml_file.read_text())
                for rule_data in data.get("rules", []):
                    new_rules.append(Rule(rule_data))
            except Exception as exc:
                logger.warning("Failed to load %s: %s", yaml_file, exc)

        self.rules = new_rules
        self._mtimes = new_mtimes
        logger.info("Loaded %d rules from %s", len(self.rules), rules_dir)

    def reload(self) -> bool:
        """
        Reload rules if any YAML file has changed since last load.
        Returns True if rules were reloaded.
        """
        rules_path = Path(self._rules_dir)
        changed = False
        for yaml_file in rules_path.glob("*.yaml"):
            key = str(yaml_file)
            try:
                mtime = yaml_file.stat().st_mtime
                if key not in self._mtimes or self._mtimes[key] != mtime:
                    changed = True
                    break
            except OSError:
                pass
        # Also detect new or deleted files
        current_keys = {str(f) for f in rules_path.glob("*.yaml")}
        if current_keys != set(self._mtimes.keys()):
            changed = True
        if changed:
            logger.info("Rules changed — reloading")
            self._load_rules(self._rules_dir)
        return changed

    def scan_smali_dir(
        self,
        smali_dir: str,
        reachable_classes: Optional[set[str]] = None,
        existing_rule_ids: Optional[set[str]] = None,
    ) -> list[Finding]:
        """
        Scan all .smali files in smali_dir.

        Parameters
        ----------
        reachable_classes : if provided, only analyse files whose class names
                            are in this set (for FP reduction)
        existing_rule_ids : rule IDs already emitted by other detectors —
                            avoid double-counting
        """
        if not self.rules:
            return []

        existing = existing_rule_ids or set()
        findings: list[Finding] = []

        for smali_file in Path(smali_dir).rglob("*.smali"):
            try:
                findings.extend(
                    self._scan_file(smali_file, reachable_classes, existing)
                )
            except OSError as exc:
                logger.debug("Cannot read %s: %s", smali_file, exc)

        return findings

    def _scan_file(
        self,
        smali_file: Path,
        reachable_classes: Optional[set[str]],
        existing_rule_ids: set[str],
    ) -> list[Finding]:
        lines = smali_file.read_text(errors="replace").splitlines()

        # Extract class name from first .class line
        class_name = ""
        for line in lines[:10]:
            if line.startswith(".class"):
                parts = line.split()
                if parts:
                    class_name = parts[-1]
                break

        if _is_test_class(class_name):
            return []

        # Convert Smali class name (Lcom/example/Foo;) to set lookup key
        if reachable_classes and class_name not in reachable_classes:
            return []

        findings: list[Finding] = []
        # Bucket rules so we only join the file text once when a multi-line
        # rule actually exists — for the common single-line case we stay on
        # the cheap line-by-line path.
        line_rules = [r for r in self.rules if not r.multiline]
        multi_rules = [r for r in self.rules if r.multiline]

        for line_no, line in enumerate(lines, start=1):
            for rule in line_rules:
                if rule.rule_id in existing_rule_ids:
                    continue
                if rule.matches(line):
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        description=rule.description,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        category=rule.category,
                        class_name=class_name,
                        file_path=str(smali_file),
                        line_number=line_no,
                        evidence=f"Line {line_no}: {line.strip()[:120]}",
                        remediation=rule.remediation,
                        cwe_id=rule.cwe,
                        cvss=rule.cvss,
                    ))

        if multi_rules:
            full_text = "\n".join(lines)
            for rule in multi_rules:
                if rule.rule_id in existing_rule_ids or not rule._pattern:
                    continue
                m = rule._pattern.search(full_text)
                if not m:
                    continue
                # Approximate the start line by counting newlines before the match
                line_no = full_text.count("\n", 0, m.start()) + 1
                snippet = m.group(0).replace("\n", " ⏎ ").strip()[:160]
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    category=rule.category,
                    class_name=class_name,
                    file_path=str(smali_file),
                    line_number=line_no,
                    evidence=f"Line {line_no} (multiline): {snippet}",
                    remediation=rule.remediation,
                    cwe_id=rule.cwe,
                    cvss=rule.cvss,
                ))

        return findings
