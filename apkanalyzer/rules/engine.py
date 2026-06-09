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

Data-flow rules
---------------
Beyond the regex `smali_pattern` form, a rule may declare a `data_flow`
block that compiles into TaintSource / TaintSink / Sanitiser specs and is
fed into the inter-procedural taint engine. Schema::

    rules:
      - id: TAINT_PII_TO_NETWORK
        title: ...
        severity: HIGH
        confidence: HIGH
        cwe: CWE-359
        data_flow:
          sources:
            - class: "Landroid/telephony/TelephonyManager;"
              method: "getSubscriberId"
              label: "DEVICE_ID"
          sinks:
            - class: "Lokhttp3/RequestBody;"
              method: "create"
              label: "NETWORK_OUT"
              tainted_param: 0
          sanitizers:
            - class: "Lcom/example/Mask;"
              method: "redact"
              label: "REDACT"
              neutralizes: ["NETWORK_OUT"]

The rule's metadata (id, title, severity, …) is unused by the engine
itself — those entries don't drive findings directly. They drive
findings via the *taint engine*, which already constructs Findings out
of source→sink paths. Putting the dataflow definitions inside the same
YAML rule lets ops teams version-control sources and sinks alongside
the regex rules without juggling a parallel YAML hierarchy.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from apkanalyzer.ir.models import Finding, Severity, Confidence
from apkanalyzer.analysis.taint.sources import TaintSourceSpec
from apkanalyzer.analysis.taint.sinks import TaintSinkSpec
from apkanalyzer.analysis.taint.sanitizers import SanitizerSpec

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
        "language",
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
        # Default language is smali; rules can opt into running against the
        # jadx-decompiled Java tree instead by setting `language: java`.
        # Patterns coupled to Java-specific constructs (Kotlin lambdas,
        # `suspend`, sealed classes) only make sense at that level.
        lang = str(data.get("language", "smali")).lower()
        self.language: str = lang if lang in ("smali", "java") else "smali"
        self._pattern: Optional[re.Pattern] = None
        pattern_str = (
            data.get("smali_pattern")
            or data.get("java_pattern")
            or data.get("source_pattern")
            or ""
        )
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
        # Compiled data-flow specs harvested from any rule with a `data_flow`
        # block. Orchestrator merges these into the TaintEngine's spec lists
        # without going through the loader.py CLI hook.
        self.taint_sources: list[TaintSourceSpec] = []
        self.taint_sinks: list[TaintSinkSpec] = []
        self.taint_sanitizers: list[SanitizerSpec] = []
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
        new_sources: list[TaintSourceSpec] = []
        new_sinks: list[TaintSinkSpec] = []
        new_sanitizers: list[SanitizerSpec] = []
        for yaml_file in sorted(rules_path.glob("*.yaml")):
            try:
                new_mtimes[str(yaml_file)] = yaml_file.stat().st_mtime
                data = yaml.safe_load(yaml_file.read_text())
                if not isinstance(data, dict):
                    continue
                for rule_data in data.get("rules", []):
                    if (
                        "smali_pattern" in rule_data
                        or "java_pattern" in rule_data
                        or "source_pattern" in rule_data
                    ):
                        new_rules.append(Rule(rule_data))
                    df = rule_data.get("data_flow") or rule_data.get("dataflow")
                    if isinstance(df, dict):
                        s, k, n = self._compile_data_flow(df, rule_data, yaml_file)
                        new_sources.extend(s)
                        new_sinks.extend(k)
                        new_sanitizers.extend(n)
                # Bare top-level data-flow blocks (no enclosing rule) — a
                # convenient form for files that only carry source/sink defs.
                top_df = data.get("data_flow") or data.get("dataflow")
                if isinstance(top_df, dict):
                    s, k, n = self._compile_data_flow(top_df, {}, yaml_file)
                    new_sources.extend(s)
                    new_sinks.extend(k)
                    new_sanitizers.extend(n)
            except Exception as exc:
                logger.warning("Failed to load %s: %s", yaml_file, exc)

        self.rules = new_rules
        self.taint_sources = new_sources
        self.taint_sinks = new_sinks
        self.taint_sanitizers = new_sanitizers
        self._mtimes = new_mtimes
        logger.info(
            "Loaded %d regex rules + %d sources / %d sinks / %d sanitizers from %s",
            len(self.rules), len(new_sources), len(new_sinks),
            len(new_sanitizers), rules_dir,
        )

    @staticmethod
    def _compile_data_flow(
        df: dict, rule_meta: dict, yaml_file: Path,
    ) -> tuple[list[TaintSourceSpec], list[TaintSinkSpec], list[SanitizerSpec]]:
        """Convert a `data_flow:` YAML block into TaintEngine spec objects.

        Schema is intentionally identical to `apkanalyzer/analysis/taint/loader.py`
        so the same dicts can be hand-written or programmatically generated.
        Malformed entries log a warning and are skipped — never abort the
        whole rule load because of one typo.
        """
        sources: list[TaintSourceSpec] = []
        sinks: list[TaintSinkSpec] = []
        sanitizers: list[SanitizerSpec] = []

        def _str_or_none(d, *keys):
            for k in keys:
                v = d.get(k)
                if v:
                    return str(v)
            return None

        for entry in df.get("sources") or df.get("pattern-source") or []:
            if not isinstance(entry, dict):
                logger.warning("%s: data_flow source not a mapping: %r", yaml_file, entry)
                continue
            cls = _str_or_none(entry, "class", "class_pattern")
            method = _str_or_none(entry, "method", "method_pattern")
            label = entry.get("label") or rule_meta.get("source_label")
            if not (cls and method and label):
                logger.warning("%s: data_flow source missing class/method/label: %r",
                               yaml_file, entry)
                continue
            try:
                sources.append(TaintSourceSpec(
                    class_pattern=str(cls),
                    method_pattern=str(method),
                    label=str(label),
                    param_index=int(entry.get("param_index", -1)),
                ))
            except (TypeError, ValueError) as exc:
                logger.warning("%s: invalid data_flow source %r: %s",
                               yaml_file, entry, exc)

        for entry in df.get("sinks") or df.get("pattern-sink") or []:
            if not isinstance(entry, dict):
                logger.warning("%s: data_flow sink not a mapping: %r", yaml_file, entry)
                continue
            cls = _str_or_none(entry, "class", "class_pattern")
            method = _str_or_none(entry, "method", "method_pattern")
            label = entry.get("label") or rule_meta.get("sink_label")
            if not (cls and method and label):
                logger.warning("%s: data_flow sink missing class/method/label: %r",
                               yaml_file, entry)
                continue
            try:
                sinks.append(TaintSinkSpec(
                    class_pattern=str(cls),
                    method_pattern=str(method),
                    label=str(label),
                    tainted_param=int(entry.get("tainted_param", 0)),
                ))
            except (TypeError, ValueError) as exc:
                logger.warning("%s: invalid data_flow sink %r: %s",
                               yaml_file, entry, exc)

        for entry in df.get("sanitizers") or df.get("pattern-sanitizer") or []:
            if not isinstance(entry, dict):
                logger.warning("%s: data_flow sanitizer not a mapping: %r", yaml_file, entry)
                continue
            cls = _str_or_none(entry, "class", "class_pattern")
            method = _str_or_none(entry, "method", "method_pattern")
            label = entry.get("label")
            neutralizes = entry.get("neutralizes") or []
            if isinstance(neutralizes, str):
                neutralizes = [neutralizes]
            if not (cls and method and label):
                logger.warning("%s: data_flow sanitizer missing class/method/label: %r",
                               yaml_file, entry)
                continue
            try:
                sanitizers.append(SanitizerSpec(
                    class_pattern=str(cls),
                    method_pattern=str(method),
                    label=str(label),
                    neutralizes=set(str(x) for x in neutralizes),
                ))
            except (TypeError, ValueError) as exc:
                logger.warning("%s: invalid data_flow sanitizer %r: %s",
                               yaml_file, entry, exc)

        return sources, sinks, sanitizers

    def collect_taint_specs(
        self,
    ) -> tuple[list[TaintSourceSpec], list[TaintSinkSpec], list[SanitizerSpec]]:
        """Return the data-flow specs harvested from `data_flow:` blocks."""
        return list(self.taint_sources), list(self.taint_sinks), list(self.taint_sanitizers)

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
        java_dir: Optional[str] = None,
    ) -> list[Finding]:
        """
        Scan all .smali files in smali_dir, plus optional .java files
        decompiled by jadx.

        Parameters
        ----------
        reachable_classes : if provided, only analyse files whose class names
                            are in this set (for FP reduction)
        existing_rule_ids : rule IDs already emitted by other detectors —
                            avoid double-counting
        java_dir          : optional jadx Java-source root. Rules tagged
                            `language: java` are only run against this tree;
                            the default `smali` language is unaffected.
        """
        if not self.rules:
            return []

        existing = existing_rule_ids or set()
        findings: list[Finding] = []

        for smali_file in Path(smali_dir).rglob("*.smali"):
            try:
                findings.extend(
                    self._scan_file(smali_file, reachable_classes, existing,
                                    language="smali")
                )
            except OSError as exc:
                logger.debug("Cannot read %s: %s", smali_file, exc)

        if java_dir:
            java_root = Path(java_dir)
            if java_root.is_dir():
                for java_file in java_root.rglob("*.java"):
                    try:
                        findings.extend(
                            self._scan_file(java_file, None, existing,
                                            language="java")
                        )
                    except OSError as exc:
                        logger.debug("Cannot read %s: %s", java_file, exc)

        return findings

    def _scan_file(
        self,
        smali_file: Path,
        reachable_classes: Optional[set[str]],
        existing_rule_ids: set[str],
        language: str = "smali",
    ) -> list[Finding]:
        lines = smali_file.read_text(errors="replace").splitlines()

        # Extract class name. Smali files start with a `.class` directive;
        # for jadx-decompiled Java we fall back to deriving the class name
        # from the file path under the source root so the reachable-class
        # filter still applies (Java files have explicit `package` lines but
        # walking them requires more parsing than is worth here).
        class_name = ""
        if language == "smali":
            for line in lines[:10]:
                if line.startswith(".class"):
                    parts = line.split()
                    if parts:
                        class_name = parts[-1]
                    break
        else:
            # Java path: we don't gate on reachable_classes since reachability
            # is computed in DEX-land. Test-class filter still applies via
            # filename heuristic.
            class_name = smali_file.stem

        if _is_test_class(class_name):
            return []

        # Convert Smali class name (Lcom/example/Foo;) to set lookup key
        if (
            language == "smali"
            and reachable_classes
            and class_name not in reachable_classes
        ):
            return []

        findings: list[Finding] = []
        # Bucket rules so we only join the file text once when a multi-line
        # rule actually exists — for the common single-line case we stay on
        # the cheap line-by-line path. We also gate by the rule's `language`
        # attribute so smali-only rules don't match Java sources and vice-versa.
        applicable = [r for r in self.rules if r.language == language]
        line_rules = [r for r in applicable if not r.multiline]
        multi_rules = [r for r in applicable if r.multiline]

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
