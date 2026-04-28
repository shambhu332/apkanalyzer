"""
Pipeline orchestrator.

Coordinates all analysis stages in the correct order and aggregates findings.

Stage order
-----------
1.  Extract     — load APK with androguard, build string pool, optional apktool
2.  Manifest    — parse AndroidManifest.xml
3.  CallGraph   — build inter-procedural call graph
4.  Reach       — compute reachable methods from Android entry points
5.  Taint       — inter-procedural taint analysis (Source → Sink paths)
6.  PerMethod   — crypto, network, storage, webview, deeplink, intent,
                  logging, native, obfuscation (parallel)
7.  Manifest    — debuggable, cleartext, exported components, deep links,
                  intent/SDK manifest checks
8.  Native      — ELF security flags on bundled .so libraries
9.  Secrets     — entropy + regex scan of DEX strings and decompiled smali
10. SDK / Privacy / Anti-analysis
11. YAML rules  — pattern-based safety net (RuleEngine, dedup against
                  exact rule IDs already emitted by the structured detectors)
12. Plugins     — third-party BaseDetector subclasses from plugins/
13. Score       — confidence filter + OWASP / CVSS enrichment
14. Report      — JSON + HTML output
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Callable, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from apkanalyzer.pipeline.extractor import APKContext, load_apk, unpack_with_apktool
from apkanalyzer.utils.manifest_parser import parse_manifest
from apkanalyzer.ir.call_graph import CallGraph
from apkanalyzer.ir.cfg_builder import build_cfg
from apkanalyzer.ir.models import MethodDescriptor, Finding
from apkanalyzer.analysis.reachability import compute_reachable_methods
from apkanalyzer.analysis.taint.engine import TaintEngine
from apkanalyzer.analysis.detectors.crypto_detector import CryptoDetector
from apkanalyzer.analysis.detectors.network_detector import NetworkDetector
from apkanalyzer.analysis.detectors.storage_detector import StorageDetector
from apkanalyzer.analysis.detectors.webview_detector import WebViewDetector
from apkanalyzer.analysis.detectors.secret_detector import SecretDetector
from apkanalyzer.analysis.detectors.obfuscation_detector import ObfuscationDetector
from apkanalyzer.analysis.detectors.sdk_detector import SDKDetector
from apkanalyzer.analysis.detectors.privacy_detector import PrivacyDetector
from apkanalyzer.analysis.detectors.antianalysis_detector import AntiAnalysisDetector
from apkanalyzer.analysis.detectors.deeplink_detector import DeeplinkDetector
from apkanalyzer.analysis.detectors.intent_detector import IntentDetector
from apkanalyzer.analysis.detectors.logging_detector import LoggingDetector
from apkanalyzer.analysis.detectors.native_detector import NativeDetector
from apkanalyzer.analysis.detectors.resource_detector import ResourceScanner
from apkanalyzer.scoring.confidence import filter_findings, summarise
from apkanalyzer.scoring.owasp import assign_owasp
from apkanalyzer.scoring.cvss import assign_vector
from apkanalyzer.reporting.json_reporter import JSONReporter
from apkanalyzer.reporting.html_reporter import HTMLReporter
from apkanalyzer.plugins.loader import load_plugins
from apkanalyzer.rules.engine import RuleEngine
from apkanalyzer.utils.test_class import is_test_class as _is_test_class

logger = logging.getLogger(__name__)
console = Console()

# Type alias for the optional progress callback. Hands the web layer
# (or any embedder) live stage telemetry without forcing them to re-implement
# the orchestration. Signature: (stage_name, detail, percent_complete).
ProgressCallback = Callable[[str, str, int], None]


class AnalysisPipeline:
    """
    The main orchestrator.  Instantiate once per APK.

    Parameters
    ----------
    apk_path        : path to the .apk file
    output_dir      : where to write report files
    min_confidence  : filter threshold (HIGH/MEDIUM/LOW)
    run_apktool     : whether to run apktool for resource decoding
    taint_depth     : max call depth for inter-procedural taint analysis
    plugins_dir     : optional override for the plugin directory
    extra_sources / extra_sinks / extra_sanitizers
                    : custom taint definitions
    masvs_profile   : optional MASVS L1/L2/R filter applied at scoring time
    """

    def __init__(
        self,
        apk_path: str,
        output_dir: str = ".",
        min_confidence: str = "LOW",
        run_apktool: bool = True,
        taint_depth: int = 8,
        plugins_dir: Optional[str] = None,
        extra_sources: Optional[list] = None,
        extra_sinks: Optional[list] = None,
        extra_sanitizers: Optional[list] = None,
        masvs_profile: Optional[str] = None,
    ) -> None:
        self.apk_path = apk_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.min_confidence_str = min_confidence
        self.run_apktool = run_apktool
        self.taint_depth = taint_depth
        self.plugins_dir = plugins_dir
        self.extra_sources = extra_sources or []
        self.extra_sinks = extra_sinks or []
        self.extra_sanitizers = extra_sanitizers or []
        self.masvs_profile = masvs_profile

        self._ctx: Optional[APKContext] = None
        self._findings: list[Finding] = []
        self._start_time: float = 0.0
        self._candidates: list[tuple] = []  # (cfg, desc, reg_strings) — built once, reused
        self._last_reachable: set[str] = set()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, progress_callback: Optional[ProgressCallback] = None) -> dict:
        """
        Execute the full pipeline. Returns the final report dict.

        progress_callback: optional (stage, detail, pct) → None, called at
        every stage boundary. Lets web/SSE consumers stream updates without
        re-implementing the pipeline.
        """
        self._start_time = time.time()

        def _notify(stage: str, detail: str, pct: int) -> None:
            if progress_callback is not None:
                try:
                    progress_callback(stage, detail, pct)
                except Exception as exc:  # never let a UI callback break the scan
                    logger.debug("progress_callback raised: %s", exc)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            console=console,
            transient=True,
        ) as progress:

            task = progress.add_task("Loading APK…", total=None)
            _notify("Loading APK", "Parsing DEX with androguard", 5)
            self._ctx = load_apk(self.apk_path)

            if self.run_apktool:
                progress.update(task, description="Unpacking resources (apktool)…")
                _notify("Unpacking Resources", "Running apktool", 12)
                unpack_with_apktool(self._ctx)

            progress.update(task, description="Parsing AndroidManifest…")
            _notify("Manifest", "Parsing AndroidManifest.xml", 18)
            self._ctx.manifest = parse_manifest(self._ctx.apk)

            progress.update(task, description="Building call graph…")
            _notify("Call Graph", "Building inter-procedural call graph", 25)
            cg = CallGraph.build(self._ctx.dx)

            progress.update(task, description="Computing reachable methods…")
            _notify("Reachability", "Computing reachable methods from entry points", 32)
            reachable = compute_reachable_methods(cg, self._ctx.dx)
            self._last_reachable = reachable
            _notify("Reachability", f"{len(reachable)} reachable methods", 35)

            progress.update(task, description="Running taint analysis…")
            _notify("Taint Analysis", "Tracking source → sink flows", 40)
            taint_findings = self._run_taint(cg, reachable)
            self._findings.extend(taint_findings)
            _notify("Taint Analysis", f"{len(taint_findings)} flows", 52)

            # Build the per-method candidate list ONCE here. Three later stages
            # (per-method detectors, privacy, anti-analysis) all walk the same
            # set of reachable methods; constructing CFGs three times triples
            # the cost of the most expensive bytecode iteration in the pipeline.
            progress.update(task, description="Collecting reachable methods…")
            _notify("Detector Analysis", "Collecting reachable methods", 54)
            self._candidates = self._collect_candidates(reachable)

            progress.update(task, description="Per-method detectors (parallel)…")
            _notify("Detector Analysis",
                    f"Analysing {len(self._candidates)} methods", 56)
            self._findings.extend(self._run_per_method_detectors())

            progress.update(task, description="Checking manifest flags…")
            _notify("Manifest Checks", "Checking exported components and flags", 70)
            self._findings.extend(self._run_manifest_checks())

            progress.update(task, description="Native library audit…")
            _notify("Native Library Audit", "Inspecting bundled .so libraries", 73)
            self._findings.extend(NativeDetector().analyse_apk(self._ctx))

            progress.update(task, description="Scanning for secrets…")
            _notify("Secret Detection", "Entropy + regex scan", 76)
            self._findings.extend(self._run_secret_scan())

            progress.update(task, description="Scanning resources…")
            _notify("Resource Scan", "strings.xml / res/raw / assets", 78)
            self._findings.extend(self._run_resource_scan())

            progress.update(task, description="SDK risk inventory…")
            _notify("SDK Inventory", "Detecting third-party SDKs", 80)
            self._findings.extend(self._run_sdk_scan())

            progress.update(task, description="Privacy compliance checks…")
            _notify("Privacy Checks", "PII / location / advertising-id audit", 83)
            self._findings.extend(self._run_privacy_checks())

            progress.update(task, description="Anti-analysis detection…")
            _notify("Anti-analysis", "Root / emulator / debugger checks", 86)
            self._findings.extend(self._run_antianalysis_scan())

            progress.update(task, description="YAML rule engine…")
            _notify("Rule Engine", "Pattern-based safety net", 88)
            self._findings.extend(self._run_yaml_rules())

            progress.update(task, description="Running plugins…")
            _notify("Plugins", "Running custom detectors", 90)
            self._findings.extend(self._run_plugins())

            progress.update(task, description="Scoring and filtering findings…")
            _notify("Scoring", "Confidence filter + OWASP/CVSS enrichment", 93)
            self._score_and_enrich()

            progress.update(task, description="Generating reports…")
            _notify("Generating Reports", "Writing JSON and HTML", 97)
            report = self._generate_reports()

        elapsed = time.time() - self._start_time
        console.print(
            f"\n[bold green]Analysis complete[/bold green] in {elapsed:.1f}s — "
            f"[bold]{report['summary']['total']}[/bold] findings\n"
        )
        self._print_summary(report["summary"])
        _notify("Complete", f"{report['summary']['total']} findings", 100)
        return report

    # ------------------------------------------------------------------
    # Stage implementations
    # ------------------------------------------------------------------

    def _run_taint(self, cg: CallGraph, reachable: set[str]) -> list[Finding]:
        engine = TaintEngine(
            cg,
            self._ctx.dx,
            max_depth=self.taint_depth,
            extra_sources=self.extra_sources,
            extra_sinks=self.extra_sinks,
            extra_sanitizers=self.extra_sanitizers,
        )
        return engine.run(reachable)

    def _collect_candidates(self, reachable: set[str]) -> list[tuple]:
        """
        Walk dx.get_methods() once and return (cfg, desc, reg_strings) tuples
        for every reachable, non-test method whose CFG is non-empty.

        Hoisted out of the per-stage loops so we don't pay the iteration cost
        three times. Androguard's method iterator and CFG builder are not
        cheap on large APKs.
        """
        candidates: list[tuple] = []
        for method_analysis in self._ctx.dx.get_methods():
            try:
                m = method_analysis.get_method() if hasattr(method_analysis, "get_method") else method_analysis
                class_name = m.get_class_name()
            except Exception:
                continue
            if _is_test_class(class_name):
                continue
            desc = MethodDescriptor(
                class_name=class_name,
                method_name=m.get_name(),
                descriptor=m.get_descriptor(),
            )
            if desc.full_name not in reachable:
                continue
            cfg = build_cfg(method_analysis, desc)
            if not cfg.blocks:
                continue
            reg_strings = (
                self._ctx.string_pool
                .get(class_name, {})
                .get(m.get_name(), {})
            )
            candidates.append((cfg, desc, reg_strings))
        return candidates

    def _run_per_method_detectors(self) -> list[Finding]:
        """Run all per-method detectors in parallel using a thread pool."""
        import concurrent.futures

        def _analyse_method(args):
            cfg, desc, reg_strings = args
            # Each thread gets fresh detector instances. They are stateless,
            # but per-call construction makes that contract explicit and
            # avoids any future shared-state surprises.
            local_crypto = CryptoDetector()
            local_network = NetworkDetector()
            local_storage = StorageDetector()
            local_webview = WebViewDetector()
            local_obfusc = ObfuscationDetector()
            local_deeplink = DeeplinkDetector()
            local_intent = IntentDetector()
            local_logging = LoggingDetector()
            local_native = NativeDetector()
            result: list[Finding] = []
            result.extend(local_crypto.analyse(cfg, desc, reg_strings))
            result.extend(local_network.analyse_method(cfg, desc, reg_strings))
            result.extend(local_storage.analyse_method(cfg, desc, reg_strings))
            result.extend(local_webview.analyse_method(cfg, desc, reg_strings))
            result.extend(local_obfusc.analyse_method(cfg, desc, reg_strings))
            result.extend(local_deeplink.analyse_method(cfg, desc, reg_strings))
            result.extend(local_intent.analyse_method(cfg, desc, reg_strings))
            result.extend(local_logging.analyse_method(cfg, desc, reg_strings))
            result.extend(local_native.analyse_method(cfg, desc, reg_strings))
            return result

        findings: list[Finding] = []
        # Worker count: cap at CPU count (no point oversubscribing for
        # CPU-bound work — androguard's parser is the bottleneck, not I/O).
        # Floor at 2 so even single-core CI agents make progress, ceiling at 16
        # because androguard internals serialise past that point in practice.
        # APKANALYZER_WORKERS env var pins the count if you need a fixed
        # value (CI cost control, container CPU quotas).
        env_workers = os.environ.get("APKANALYZER_WORKERS")
        if env_workers and env_workers.isdigit() and int(env_workers) > 0:
            max_workers = max(1, min(int(env_workers), 64))
        else:
            cpu = os.cpu_count() or 2
            candidate_target = max(1, (len(self._candidates) // 50) + 1)
            max_workers = max(2, min(16, cpu, candidate_target * cpu))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for batch in concurrent.futures.as_completed(
                pool.submit(_analyse_method, c) for c in self._candidates
            ):
                try:
                    findings.extend(batch.result())
                except Exception as exc:
                    logger.debug("Method analysis error: %s", exc)

        # NSC XML analysis (single-threaded, XML parser not thread-safe)
        network_d = NetworkDetector()
        if self._ctx.network_security_config_xml:
            findings.extend(
                network_d.analyse_network_security_config(
                    self._ctx.network_security_config_xml,
                    self._ctx.manifest.get("package", ""),
                )
            )

        return findings

    def _run_manifest_checks(self) -> list[Finding]:
        findings: list[Finding] = []
        manifest = self._ctx.manifest
        findings.extend(StorageDetector().analyse_manifest(manifest))
        findings.extend(DeeplinkDetector().analyse_manifest(manifest))
        findings.extend(IntentDetector().analyse_manifest(manifest))
        findings.extend(PrivacyDetector().analyse_manifest(manifest))

        from apkanalyzer.ir.models import Severity, Confidence

        # Debuggable release
        if manifest.get("debuggable"):
            findings.append(Finding(
                rule_id="MANIFEST_DEBUGGABLE",
                title="Application is debuggable",
                description=(
                    "android:debuggable=true allows any user on the device to "
                    "attach a debugger, inspect memory, and extract sensitive data."
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category="MANIFEST",
                file_path="AndroidManifest.xml",
                evidence='android:debuggable="true"',
                remediation="Set android:debuggable=false in release manifests.",
                cwe_id="CWE-489",
                cvss=9.8,
            ))

        # Cleartext traffic
        if manifest.get("uses_cleartext_traffic"):
            findings.append(Finding(
                rule_id="MANIFEST_CLEARTEXT",
                title="usesCleartextTraffic=true in manifest",
                description=(
                    "The application allows cleartext HTTP traffic for all domains."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="NETWORK",
                file_path="AndroidManifest.xml",
                evidence='android:usesCleartextTraffic="true"',
                remediation='Set android:usesCleartextTraffic="false".',
                cwe_id="CWE-319",
                cvss=7.5,
            ))

        # Deep link hijacking
        for comp_list, label in [
            (manifest.get("exported_activities", []), "Activity"),
            (manifest.get("exported_services", []), "Service"),
        ]:
            for comp in comp_list:
                for dl in comp.get("deep_links", []):
                    scheme = dl.get("scheme", "")
                    # Custom schemes (not http/https) without permission are hijackable
                    if scheme and scheme not in ("http", "https") and not comp.get("permission"):
                        findings.append(Finding(
                            rule_id="DEEPLINK_UNPROTECTED",
                            title=f"Unprotected deep link scheme: {dl['uri']}",
                            description=(
                                f"The {label} {comp['name']} registers a custom URI "
                                f"scheme ({dl['uri']}) without a permission guard. "
                                "Any installed app can craft an Intent targeting this "
                                "component, enabling open redirect or data injection."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="DEEPLINK",
                            file_path="AndroidManifest.xml",
                            evidence=f"deep link: {dl['uri']} on {comp['name']}",
                            remediation=(
                                "Add android:permission to the component, or validate "
                                "all URI parameters before acting on them."
                            ),
                            cwe_id="CWE-601",
                            cvss=7.4,
                        ))

        # Exported components without permission
        for comp_list, label in [
            (manifest.get("exported_activities", []), "Activity"),
            (manifest.get("exported_services", []), "Service"),
            (manifest.get("exported_receivers", []), "BroadcastReceiver"),
            (manifest.get("exported_providers", []), "ContentProvider"),
        ]:
            for comp in comp_list:
                if not comp.get("permission"):
                    findings.append(Finding(
                        rule_id=f"MANIFEST_EXPORTED_{label.upper()}",
                        title=f"Exported {label} without permission restriction",
                        description=(
                            f"{comp['name']} is exported without a permission "
                            "requirement. Any app on the device can interact with it."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="MANIFEST",
                        file_path="AndroidManifest.xml",
                        evidence=f"<{label.lower()} android:name=\"{comp['name']}\" exported without permission>",
                        remediation=(
                            f"Add android:permission=\"…\" to the {label} element "
                            "or set exported=false if external access is not required."
                        ),
                        cwe_id="CWE-926",
                        cvss=6.5,
                    ))

        return findings

    def _run_secret_scan(self) -> list[Finding]:
        detector = SecretDetector()
        findings: list[Finding] = []

        # Scan DEX string pool
        findings.extend(
            detector.scan_string_pool(
                self._ctx.all_strings,
                source_hint=f"{self._ctx.manifest.get('package', 'unknown')} DEX",
            )
        )

        # Scan decompiled source files if available
        if self._ctx.unpacked_dir:
            source_dir = Path(self._ctx.unpacked_dir)
            for smali_file in source_dir.rglob("*.smali"):
                try:
                    content = smali_file.read_text(errors="replace")
                    rel_path = str(smali_file.relative_to(source_dir))
                    findings.extend(detector.scan_file(content, rel_path))
                except OSError:
                    pass

        return findings

    def _run_resource_scan(self) -> list[Finding]:
        try:
            return ResourceScanner().scan(self._ctx.unpacked_dir)
        except Exception as exc:
            logger.warning("ResourceScanner error: %s", exc)
            return []

    def _run_sdk_scan(self) -> list[Finding]:
        detector = SDKDetector()
        class_names = self._collect_class_names()
        pkg = self._ctx.manifest.get("package", "")
        return detector.analyse_classes(class_names, pkg)

    def _collect_class_names(self) -> list[str]:
        class_names: list[str] = []
        try:
            for cls in self._ctx.dx.get_classes():
                try:
                    class_names.append(cls.get_vm_class().get_name())
                except Exception:
                    pass
        except Exception:
            pass
        return class_names

    def _run_privacy_checks(self) -> list[Finding]:
        detector = PrivacyDetector()
        findings: list[Finding] = []
        for cfg, desc, rs in self._candidates:
            findings.extend(detector.analyse_method(cfg, desc, rs))
        return findings

    def _run_antianalysis_scan(self) -> list[Finding]:
        detector = AntiAnalysisDetector()
        findings: list[Finding] = []
        for cfg, desc, rs in self._candidates:
            findings.extend(detector.analyse_method(cfg, desc, rs))
        return findings

    def _run_yaml_rules(self) -> list[Finding]:
        """
        Run the YAML rule engine over decompiled smali. Skipped when apktool
        didn't produce output (no smali → nothing to grep).

        Reachable-class restriction prevents firing on dead code; existing
        rule IDs are passed in so the engine doesn't double-emit findings
        already produced by the high-fidelity detectors.
        """
        if not self._ctx.unpacked_dir:
            return []
        try:
            engine = RuleEngine()
        except Exception as exc:
            logger.warning("RuleEngine init failed: %s", exc)
            return []
        if not engine.rules:
            return []

        # Derive reachable_classes from the reachable-method set.
        # full_name is "Lcom/foo/Bar;->method()V" → class part is everything
        # before the "->".
        reachable_classes = {
            full.split("->", 1)[0]
            for full in self._last_reachable
        }
        existing_rule_ids = {f.rule_id for f in self._findings}
        try:
            return engine.scan_smali_dir(
                self._ctx.unpacked_dir,
                reachable_classes=reachable_classes or None,
                existing_rule_ids=existing_rule_ids,
            )
        except Exception as exc:
            logger.warning("RuleEngine scan failed: %s", exc)
            return []

    def _run_plugins(self) -> list[Finding]:
        plugins = load_plugins(self.plugins_dir)
        if not plugins:
            return []
        findings: list[Finding] = []
        class_names = self._collect_class_names()
        pkg = self._ctx.manifest.get("package", "")

        for plugin in plugins:
            try:
                findings.extend(plugin.analyse_manifest(self._ctx.manifest))
                findings.extend(plugin.analyse_classes(class_names, pkg))
                for cfg, desc, rs in self._candidates:
                    findings.extend(plugin.analyse_method(cfg, desc, rs))
            except Exception as exc:
                logger.warning("Plugin %s error: %s", plugin.name, exc)
        return findings

    # ------------------------------------------------------------------
    # Scoring + reporting
    # ------------------------------------------------------------------

    def _score_and_enrich(self) -> None:
        from apkanalyzer.ir.models import Confidence
        min_conf = Confidence[self.min_confidence_str.upper()]
        self._findings = filter_findings(self._findings, min_confidence=min_conf)

        # NOTE: MASVS profile filtering is intentionally NOT applied here.
        # main.py applies it post-cache so a single cached report can be
        # re-projected through different profiles (L1/L2/R) without re-scanning.
        # `self.masvs_profile` is retained on the constructor for API
        # compatibility and to make the requested profile observable to
        # embedders that might want to honour it.

        # Enrich with OWASP category and CVSS vector
        for f in self._findings:
            if not f.owasp_category:
                f.owasp_category = assign_owasp(f.rule_id, f.category)
            if not f.cvss_vector:
                tp = f.taint_path
                f.cvss_vector = assign_vector(
                    f.rule_id, f.severity,
                    tp.source.label if tp else "",
                    tp.sink.label if tp else "",
                )

    def _generate_reports(self) -> dict:
        summary = summarise(self._findings)
        metadata = {
            "apk_path": self.apk_path,
            "filename": Path(self.apk_path).name,
            "package": self._ctx.manifest.get("package", "unknown"),
            "min_sdk": self._ctx.manifest.get("min_sdk"),
            "target_sdk": self._ctx.manifest.get("target_sdk"),
            "permissions": self._ctx.manifest.get("permissions", []),
            "dangerous_permissions": self._ctx.manifest.get("dangerous_permissions", []),
            "analysis_duration_seconds": round(time.time() - self._start_time, 2),
        }

        report = {
            "metadata": metadata,
            "summary": summary,
            "findings": [f.to_dict() for f in self._findings],
        }

        # Write JSON
        json_path = self.output_dir / "report.json"
        JSONReporter().write(report, str(json_path))
        console.print(f"  JSON report → [cyan]{json_path}[/cyan]")

        # Write HTML
        html_path = self.output_dir / "report.html"
        HTMLReporter().write(report, str(html_path))
        console.print(f"  HTML report → [cyan]{html_path}[/cyan]")

        return report

    def _print_summary(self, summary: dict) -> None:
        sev = summary["by_severity"]
        console.print(
            f"  [red]CRITICAL {sev.get('CRITICAL', 0)}[/red]  "
            f"[yellow]HIGH {sev.get('HIGH', 0)}[/yellow]  "
            f"[blue]MEDIUM {sev.get('MEDIUM', 0)}[/blue]  "
            f"[green]LOW {sev.get('LOW', 0)}[/green]"
        )
