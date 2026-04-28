#!/usr/bin/env python3
"""
APKAnalyzer CLI

Usage
-----
  apkanalyzer scan app.apk
  apkanalyzer scan app.apk --output ./reports --confidence HIGH
  apkanalyzer scan app.apk --no-apktool --taint-depth 5
  apkanalyzer demo
"""

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
    # Suppress noisy third-party loggers
    for name in ("androguard", "androguard.core", "lxml"):
        logging.getLogger(name).setLevel(logging.ERROR)


@click.group()
def cli():
    """APKAnalyzer — advanced static analysis for Android APKs."""


_SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


@cli.command()
@click.argument("apk_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", default="./apkanalyzer_report", help="Output directory")
@click.option(
    "--confidence", "-c",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    help="Minimum confidence level to include in report",
)
@click.option("--no-apktool", is_flag=True, help="Skip apktool resource unpacking")
@click.option(
    "--taint-depth",
    default=None, type=int,
    help="Max call depth for taint analysis (default: package DEFAULT_TAINT_DEPTH)",
)
@click.option(
    "--format", "-f", "output_format",
    type=click.Choice(["json", "html", "sarif", "frida", "all"], case_sensitive=False),
    default="all",
    help="Output format (default: all)",
)
@click.option("--no-cache", is_flag=True, help="Skip incremental scan cache")
@click.option("--plugins-dir", default=None, help="Directory containing custom detector plugins")
@click.option(
    "--sources", "extra_source_files", multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="JSON/YAML file(s) with extra TaintSource specs (repeatable).",
)
@click.option(
    "--sinks", "extra_sink_files", multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="JSON/YAML file(s) with extra TaintSink specs (repeatable).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "NEVER"],
                      case_sensitive=False),
    default="HIGH",
    help="Exit non-zero if any finding at this severity or higher is present "
         "(default: HIGH). Use NEVER to always exit 0.",
)
@click.option(
    "--masvs",
    type=click.Choice(["L1", "L2", "R"], case_sensitive=False),
    default=None,
    help="Restrict the report to findings relevant to the given MASVS profile.",
)
@click.option(
    "--baseline",
    type=click.Path(dir_okay=False),
    default=None,
    help="Baseline JSON/SARIF file. Findings already present are marked as known.",
)
@click.option(
    "--fail-on-new", is_flag=True,
    help="With --baseline, exit non-zero only if NEW findings appear "
         "(supersedes --fail-on).",
)
@click.option(
    "--write-baseline",
    type=click.Path(dir_okay=False),
    default=None,
    help="Write the current run's findings as a baseline file (JSON list of fingerprints).",
)
@click.option("--verbose", "-v", is_flag=True)
def scan(apk_path, output, confidence, no_apktool, taint_depth, output_format,
         no_cache, plugins_dir, extra_source_files, extra_sink_files,
         fail_on, masvs, baseline, fail_on_new, write_baseline, verbose):
    """Scan an APK for security vulnerabilities."""
    _setup_logging(verbose)
    from apkanalyzer import DEFAULT_TAINT_DEPTH
    from apkanalyzer.cache.scan_cache import ScanCache
    from apkanalyzer.reporting.sarif_reporter import SARIFReporter
    from apkanalyzer.reporting.frida_generator import FridaGenerator
    from apkanalyzer.reporting.baseline import (
        load_baseline, split_findings, fingerprint_finding,
    )
    from apkanalyzer.scoring.masvs import filter_by_profile
    from apkanalyzer.analysis.taint.loader import load_specs
    from pathlib import Path as _Path

    console.print(f"\n[bold]APKAnalyzer[/bold] — scanning [cyan]{apk_path}[/cyan]\n")

    out_dir = _Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    if taint_depth is None:
        taint_depth = DEFAULT_TAINT_DEPTH

    extra_sources, extra_sinks, extra_sanitizers = load_specs(
        list(extra_source_files) + list(extra_sink_files),
    )

    pipeline_kwargs = dict(
        confidence=confidence,
        no_apktool=no_apktool,
        taint_depth=taint_depth,
        verbose=verbose,
        plugins_dir=plugins_dir,
        extra_sources=extra_sources,
        extra_sinks=extra_sinks,
        extra_sanitizers=extra_sanitizers,
        masvs_profile=masvs,
    )

    # Cache: include extra-spec fingerprints in the cache key by skipping the
    # cache when user-supplied specs are present (they're typically transient
    # and not worth a more elaborate cache-key).
    use_cache = not no_cache and not (extra_sources or extra_sinks or extra_sanitizers)
    if use_cache:
        cache = ScanCache()
        cached = cache.get(apk_path)
        if cached:
            console.print("[green]Cache hit[/green] — returning cached report\n")
            report = cached
        else:
            report = _run_pipeline(apk_path, output, **pipeline_kwargs)
            if report is not None:
                cache.put(apk_path, report)
    else:
        report = _run_pipeline(apk_path, output, **pipeline_kwargs)

    if report is None:
        sys.exit(1)

    # Apply MASVS profile filtering (post-cache so a single cached run can be
    # re-projected through different profiles without re-analysing).
    if masvs:
        before = len(report["findings"])
        report["findings"] = filter_by_profile(report["findings"], masvs)
        console.print(
            f"  MASVS [{masvs.upper()}] filter: {before} → {len(report['findings'])} findings"
        )

    # Baseline diff
    new_findings: list = []
    known_findings: list = []
    if baseline:
        baseline_fps = load_baseline(baseline)
        new_findings, known_findings = split_findings(report["findings"], baseline_fps)
        console.print(
            f"  Baseline: [green]{len(known_findings)} known[/green] / "
            f"[red]{len(new_findings)} new[/red]"
        )
        # Mark known findings in the report so the HTML/SARIF can grey them out
        for f in known_findings:
            f["baseline_status"] = "known"
        for f in new_findings:
            f["baseline_status"] = "new"

    fmt = output_format.lower()
    if fmt in ("sarif", "all"):
        sarif_path = out_dir / "report.sarif"
        SARIFReporter().write(report, str(sarif_path))
        console.print(f"  SARIF report → [cyan]{sarif_path}[/cyan]")

    if fmt in ("frida", "all"):
        frida_path = out_dir / "hooks.js"
        FridaGenerator().write(report, str(frida_path))
        console.print(f"  Frida hooks  → [cyan]{frida_path}[/cyan]")

    if write_baseline:
        import json as _json
        fps = sorted({fingerprint_finding(f) for f in report["findings"]})
        _Path(write_baseline).write_text(_json.dumps(fps, indent=2), encoding="utf-8")
        console.print(f"  Baseline written → [cyan]{write_baseline}[/cyan] ({len(fps)} fingerprints)")

    grade = report["summary"].get("risk_grade", "?")
    console.print(f"\n  Risk Grade: [bold]{grade}[/bold]")

    sys.exit(_compute_exit_code(report, fail_on, fail_on_new, new_findings, baseline))


def _compute_exit_code(
    report: dict,
    fail_on: str,
    fail_on_new: bool,
    new_findings: list,
    baseline: str | None,
) -> int:
    """
    Decide the process exit code.

    Precedence:
      1. --fail-on-new (with --baseline): exit 1 iff there is at least one new
         finding at or above --fail-on threshold (default HIGH).
      2. Otherwise: exit 1 iff any finding at or above --fail-on is present.
      3. --fail-on NEVER: always 0.
    """
    fail_on = fail_on.upper()
    if fail_on == "NEVER":
        return 0
    threshold = _SEVERITY_RANK[fail_on]

    pool = (new_findings if (fail_on_new and baseline) else report.get("findings", []))
    for f in pool:
        sev = f.get("severity", "INFO") if isinstance(f, dict) else getattr(f, "severity", "INFO")
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        if _SEVERITY_RANK.get(sev_str.upper(), 0) >= threshold:
            return 1
    return 0


def _run_pipeline(apk_path, output, confidence, no_apktool, taint_depth, verbose,
                  plugins_dir=None, extra_sources=None, extra_sinks=None,
                  extra_sanitizers=None, masvs_profile=None):
    from apkanalyzer.pipeline.orchestrator import AnalysisPipeline
    pipeline = AnalysisPipeline(
        apk_path=apk_path,
        output_dir=output,
        min_confidence=confidence,
        run_apktool=not no_apktool,
        taint_depth=taint_depth,
        plugins_dir=plugins_dir,
        extra_sources=extra_sources,
        extra_sinks=extra_sinks,
        extra_sanitizers=extra_sanitizers,
        masvs_profile=masvs_profile,
    )
    try:
        return pipeline.run()
    except Exception as exc:
        console.print(f"[red]Analysis failed:[/red] {exc}")
        if verbose:
            console.print_exception()
        return None


@cli.command()
@click.argument("apk_paths", nargs=-1, type=click.Path(exists=True, dir_okay=False), required=True)
@click.option("--output", "-o", default="./apkanalyzer_batch", help="Output directory")
@click.option("--confidence", "-c",
              type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
              default="LOW")
@click.option("--workers", "-w", default=4, help="Parallel workers (default: 4)")
@click.option("--plugins-dir", default=None, help="Directory containing custom detector plugins")
@click.option("--verbose", "-v", is_flag=True)
def batch(apk_paths, output, confidence, workers, plugins_dir, verbose):
    """Scan multiple APKs in parallel and produce a comparative HTML table."""
    _setup_logging(verbose)
    import concurrent.futures
    from pathlib import Path as _Path
    from apkanalyzer.reporting.json_reporter import JSONReporter

    out_dir = _Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]APKAnalyzer Batch[/bold] — {len(apk_paths)} APKs, {workers} workers\n")

    def _scan_one(apk_path):
        apk_out = out_dir / _Path(apk_path).stem
        report = _run_pipeline(
            apk_path, str(apk_out), confidence, False, 6, verbose, plugins_dir,
        )
        return apk_path, report

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, p): p for p in apk_paths}
        for future in concurrent.futures.as_completed(futures):
            apk_path, report = future.result()
            name = _Path(apk_path).name
            if report:
                s = report["summary"]
                grade = s.get("risk_grade", "?")
                console.print(
                    f"  [cyan]{name}[/cyan] — Grade [bold]{grade}[/bold] | "
                    f"[red]C:{s['by_severity'].get('CRITICAL',0)}[/red] "
                    f"[yellow]H:{s['by_severity'].get('HIGH',0)}[/yellow] "
                    f"M:{s['by_severity'].get('MEDIUM',0)} "
                    f"Total:{s['total']}"
                )
                results.append((name, report))
            else:
                console.print(f"  [red]FAILED[/red] {name}")

    # Write combined JSON
    combined = {
        "apks": [
            {"filename": name, "summary": r["summary"], "metadata": r["metadata"]}
            for name, r in results
        ]
    }
    JSONReporter().write(combined, str(out_dir / "batch_summary.json"))

    # Write comparative HTML table
    _write_batch_html(results, str(out_dir / "batch_report.html"))
    console.print(f"\n  Batch report → [cyan]{out_dir / 'batch_report.html'}[/cyan]")
    console.print(f"  JSON summary → [cyan]{out_dir / 'batch_summary.json'}[/cyan]")

    any_critical = any(
        r["summary"]["by_severity"].get("CRITICAL", 0) > 0
        for _, r in results if r
    )
    sys.exit(1 if any_critical else 0)


def _write_batch_html(results: list, path: str) -> None:
    from pathlib import Path as _Path
    rows = ""
    grade_colors = {"A": "#00b894", "B": "#00cec9", "C": "#fdcb6e", "D": "#e17055", "F": "#d63031"}
    for name, report in results:
        s = report["summary"]
        m = report.get("metadata", {})
        grade = s.get("risk_grade", "?")
        gc = grade_colors.get(grade, "#999")
        rows += f"""<tr>
          <td>{name}</td>
          <td>{m.get('package','')}</td>
          <td><strong style="color:{gc}">{grade}</strong></td>
          <td style="color:#d63031">{s['by_severity'].get('CRITICAL',0)}</td>
          <td style="color:#e17055">{s['by_severity'].get('HIGH',0)}</td>
          <td style="color:#fdcb6e">{s['by_severity'].get('MEDIUM',0)}</td>
          <td>{s['by_severity'].get('LOW',0)}</td>
          <td>{s['total']}</td>
          <td>{m.get('target_sdk','?')}</td>
          <td>{m.get('analysis_duration_seconds','?')}s</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APKAnalyzer Batch Report</title>
<style>
  body {{background:#0d1117;color:#c9d1d9;font:14px/1.6 'Segoe UI',system-ui,sans-serif;margin:0;}}
  header {{background:#161b22;border-bottom:1px solid #30363d;padding:20px 32px;}}
  h1 {{font-size:20px;margin:0;}}
  .container {{max-width:1200px;margin:0 auto;padding:24px 32px;}}
  table {{width:100%;border-collapse:collapse;}}
  th {{text-align:left;padding:10px 12px;font-size:11px;text-transform:uppercase;
       color:#8b949e;background:#161b22;border-bottom:1px solid #30363d;}}
  td {{padding:10px 12px;border-bottom:1px solid #30363d;font-size:13px;}}
  tr:hover td {{background:rgba(255,255,255,.02);}}
  input {{background:#161b22;border:1px solid #30363d;border-radius:6px;
          padding:6px 12px;color:#c9d1d9;font-size:13px;width:300px;margin-bottom:16px;}}
</style>
</head>
<body>
<header><h1>APKAnalyzer Batch Report — {len(results)} APKs</h1></header>
<div class="container">
  <input type="text" placeholder="Filter…" oninput="
    const q=this.value.toLowerCase();
    document.querySelectorAll('tbody tr').forEach(r=>{{
      r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';
    }});">
  <table>
    <thead><tr>
      <th>File</th><th>Package</th><th>Grade</th>
      <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
      <th>Total</th><th>Target SDK</th><th>Duration</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
</body>
</html>"""
    _Path(path).write_text(html, encoding="utf-8")


@cli.command()
@click.argument("old_apk", type=click.Path(exists=True, dir_okay=False))
@click.argument("new_apk", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", "-o", default="./apkanalyzer_diff", help="Output directory")
@click.option("--confidence", "-c",
              type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
              default="LOW")
@click.option("--verbose", "-v", is_flag=True)
def compare(old_apk, new_apk, output, confidence, verbose):
    """Compare two APK versions and report new/fixed/changed findings."""
    _setup_logging(verbose)
    from apkanalyzer.pipeline.orchestrator import AnalysisPipeline
    from apkanalyzer.reporting.diff_reporter import diff_reports, DiffHTMLReporter
    from apkanalyzer.reporting.json_reporter import JSONReporter
    from pathlib import Path as _Path
    import json

    out_dir = _Path(output)
    out_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"\n[bold]APKAnalyzer Compare[/bold]\n"
                  f"  old: [cyan]{old_apk}[/cyan]\n"
                  f"  new: [cyan]{new_apk}[/cyan]\n")

    console.print("[bold blue]Scanning old APK…[/bold blue]")
    old_report = _run_pipeline(old_apk, str(out_dir / "old"), confidence, False, 8, verbose)
    if old_report is None:
        sys.exit(1)

    console.print("[bold blue]Scanning new APK…[/bold blue]")
    new_report = _run_pipeline(new_apk, str(out_dir / "new"), confidence, False, 8, verbose)
    if new_report is None:
        sys.exit(1)

    diff = diff_reports(old_report, new_report)
    s = diff.summary()

    console.print(
        f"\n[bold]Diff complete[/bold] — "
        f"[red]NEW: {s['new']}[/red]  "
        f"[green]FIXED: {s['fixed']}[/green]  "
        f"[yellow]CHANGED: {s['changed']}[/yellow]  "
        f"UNCHANGED: {s['unchanged']}"
    )

    json_path = out_dir / "diff.json"
    JSONReporter().write(diff.to_dict(), str(json_path))
    console.print(f"  JSON diff  → [cyan]{json_path}[/cyan]")

    html_path = out_dir / "diff.html"
    DiffHTMLReporter().write(diff, old_report["metadata"], new_report["metadata"], str(html_path))
    console.print(f"  HTML diff  → [cyan]{html_path}[/cyan]")

    sys.exit(1 if s["regression"] else 0)


@cli.command()
def demo():
    """Run a self-contained demo using a synthetic test case (no APK required)."""
    _setup_logging(False)
    _run_demo()


def _run_demo():
    """
    Demo mode: exercise all analysis modules with synthetic data.
    Useful for verifying the installation without a real APK.
    """
    from apkanalyzer.analysis.detectors.secret_detector import SecretDetector
    from apkanalyzer.analysis.detectors.crypto_detector import CryptoDetector
    from apkanalyzer.ir.models import MethodDescriptor, CFGMethod, BasicBlock
    from apkanalyzer.scoring.confidence import filter_findings, summarise, Confidence

    console.print("\n[bold]APKAnalyzer Demo[/bold] — synthetic analysis\n")

    # 1. Secret detection
    console.print("[blue]── Secret Detector ──[/blue]")
    detector = SecretDetector()
    test_strings = [
        'AKIAIOSFODNN7EXAMPLE',            # AWS key ID
        'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3ns',  # Google API key
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abc123xyz',  # JWT
        'the quick brown fox',             # not a secret
        '00000000-0000-0000-0000-000000000000',  # UUID — not a secret
        'BEGIN RSA PRIVATE KEY',
    ]
    secret_findings = detector.scan_string_pool(test_strings, "<demo>")
    console.print(f"  Found {len(secret_findings)} secrets in {len(test_strings)} strings")
    for f in secret_findings:
        console.print(f"  [{f.severity.value}] {f.title}")

    # 2. Crypto detector — synthetic CFG
    console.print("\n[blue]── Crypto Detector ──[/blue]")
    crypto = CryptoDetector()
    desc = MethodDescriptor("Lcom/example/Crypto;", "doEncrypt", "(Ljava/lang/String;)V")
    cfg = CFGMethod(descriptor=desc)

    block = BasicBlock(block_id="0", method=desc)
    block.instructions = [
        {
            "offset": 0,
            "mnemonic": "const-string",
            "operands": [{"kind": 0, "value": "v1", "raw": "v1"},
                         {"kind": 2, "value": "AES/ECB/PKCS5Padding", "raw": '"AES/ECB/PKCS5Padding"'}],
            "raw": 'const-string v1, "AES/ECB/PKCS5Padding"',
        },
        {
            "offset": 4,
            "mnemonic": "invoke-static",
            "operands": [],
            "raw": 'invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;',
        },
    ]
    cfg.blocks["0"] = block
    cfg.entry_block = "0"

    reg_strings = {"v1": "AES/ECB/PKCS5Padding"}
    crypto_findings = crypto.analyse(cfg, desc, reg_strings)
    console.print(f"  Found {len(crypto_findings)} crypto issues")
    for f in crypto_findings:
        console.print(f"  [{f.severity.value}] {f.title}")

    # 3. Scoring/filter
    all_findings = secret_findings + crypto_findings
    filtered = filter_findings(all_findings, min_confidence=Confidence.LOW)
    summary = summarise(filtered)

    console.print(f"\n[green]Demo complete.[/green] "
                  f"Total findings: {summary['total']} | "
                  f"CRITICAL: {summary['by_severity']['CRITICAL']} | "
                  f"HIGH: {summary['by_severity']['HIGH']}")


if __name__ == "__main__":
    cli()
