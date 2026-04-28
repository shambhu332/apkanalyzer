"""
Differential reporter: compare two APK scan reports.

Classifies findings as:
  NEW      — present in new_report, absent from old_report (regression)
  FIXED    — present in old_report, absent from new_report (improvement)
  CHANGED  — same rule_id + location, but severity or confidence differs
  UNCHANGED — identical in both reports

A finding is identified by (rule_id, class, method, category) to be robust
to minor offset changes between APK versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DiffEntry:
    status: str          # NEW | FIXED | CHANGED | UNCHANGED
    finding: dict        # finding dict from whichever report is relevant
    old_finding: Optional[dict] = None  # populated for CHANGED


@dataclass
class DiffReport:
    new_findings: list[DiffEntry] = field(default_factory=list)
    fixed_findings: list[DiffEntry] = field(default_factory=list)
    changed_findings: list[DiffEntry] = field(default_factory=list)
    unchanged_findings: list[DiffEntry] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "new": len(self.new_findings),
            "fixed": len(self.fixed_findings),
            "changed": len(self.changed_findings),
            "unchanged": len(self.unchanged_findings),
            "regression": len(self.new_findings) > 0,
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "new": [e.finding for e in self.new_findings],
            "fixed": [e.finding for e in self.fixed_findings],
            "changed": [
                {"new": e.finding, "old": e.old_finding}
                for e in self.changed_findings
            ],
        }


def _finding_key(f: dict) -> tuple:
    loc = f.get("location", {})
    return (
        f.get("rule_id", ""),
        loc.get("class", ""),
        loc.get("method", ""),
        f.get("category", ""),
    )


def diff_reports(old_report: dict, new_report: dict) -> DiffReport:
    """
    Compare two report dicts (as produced by AnalysisPipeline or cached).

    Returns a DiffReport classifying every finding.
    """
    old_findings = {_finding_key(f): f for f in old_report.get("findings", [])}
    new_findings = {_finding_key(f): f for f in new_report.get("findings", [])}

    result = DiffReport()

    for key, new_f in new_findings.items():
        if key not in old_findings:
            result.new_findings.append(DiffEntry(status="NEW", finding=new_f))
        else:
            old_f = old_findings[key]
            if (old_f.get("severity") != new_f.get("severity") or
                    old_f.get("confidence") != new_f.get("confidence")):
                result.changed_findings.append(
                    DiffEntry(status="CHANGED", finding=new_f, old_finding=old_f)
                )
            else:
                result.unchanged_findings.append(DiffEntry(status="UNCHANGED", finding=new_f))

    for key, old_f in old_findings.items():
        if key not in new_findings:
            result.fixed_findings.append(DiffEntry(status="FIXED", finding=old_f))

    return result


class DiffHTMLReporter:
    """Produce a self-contained HTML diff report."""

    def write(self, diff: DiffReport, old_meta: dict, new_meta: dict, path: str) -> None:
        from pathlib import Path

        s = diff.summary()
        old_pkg = old_meta.get("package", "old")
        new_pkg = new_meta.get("package", "new")

        def _sev_badge(f):
            sev = f.get("severity", "INFO")
            color = {"CRITICAL": "#d63031", "HIGH": "#e17055", "MEDIUM": "#fdcb6e",
                     "LOW": "#00b894", "INFO": "#74b9ff"}.get(sev, "#999")
            return f'<span style="background:{color};color:#fff;padding:1px 7px;border-radius:3px;font-size:11px;">{sev}</span>'

        def _rows(entries, color):
            if not entries:
                return f'<tr><td colspan="4" style="color:#8b949e;padding:12px;">None</td></tr>'
            rows = ""
            for e in entries:
                f = e.finding
                loc = f.get("location", {})
                rows += f"""<tr style="border-bottom:1px solid #30363d;">
                  <td style="padding:8px 12px;">{_sev_badge(f)}</td>
                  <td style="padding:8px 12px;">{f.get('title','')}</td>
                  <td style="padding:8px 12px;font-size:11px;font-family:monospace;">{loc.get('class','')}</td>
                  <td style="padding:8px 12px;font-size:11px;">{f.get('rule_id','')}</td>
                </tr>"""
            return rows

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APKAnalyzer Diff — {old_pkg} → {new_pkg}</title>
<style>
  body {{background:#0d1117;color:#c9d1d9;font:14px/1.6 'Segoe UI',system-ui,sans-serif;margin:0;}}
  header {{background:#161b22;border-bottom:1px solid #30363d;padding:20px 32px;}}
  h1 {{font-size:20px;margin:0 0 4px;}}
  .meta {{color:#8b949e;font-size:12px;}}
  .container {{max-width:1280px;margin:0 auto;padding:24px 32px;}}
  .cards {{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px;}}
  .card {{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center;}}
  .card .n {{font-size:32px;font-weight:700;}}
  .card .l {{font-size:11px;text-transform:uppercase;color:#8b949e;}}
  .card.new .n {{color:#d63031;}} .card.fixed .n {{color:#00b894;}}
  .card.changed .n {{color:#fdcb6e;}} .card.unchanged .n {{color:#8b949e;}}
  h2 {{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #30363d;padding-bottom:6px;}}
  table {{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;}}
  th {{text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;color:#8b949e;background:#0d1117;}}
</style>
</head>
<body>
<header>
  <h1>APKAnalyzer Differential Report</h1>
  <div class="meta">
    Old: <strong>{old_pkg}</strong> (SDK {old_meta.get('target_sdk','?')}) &nbsp;→&nbsp;
    New: <strong>{new_pkg}</strong> (SDK {new_meta.get('target_sdk','?')})
  </div>
</header>
<div class="container">
  <div class="cards">
    <div class="card new"><div class="n">{s['new']}</div><div class="l">New (Regressions)</div></div>
    <div class="card fixed"><div class="n">{s['fixed']}</div><div class="l">Fixed</div></div>
    <div class="card changed"><div class="n">{s['changed']}</div><div class="l">Changed</div></div>
    <div class="card unchanged"><div class="n">{s['unchanged']}</div><div class="l">Unchanged</div></div>
  </div>

  <h2>🔴 New Findings (Regressions)</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Class</th><th>Rule ID</th></tr>
    {_rows(diff.new_findings, '#d63031')}
  </table>

  <h2>🟢 Fixed Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Class</th><th>Rule ID</th></tr>
    {_rows(diff.fixed_findings, '#00b894')}
  </table>

  <h2>🟡 Changed Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Class</th><th>Rule ID</th></tr>
    {_rows(diff.changed_findings, '#fdcb6e')}
  </table>
</div>
</body>
</html>"""

        Path(path).write_text(html, encoding="utf-8")
