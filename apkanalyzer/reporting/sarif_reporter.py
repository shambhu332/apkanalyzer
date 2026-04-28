"""
SARIF 2.1.0 reporter for GitHub / GitLab Code Scanning integration.

Produces a file that can be uploaded to GitHub Actions as a code-scanning result,
causing findings to appear as inline annotations on pull requests.

Usage (GitHub Actions):
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: apkanalyzer_report.sarif
"""

from __future__ import annotations

import json
from pathlib import Path

from apkanalyzer.reporting.baseline import fingerprint_finding

# main.py marks each finding with one of these tags before emitting SARIF.
# We map them onto SARIF 2.1.0 §3.27.23 `result.baselineState` values so
# Code Scanning UIs can show "new alerts only" filters correctly.
_BASELINE_STATE_MAP = {
    "new": "new",
    "known": "unchanged",
}


_TOOL_NAME = "APKAnalyzer"
_TOOL_VERSION = "1.0.0"
_TOOL_URI = "https://github.com/yourorg/apkanalyzer"

_SEVERITY_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

_CONFIDENCE_TO_SARIF = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _make_rule(finding: dict) -> dict:
    return {
        "id": finding["rule_id"],
        "name": finding["rule_id"].replace("_", " ").title(),
        "shortDescription": {"text": finding["title"]},
        "fullDescription": {"text": finding.get("description", finding["title"])},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.get('cwe_id','').replace('CWE-','')}.html"
                   if finding.get("cwe_id") else _TOOL_URI,
        "properties": {
            "tags": [finding.get("category", "GENERAL")],
            "precision": _CONFIDENCE_TO_SARIF.get(finding.get("confidence", "LOW"), "low"),
            "problem.severity": _SEVERITY_TO_SARIF.get(finding.get("severity", "MEDIUM"), "warning"),
            "security-severity": str(finding.get("cvss", 0.0)),
        },
        "defaultConfiguration": {
            "level": _SEVERITY_TO_SARIF.get(finding.get("severity", "MEDIUM"), "warning"),
        },
    }


def _make_result(finding: dict, rule_index: int) -> dict:
    loc = finding.get("location", {})
    file_path = loc.get("file") or loc.get("class", "").replace("L", "").replace(";", "").replace("/", "/") + ".smali"
    line = loc.get("line") or 1

    message_text = finding["title"]
    if finding.get("evidence"):
        message_text += f"\n\nEvidence: {finding['evidence']}"
    if finding.get("remediation"):
        message_text += f"\n\nRemediation: {finding['remediation']}"
    if finding.get("cwe_id"):
        message_text += f"\n\nCWE: {finding['cwe_id']}"

    result: dict = {
        "ruleId": finding["rule_id"],
        "ruleIndex": rule_index,
        "level": _SEVERITY_TO_SARIF.get(finding.get("severity", "MEDIUM"), "warning"),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path or "unknown",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(1, line),
                    },
                }
            }
        ],
        "properties": {
            "confidence": finding.get("confidence", "LOW"),
            "category": finding.get("category", ""),
        },
    }

    # Stable per-result fingerprint — lets Code Scanning correlate findings
    # across runs even when the result list re-orders or line numbers shift.
    fp = fingerprint_finding(finding)
    result["partialFingerprints"] = {"apkanalyzer/v1": fp}

    # baselineState is the SARIF-native way to signal "this is a new
    # alert" vs. "this was here last time". main.py annotates each finding
    # with baseline_status when --baseline is passed; if it's absent, we
    # omit the field entirely (per the SARIF spec — emitting "absent"
    # means the result is gone, which would be wrong).
    bstate = _BASELINE_STATE_MAP.get(finding.get("baseline_status"))
    if bstate:
        result["baselineState"] = bstate

    if finding.get("taint_flow"):
        tf = finding["taint_flow"]
        result["codeFlows"] = [
            {
                "message": {"text": "Taint flow: source → sink"},
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "message": {"text": f"Source: {tf['source']['label']} @ {tf['source']['method']}"},
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "unknown", "uriBaseId": "%SRCROOT%"},
                                        "region": {"startLine": 1},
                                    },
                                }
                            },
                            {
                                "location": {
                                    "message": {"text": f"Sink: {tf['sink']['label']} @ {tf['sink']['method']}"},
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "unknown", "uriBaseId": "%SRCROOT%"},
                                        "region": {"startLine": 1},
                                    },
                                }
                            },
                        ]
                    }
                ],
            }
        ]

    return result


class SARIFReporter:
    def write(self, report: dict, path: str) -> None:
        findings = report.get("findings", [])

        # Deduplicate rules by rule_id
        seen_rules: dict[str, int] = {}
        rules = []
        for f in findings:
            rid = f["rule_id"]
            if rid not in seen_rules:
                seen_rules[rid] = len(rules)
                rules.append(_make_rule(f))

        results = [_make_result(f, seen_rules[f["rule_id"]]) for f in findings]

        meta = report.get("metadata", {})
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": _TOOL_URI,
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "properties": {
                        "apk_package": meta.get("package", "unknown"),
                        "target_sdk": str(meta.get("target_sdk", "")),
                        "min_sdk": str(meta.get("min_sdk", "")),
                        "risk_grade": report.get("summary", {}).get("risk_grade", ""),
                        "total_findings": report.get("summary", {}).get("total", 0),
                    },
                }
            ],
        }

        Path(path).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
