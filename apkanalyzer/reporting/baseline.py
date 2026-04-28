"""
Baseline support for CI integrations.

A baseline is a previously-saved JSON or SARIF report that represents the
"already-accepted" set of findings. New findings are those whose fingerprint
is not in the baseline; --fail-on-new exits non-zero only on those.

Fingerprint
-----------
We deliberately do not include line numbers in the fingerprint. Refactors
that move a method by a few lines should not invalidate a baseline. The
fingerprint is:

    sha1(rule_id | class_name | method_name | evidence_normalized)

where evidence_normalized strips offset numbers like "@offset 12" so a
re-built APK with shifted bytecode offsets still matches.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

_OFFSET_PATTERN = re.compile(r"@offset \d+")
_HEX_OFFSET_PATTERN = re.compile(r"0x[0-9a-fA-F]+")


def _normalize_evidence(evidence: str) -> str:
    if not evidence:
        return ""
    s = _OFFSET_PATTERN.sub("@offset N", evidence)
    s = _HEX_OFFSET_PATTERN.sub("0xN", s)
    return s.strip()


def fingerprint_finding(finding: dict) -> str:
    """Stable fingerprint, robust to trivial code movement."""
    rule = finding.get("rule_id", "")
    cls = finding.get("class_name") or finding.get("location", {}).get("class", "")
    method = finding.get("method_name") or finding.get("location", {}).get("method", "")
    evidence = _normalize_evidence(finding.get("evidence", ""))
    raw = f"{rule}|{cls}|{method}|{evidence}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def load_baseline(path: str) -> set[str]:
    """
    Load a baseline file and return the set of fingerprints it contains.

    Accepts either:
      - APKAnalyzer JSON report (dict with "findings" list)
      - SARIF 2.1.0 (dict with "runs" → "results")
      - Plain JSON list of fingerprints
    """
    p = Path(path)
    if not p.is_file():
        return set()
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return set()

    if isinstance(data, list):
        # Assume list-of-fingerprints
        return {str(x) for x in data if isinstance(x, str)}

    if isinstance(data, dict) and "findings" in data:
        return {fingerprint_finding(f) for f in data["findings"]}

    if isinstance(data, dict) and "runs" in data:
        # SARIF — synthesise findings dicts from results
        out: set[str] = set()
        for run in data.get("runs", []):
            for r in run.get("results", []):
                # Pull class/method out of the SARIF location URI when possible
                loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                uri = loc.get("artifactLocation", {}).get("uri", "")
                # uri looks like com/example/Foo.smali — convert back to
                # a Dalvik-ish class descriptor for fingerprint stability
                cls = ""
                if uri.endswith(".smali"):
                    cls = "L" + uri[:-6] + ";"
                msg = r.get("message", {}).get("text", "")
                # Evidence line embedded in message after "Evidence:"
                evidence = ""
                for line in msg.splitlines():
                    if line.startswith("Evidence:"):
                        evidence = line[len("Evidence:"):].strip()
                        break
                synthetic = {
                    "rule_id": r.get("ruleId", ""),
                    "class_name": cls,
                    "method_name": "",
                    "evidence": evidence,
                }
                out.add(fingerprint_finding(synthetic))
        return out

    return set()


def split_findings(findings: list[dict], baseline: set[str]) -> tuple[list[dict], list[dict]]:
    """
    Partition findings into (new, known) based on the baseline fingerprints.

    Returns
    -------
    new_findings : findings whose fingerprint is NOT in the baseline
    known_findings : findings whose fingerprint IS in the baseline
    """
    new_findings: list[dict] = []
    known_findings: list[dict] = []
    for f in findings:
        fp = fingerprint_finding(f)
        if fp in baseline:
            known_findings.append(f)
        else:
            new_findings.append(f)
    return new_findings, known_findings
