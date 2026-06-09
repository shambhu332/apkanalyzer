"""
Quark-style malware behaviour scoring.

Single-finding severity tells you "this rule fired"; behaviour scoring
tells you "this *combination* of rules fired together looks like X".
The Quark engine does this by weighting groups of API calls; we do the
same against the rule_id / category surface that our detectors expose.

Output is a list of `BehaviorScore` objects, attached to the report
under `malware_behaviors`. The HTML reporter surfaces a banner when any
HIGH/CRITICAL behaviour is detected.

Adding a behaviour: append a `BehaviorRule` whose `components` list maps
required signal -> 1+ matching predicates (substring/category match).
A behaviour fires only when *every* component slot has at least one
matching finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from apkanalyzer.ir.models import Finding


@dataclass(frozen=True)
class BehaviorComponent:
    """One required signal in a behavior. Matches a finding by substring of
    `rule_id` OR exact `category` match. Either field may be empty (the
    other still has to match)."""
    rule_id_substr: str = ""
    category: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.category and finding.category != self.category:
            return False
        if self.rule_id_substr and self.rule_id_substr not in finding.rule_id:
            return False
        return bool(self.rule_id_substr or self.category)


@dataclass(frozen=True)
class BehaviorRule:
    """A weighted combination of required components."""
    name: str
    description: str
    weight: int
    components: tuple[BehaviorComponent, ...]
    mitre_tactic: str = ""

    def evaluate(self, findings: Sequence[Finding]) -> list[Finding]:
        """Return the matching findings for every component, or [] if any
        component has no match (behaviour does not fire)."""
        matched: list[Finding] = []
        for comp in self.components:
            hit = next((f for f in findings if comp.matches(f)), None)
            if hit is None:
                return []
            matched.append(hit)
        return matched


@dataclass
class BehaviorScore:
    """A behaviour that fired, with the findings that triggered it and a
    severity bucket derived from the cumulative weight."""
    name: str
    description: str
    weight: int
    severity: str
    mitre_tactic: str
    contributing_rule_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "weight": self.weight,
            "severity": self.severity,
            "mitre_tactic": self.mitre_tactic,
            "contributing_rule_ids": list(self.contributing_rule_ids),
        }


# Behaviour catalogue. Weights are coarse (1–10 per behaviour); the
# cumulative sum across all firing behaviours is bucketed at the bottom.
# Components are intentionally permissive — pattern-matching tools tend
# to over-emit, so we'd rather over-trigger here than miss a real combo.
BEHAVIOR_RULES: tuple[BehaviorRule, ...] = (
    BehaviorRule(
        name="ROOT_DETECT_AND_EXEC",
        description=(
            "App probes for root and shells out to a binary. Common in malware "
            "that drops a privilege-escalation payload only on rooted handsets."
        ),
        weight=8,
        mitre_tactic="TA0004 — Privilege Escalation",
        components=(
            BehaviorComponent(rule_id_substr="ANTI_ROOT"),
            BehaviorComponent(rule_id_substr="EXEC"),
        ),
    ),
    BehaviorRule(
        name="STEALTH_INSTALL",
        description=(
            "App hides its launcher icon and installs additional packages — "
            "the canonical persistence pattern for dropper malware."
        ),
        weight=10,
        mitre_tactic="TA0003 — Persistence",
        components=(
            BehaviorComponent(rule_id_substr="HIDE_LAUNCHER"),
            BehaviorComponent(rule_id_substr="PACKAGE_INSTALLER"),
        ),
    ),
    BehaviorRule(
        name="EXFIL_OVER_NETWORK",
        description=(
            "PII source flows into an unpinned or cleartext network sink — "
            "either intentional exfiltration or a textbook MASVS-NETWORK fail."
        ),
        weight=6,
        mitre_tactic="TA0010 — Exfiltration",
        components=(
            BehaviorComponent(category="PRIVACY"),
            BehaviorComponent(category="NETWORK"),
        ),
    ),
    BehaviorRule(
        name="DYNAMIC_CODE_LOAD",
        description=(
            "Reflection plus DexClassLoader / runtime class loading — the "
            "tell-tale shape of a packer or dynamic plugin loader."
        ),
        weight=7,
        mitre_tactic="TA0005 — Defense Evasion",
        components=(
            BehaviorComponent(rule_id_substr="DEX_CLASS_LOADER"),
            BehaviorComponent(category="REFLECTION"),
        ),
    ),
    BehaviorRule(
        name="CRYPTO_RANSOM_PROFILE",
        description=(
            "Symmetric Cipher with hardcoded or constant-derived key plus "
            "filesystem write activity — matches the encryption stage of "
            "consumer ransomware."
        ),
        weight=9,
        mitre_tactic="TA0040 — Impact",
        components=(
            BehaviorComponent(rule_id_substr="HARDCODED_KEY"),
            BehaviorComponent(category="STORAGE"),
        ),
    ),
    BehaviorRule(
        name="OVERLAY_KEYLOG",
        description=(
            "Accessibility service combined with overlay window — the "
            "BankBot / Cerberus credential-stealer pattern."
        ),
        weight=10,
        mitre_tactic="TA0009 — Collection",
        components=(
            BehaviorComponent(rule_id_substr="ACCESSIBILITY"),
            BehaviorComponent(rule_id_substr="OVERLAY"),
        ),
    ),
    BehaviorRule(
        name="SMS_INTERCEPT",
        description=(
            "Reads incoming SMS and exfiltrates over network — 2FA bypass "
            "primitive."
        ),
        weight=9,
        mitre_tactic="TA0009 — Collection",
        components=(
            BehaviorComponent(rule_id_substr="SMS"),
            BehaviorComponent(category="NETWORK"),
        ),
    ),
    BehaviorRule(
        name="DEBUG_DETECT_AND_BAIL",
        description=(
            "Multiple anti-analysis primitives (debugger, emulator, root) "
            "fire together — strong signal of intentional analysis evasion."
        ),
        weight=5,
        mitre_tactic="TA0005 — Defense Evasion",
        components=(
            BehaviorComponent(rule_id_substr="ANTI_DEBUG"),
            BehaviorComponent(rule_id_substr="ANTI_EMULATOR"),
        ),
    ),
)


def _bucket(weight: int) -> str:
    """Map a cumulative weight to a severity label.

    Bands are calibrated to the BEHAVIOR_RULES catalogue: a single
    high-impact behaviour (weight 8–10) firing alone should already
    register as HIGH; two co-occurring behaviours = CRITICAL.
    """
    if weight >= 16:
        return "CRITICAL"
    if weight >= 8:
        return "HIGH"
    if weight >= 4:
        return "MEDIUM"
    if weight >= 1:
        return "LOW"
    return "INFO"


def score_behaviors(findings: Iterable[Finding]) -> list[BehaviorScore]:
    """Evaluate every behaviour against the finding pool, return the
    triggered ones sorted by descending weight."""
    findings = list(findings)
    scored: list[BehaviorScore] = []
    for behaviour in BEHAVIOR_RULES:
        matched = behaviour.evaluate(findings)
        if not matched:
            continue
        scored.append(BehaviorScore(
            name=behaviour.name,
            description=behaviour.description,
            weight=behaviour.weight,
            severity=_bucket(behaviour.weight),
            mitre_tactic=behaviour.mitre_tactic,
            contributing_rule_ids=[f.rule_id for f in matched],
        ))
    scored.sort(key=lambda b: b.weight, reverse=True)
    return scored
