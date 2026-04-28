"""
Shared IR data models: nodes, edges, method descriptors, and findings.
All analysis modules operate on these types — never raw androguard objects.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(Enum):
    HIGH = "HIGH"      # Confirmed: source→sink path exists + reachable + context
    MEDIUM = "MEDIUM"  # Partial: path exists but context incomplete
    LOW = "LOW"        # Heuristic: pattern match without full flow proof


@dataclass(frozen=True)
class MethodDescriptor:
    """Canonical identifier for a method across DEX and decompiled code."""
    class_name: str   # Lcom/example/Foo;
    method_name: str  # doSomething
    descriptor: str   # (Ljava/lang/String;)V

    @property
    def full_name(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.descriptor}"

    def matches_signature(self, class_pattern: str, method_pattern: str) -> bool:
        """Glob-style matching — supports * wildcard."""
        import fnmatch
        return (fnmatch.fnmatch(self.class_name, class_pattern) and
                fnmatch.fnmatch(self.method_name, method_pattern))


@dataclass
class BasicBlock:
    """A maximal straight-line sequence of instructions with no branches."""
    block_id: str
    method: MethodDescriptor
    instructions: list[dict[str, Any]] = field(default_factory=list)
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    # taint labels assigned during analysis
    taint_in: set[str] = field(default_factory=set)
    taint_out: set[str] = field(default_factory=set)


@dataclass
class CFGMethod:
    """Control flow graph for a single method."""
    descriptor: MethodDescriptor
    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    entry_block: Optional[str] = None
    exit_blocks: list[str] = field(default_factory=list)
    is_reachable: bool = True


@dataclass
class CallEdge:
    caller: MethodDescriptor
    callee: MethodDescriptor
    call_site_offset: int = 0


@dataclass
class TaintSource:
    """A single point where tainted data enters the program."""
    method: MethodDescriptor
    block_id: str
    offset: int
    label: str          # e.g. "DEVICE_ID", "LOCATION", "USER_INPUT"
    register: str = ""  # Dalvik register holding the tainted value


@dataclass
class TaintSink:
    """A single point where tainted data would flow to an unsafe destination."""
    method: MethodDescriptor
    block_id: str
    offset: int
    label: str          # e.g. "NETWORK", "LOG", "STORAGE"
    register: str = ""


@dataclass
class TaintPath:
    """A complete source→sink data flow path."""
    source: TaintSource
    sink: TaintSink
    call_chain: list[MethodDescriptor] = field(default_factory=list)
    intermediate_transforms: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single security finding emitted by any analysis module."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: str                         # e.g. "CRYPTO", "NETWORK", "TAINT"

    class_name: str = ""
    method_name: str = ""
    file_path: str = ""
    line_number: int = 0

    evidence: str = ""                    # Code snippet or opcode trace
    taint_path: Optional[TaintPath] = None
    remediation: str = ""
    cwe_id: str = ""
    cvss: float = 0.0
    cvss_vector: str = ""                 # CVSS 3.1 vector string
    owasp_category: str = ""              # OWASP Mobile Top 10 2024 category (M1–M10)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "location": {
                "class": self.class_name,
                "method": self.method_name,
                "file": self.file_path,
                "line": self.line_number,
            },
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss": self.cvss,
            "cvss_vector": self.cvss_vector,
            "owasp_category": self.owasp_category,
        }
        if self.taint_path:
            tp = self.taint_path
            d["taint_flow"] = {
                "source": {
                    "method": tp.source.method.full_name,
                    "label": tp.source.label,
                    "offset": tp.source.offset,
                },
                "sink": {
                    "method": tp.sink.method.full_name,
                    "label": tp.sink.label,
                    "offset": tp.sink.offset,
                },
                "call_chain": [m.full_name for m in tp.call_chain],
                "transforms": tp.intermediate_transforms,
            }
        return d
