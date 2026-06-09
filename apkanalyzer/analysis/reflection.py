"""
Reflection resolution.

What this is
------------
Static reflection edge synthesis. Patterns of the form

    Class.forName("com.foo.Bar").getMethod("baz", ...).invoke(...)

bypass static call-graph construction because androguard only sees the call to
`Method.invoke`, not the underlying `Bar.baz` target. This module scans every
reachable CFG for these patterns, recovers the (class, method) constants, and
returns synthetic CallEdges that the orchestrator can splice into the call
graph BEFORE reachability and taint analysis run. As a result:

  * Reachability picks up reflectively-invoked methods.
  * The taint engine inlines them through normal callee resolution.
  * Findings now include reflection-mediated source→sink flows that earlier
    runs missed entirely (e.g. an Activity that uses Class.forName to call
    a hidden Telephony API and ship the result over HTTP).

How it works
------------
The resolver walks a method's instructions in order, maintaining a tiny
register state (string constants, deobfuscated strings, and "this register
holds a Class object for X" / "this register holds a Method handle for X.m").
When a `Method.invoke` is reached and we know the underlying target, we emit
an edge `current_method → target` and return it.

We accept both:
  * literal string constants (`const-string vN, "com.foo.Bar"`),
  * results of well-known deobfuscation calls (`String.intern`, `new String(byte[])`,
    base64 decode, simple XOR helpers) — see `deobfuscate.try_decode()`.

We do NOT do:
  * heap modelling beyond per-method local registers (cross-method tracking
    is the taint engine's job, not ours),
  * symbolic resolution of arbitrary string-builder concatenations.

Out-of-scope reflection patterns get logged as `OBFUSC_REFLECTION_*` by
`obfuscation_detector.py` (unchanged behaviour). This module is purely
additive — it only ever ADDS edges; it never removes or rewrites them.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, Optional

from apkanalyzer.ir.cfg_builder import build_cfg
from apkanalyzer.ir.models import CallEdge, MethodDescriptor
from apkanalyzer.utils.deobfuscate import try_decode

logger = logging.getLogger(__name__)


# Java FQN ("com.foo.Bar") → Dalvik descriptor ("Lcom/foo/Bar;").
def _to_dalvik(fqn: str) -> str:
    return "L" + fqn.replace(".", "/") + ";"


# Match the dst register of `const-string vN, "..."` lines.
_CONST_STRING_RE = re.compile(r"^const-string(?:/jumbo)?\s+(v\w+)\s*,\s*\"(.*)\"\s*$")


@dataclass
class _RegState:
    """Per-instruction register state for reflection tracking."""
    # register → recovered string constant (deobfuscated where possible)
    strings: dict[str, str]
    # register → Java FQN of the Class<?> object it holds
    class_of: dict[str, str]
    # register → (class_fqn, method_name) of the Method handle it holds
    method_of: dict[str, tuple[str, str]]

    @classmethod
    def empty(cls) -> "_RegState":
        return cls(strings={}, class_of={}, method_of={})


def _record_const_string(instr: dict, state: _RegState) -> None:
    """Capture string constants written via const-string / const-string/jumbo."""
    raw = instr.get("raw", "")
    m = _CONST_STRING_RE.match(raw.strip())
    if not m:
        # Fall back to operand inspection — some androguard outputs differ.
        ops = instr.get("operands", [])
        if len(ops) >= 2 and instr.get("mnemonic", "").startswith("const-string"):
            reg = str(ops[0].get("value", ""))
            val = str(ops[1].get("value", ""))
            if reg and val and reg.startswith(("v", "p")):
                state.strings[reg] = val
        return
    reg, val = m.group(1), m.group(2)
    state.strings[reg] = val


def _registers_in_invoke(instr: dict) -> list[str]:
    raw = instr.get("raw", "")
    try:
        regs_part = raw[raw.index("{") + 1: raw.index("}")]
        return [r.strip() for r in regs_part.split(",") if r.strip()]
    except ValueError:
        return []


def _last_const_string_arg(state: _RegState, regs: list[str], skip: int = 1) -> Optional[str]:
    """First string-typed argument after the receiver."""
    for r in regs[skip:]:
        if r in state.strings:
            return state.strings[r]
    return None


def _scan_method(
    method_desc: MethodDescriptor,
    method_analysis,
    cg_methods: dict[tuple[str, str, str], MethodDescriptor],
) -> list[CallEdge]:
    """
    Scan one method for reflective invocations and return synthetic edges.

    cg_methods is the (class, method, descriptor) → MethodDescriptor index
    of every method known to the call graph; we only emit edges for targets
    we can resolve in-app (no point fabricating edges to nonexistent nodes).
    """
    cfg = build_cfg(method_analysis, method_desc)
    if not cfg.blocks:
        return []

    state = _RegState.empty()
    edges: list[CallEdge] = []

    # We scan each block in source order. Reflection patterns are typically
    # tightly packed within one basic block (forName → getMethod → invoke
    # in a single straight-line sequence) so block-local analysis catches
    # the realistic cases without an expensive worklist.
    for block in cfg.blocks.values():
        block_state = _RegState.empty()
        for instr in block.instructions:
            mnemonic = instr.get("mnemonic", "")
            raw = instr.get("raw", "")

            # Track string constants
            if mnemonic.startswith("const-string"):
                _record_const_string(instr, block_state)
                continue

            # move-result: copy "last invoke produced X" → result register
            if mnemonic in ("move-result-object", "move-result"):
                ops = instr.get("operands", [])
                if not ops:
                    continue
                dst = str(ops[0].get("value", ""))
                # Pull from a transient slot that the previous invoke set.
                pending = block_state.strings.pop("__pending_string__", None)
                if pending is not None:
                    block_state.strings[dst] = pending
                pending_class = block_state.class_of.pop("__pending_class__", None)
                if pending_class is not None:
                    block_state.class_of[dst] = pending_class
                pending_method = block_state.method_of.pop("__pending_method__", None)
                if pending_method is not None:
                    block_state.method_of[dst] = pending_method
                continue

            if not mnemonic.startswith("invoke"):
                continue

            regs = _registers_in_invoke(instr)

            # Class.forName(stringConst) → result is a Class for that FQN
            if "Ljava/lang/Class;->forName(" in raw and regs:
                fqn = block_state.strings.get(regs[0])
                if fqn:
                    block_state.class_of["__pending_class__"] = fqn
                continue

            # Class.getMethod(name, ...) / getDeclaredMethod(name, ...)
            if (
                ("Ljava/lang/Class;->getMethod(" in raw
                 or "Ljava/lang/Class;->getDeclaredMethod(" in raw)
                and len(regs) >= 2
            ):
                cls_fqn = block_state.class_of.get(regs[0])
                m_name = block_state.strings.get(regs[1])
                if cls_fqn and m_name:
                    block_state.method_of["__pending_method__"] = (cls_fqn, m_name)
                continue

            # Class.getDeclaredField / getField — not invocable, but may be
            # chained into a Method via reflection on the field's type. We
            # don't model that pattern here — pure-field reflection is
            # logged by `obfuscation_detector.py` and rarely yields a real
            # call edge worth synthesising.

            # Method.invoke(receiver, args...) — emit synthetic edge
            if "Ljava/lang/reflect/Method;->invoke(" in raw and regs:
                target = block_state.method_of.get(regs[0])
                if not target:
                    continue
                cls_fqn, m_name = target
                dalvik_cls = _to_dalvik(cls_fqn)
                # Match by (class, name) on any descriptor — reflective
                # invokers don't carry the descriptor, so we accept any
                # overload that exists in the call graph. CHA at the taint
                # layer covers fan-out across overrides.
                for (cls_, name_, desc_), tgt in cg_methods.items():
                    if cls_ == dalvik_cls and name_ == m_name:
                        edges.append(CallEdge(
                            caller=method_desc,
                            callee=tgt,
                            call_site_offset=instr.get("offset", 0),
                        ))
                continue

            # Fold known deobfuscation helpers into block_state.strings:
            # any invoke whose first arg is a string constant and whose
            # method name suggests "decode/decrypt/unobfuscate" gets fed
            # through `try_decode` and the result is parked in __pending_string__.
            if regs:
                first = regs[1] if len(regs) >= 2 else regs[0]
                seed = block_state.strings.get(first)
                if seed:
                    decoded = try_decode(seed, raw)
                    if decoded and decoded != seed:
                        block_state.strings["__pending_string__"] = decoded
        # carry block-local discoveries forward conservatively. We don't
        # model branching state — duplicating the dict is enough because
        # the next block's const-string lines will re-establish anything
        # genuinely needed.
        for k, v in block_state.strings.items():
            state.strings.setdefault(k, v)
        for k, v in block_state.class_of.items():
            state.class_of.setdefault(k, v)
        for k, v in block_state.method_of.items():
            state.method_of.setdefault(k, v)

    return edges


def synthesise_reflection_edges(cg, dx) -> int:
    """
    Walk every method in `cg`, scan for reflective Class.forName→getMethod→invoke
    patterns, and add synthetic edges into `cg`.

    Returns the number of edges added — useful for telemetry. Mutates `cg`
    in place by calling `_add_edge` for each resolved target.

    This is best-effort: methods whose CFG androguard cannot build are
    silently skipped, malformed reflection chains produce no edge.
    """
    cg_methods = {
        (d.class_name, d.method_name, d.descriptor): d
        for d in cg.all_methods()
    }
    if not cg_methods:
        return 0

    # Build a one-shot lookup from MethodDescriptor.full_name to the
    # androguard MethodAnalysis so we don't do O(N) scans per method.
    ma_table: dict[str, object] = {}
    try:
        for ma in dx.get_methods():
            try:
                m = ma.get_method() if hasattr(ma, "get_method") else ma
                key = f"{m.get_class_name()}->{m.get_name()}{m.get_descriptor()}"
                ma_table[key] = ma
            except Exception:
                continue
    except Exception as exc:
        logger.debug("reflection: dx.get_methods iteration failed: %s", exc)
        return 0

    added = 0
    for desc in list(cg.all_methods()):
        ma = ma_table.get(desc.full_name)
        if ma is None:
            continue
        try:
            edges = _scan_method(desc, ma, cg_methods)
        except Exception as exc:
            logger.debug("reflection scan failed on %s: %s", desc.full_name, exc)
            continue
        for edge in edges:
            # Skip duplicates — the static call-graph builder may already
            # have an edge from app-code that called the target directly.
            if cg.graph.has_edge(edge.caller.full_name, edge.callee.full_name):
                continue
            cg.graph.add_edge(
                edge.caller.full_name,
                edge.callee.full_name,
                edge=edge,
                synthetic="reflection",
            )
            added += 1

    if added:
        logger.info("reflection: %d synthetic call edges added", added)
    return added
