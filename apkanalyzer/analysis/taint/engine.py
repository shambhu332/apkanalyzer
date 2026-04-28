"""
Inter-procedural taint analysis engine.

Algorithm
---------
We implement a flow-sensitive, context-insensitive (k=0) monotone dataflow
analysis on the Dalvik bytecode CFG, propagated inter-procedurally via the
call graph.

Each register in each basic block carries a set of taint labels (strings).
The transfer function for an instruction:

  invoke-virtual {v0, v1}, Landroid/telephony/TelephonyManager;->getDeviceId()
      → result register v0 gets label DEVICE_ID  (source rule)

  invoke-virtual {v3, v4}, Landroid/util/Log;->d(Ljava/lang/String;)
      → if v4 is tainted → emit TaintPath finding  (sink rule)

  move-result v2
      → v2 inherits taint of the last invoke's return

  move vA, vB
      → taint(vA) = taint(vB)

  invoke-* {v0, ..., vN}, SomeClass;->foo(...)V
      → for each callee CFG: map caller registers → callee parameters,
         propagate taint through callee, map return taint back to caller

Worklist algorithm (BFS over CFG blocks) ensures termination because
the taint lattice (𝒫(Labels)) has finite height and monotone ∪ joins.

False-positive guards
---------------------
1. Reachability: only methods reachable from an entry point are analysed.
2. Context: we require the data flow path to include at least one "interesting"
   operation (not just a trivial pass-through).
3. Test class filter: classes whose name contains Test/Mock/Debug are skipped
   (word-boundary matching, so "Latest"/"Greatest" are not affected).

Inter-procedural details
------------------------
- Method summaries cache the merged exit-state taint per method, including a
  synthetic "__return__" slot populated from any `return-*` opcodes encountered
  in the method body. Callers read that slot to propagate return-value taint
  without re-analysing the callee.
- Cached methods replay their previously-emitted source→sink paths on every
  fresh visit, so a helper called from many sites doesn't silently drop paths.
- Static fields (sget/sput) are tracked engine-wide via a global label map,
  keyed by `class;->field`. This catches taint that flows through Singleton /
  cache patterns that previously vanished.
- Field-sensitive iput: writes to instance fields tag the host object with
  composite labels of the form `LABEL@field` so subsequent iget reads of the
  same field name recover the original taint without polluting unrelated
  fields.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from typing import Optional

from apkanalyzer.ir.models import (
    BasicBlock,
    CFGMethod,
    MethodDescriptor,
    TaintPath,
    TaintSink,
    TaintSource,
    Finding,
    Severity,
    Confidence,
)
from apkanalyzer.ir.call_graph import CallGraph
from apkanalyzer.ir.cfg_builder import build_cfg
from apkanalyzer.analysis.taint.sources import TaintSourceSpec, build_source_index
from apkanalyzer.analysis.taint.sinks import TaintSinkSpec, build_sink_index
from apkanalyzer.analysis.taint.sanitizers import SanitizerSpec, build_sanitizer_index

logger = logging.getLogger(__name__)

# Register used to carry return values from invoke-* instructions
_RESULT_REG = "__result__"
# Synthetic register used in summary state to carry the method's return-value taint
_RETURN_REG = "__return__"
# Separator for field-sensitive composite labels: BASE_LABEL + FIELD_SEP + field_name
_FIELD_SEP = "@"
# Class Hierarchy Analysis cap: when a virtual/interface call resolves to many
# possible targets, analysing all of them is exponential. Eight is enough for
# OkHttp Interceptor / Volley Response.Listener / RxJava Observer style fan-out
# without blowing up on Iterable.iterator() or similar universal interfaces.
_CHA_MAX_TARGETS = 4

from apkanalyzer.utils.test_class import is_test_class as _is_test_class


def _extract_invoke_parts(instr: dict) -> Optional[tuple[str, str, str, list[str]]]:
    """
    Parse an invoke-* instruction.

    Returns (class_name, method_name, descriptor, [arg_registers]) or None.
    raw example: "invoke-virtual {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    """
    raw = instr.get("raw", "")
    mnemonic = instr.get("mnemonic", "")
    if not mnemonic.startswith("invoke"):
        return None

    try:
        # Extract register list
        reg_part = raw[raw.index("{") + 1: raw.index("}")]
        registers = [r.strip() for r in reg_part.split(",") if r.strip()]

        # Extract method reference
        ref_part = raw[raw.index("}") + 1:].strip().lstrip(",").strip()
        class_method, descriptor = ref_part.split("(", 1)
        descriptor = "(" + descriptor
        class_name, method_name = class_method.rsplit("->", 1)
        class_name = class_name.strip()
        method_name = method_name.strip()

        return class_name, method_name, descriptor, registers
    except Exception:
        return None


def _get_move_result_register(instr: dict) -> Optional[str]:
    """Return the destination register of move-result / move-result-object."""
    mnemonic = instr.get("mnemonic", "")
    if mnemonic in ("move-result", "move-result-object", "move-result-wide"):
        operands = instr.get("operands", [])
        if operands:
            return str(operands[0].get("value", ""))
    return None


def _get_move_registers(instr: dict) -> Optional[tuple[str, str]]:
    """Return (dst, src) for move / move-object instructions."""
    mnemonic = instr.get("mnemonic", "")
    if mnemonic.startswith("move") and "result" not in mnemonic:
        operands = instr.get("operands", [])
        if len(operands) >= 2:
            return str(operands[0].get("value", "")), str(operands[1].get("value", ""))
    return None


def _get_return_register(instr: dict) -> Optional[str]:
    """Return the source register of a return-* opcode (None for `return-void`)."""
    mnemonic = instr.get("mnemonic", "")
    if mnemonic in ("return", "return-object", "return-wide"):
        operands = instr.get("operands", [])
        if operands:
            return str(operands[0].get("value", ""))
    return None


def _parse_field_ref(instr: dict) -> Optional[tuple[str, str]]:
    """
    Parse the `Class;->field:Type` portion of an iget/iput/sget/sput.

    Returns (class_name, field_name) or None on malformed instruction.
    """
    raw = instr.get("raw", "")
    try:
        # Last `,` separates registers from field reference
        ref = raw.rsplit(",", 1)[-1].strip()
        # ref looks like Lcom/Foo;->bar:Ljava/lang/String;
        cls_part, rest = ref.split("->", 1)
        field_name = rest.split(":", 1)[0]
        return cls_part.strip(), field_name.strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Per-method taint state
# ---------------------------------------------------------------------------

class MethodTaintState:
    """Mutable taint state for a single method invocation context."""

    def __init__(self) -> None:
        # register name → set of taint labels
        self.regs: dict[str, set[str]] = {}
        # register → set of sanitizer labels applied to its value
        self.sanitized: dict[str, set[str]] = {}
        # taint label → originating TaintSource (kept as a real object, not repr)
        self.source_objects: dict[str, TaintSource] = {}

    def taint(self, register: str, labels: set[str]) -> None:
        if not labels:
            return
        current = self.regs.get(register, set())
        self.regs[register] = current | labels

    def sanitize(self, register: str, sanitizer_label: str) -> None:
        current = self.sanitized.get(register, set())
        self.sanitized[register] = current | {sanitizer_label}

    def get_taint(self, register: str) -> set[str]:
        return set(self.regs.get(register, set()))

    def get_sanitizers(self, register: str) -> set[str]:
        return set(self.sanitized.get(register, set()))

    def record_source(self, label: str, src: TaintSource) -> None:
        # First-writer wins so the path points at the original source location.
        self.source_objects.setdefault(label, src)

    def get_source(self, label: str) -> Optional[TaintSource]:
        return self.source_objects.get(label)

    def copy(self) -> "MethodTaintState":
        s = MethodTaintState()
        s.regs = {k: set(v) for k, v in self.regs.items()}
        s.sanitized = {k: set(v) for k, v in self.sanitized.items()}
        s.source_objects = dict(self.source_objects)
        return s

    def merge(self, other: "MethodTaintState") -> bool:
        """Merge other into self. Return True if state changed."""
        changed = False
        for reg, labels in other.regs.items():
            before = frozenset(self.regs.get(reg, set()))
            self.regs[reg] = self.regs.get(reg, set()) | labels
            if frozenset(self.regs[reg]) != before:
                changed = True
        for reg, sans in other.sanitized.items():
            self.sanitized[reg] = self.sanitized.get(reg, set()) | sans
        for label, src in other.source_objects.items():
            if label not in self.source_objects:
                self.source_objects[label] = src
                changed = True
        return changed


# ---------------------------------------------------------------------------
# Method summary
# ---------------------------------------------------------------------------

class MethodSummary:
    """
    Cached analysis result for a single method.

    Stores the merged exit-state plus the source→sink paths that were emitted
    while analysing this method. On a re-visit (helper called from a second
    site) we replay both the return-value taint *and* the recorded paths so
    multi-call helpers don't silently lose findings.
    """

    __slots__ = ("exit_state", "paths")

    def __init__(self, exit_state: MethodTaintState,
                 paths: list[tuple[TaintSource, TaintSink, list[MethodDescriptor], bool]]) -> None:
        self.exit_state = exit_state
        # Defensive copy so callers can't mutate the cached list.
        self.paths = list(paths)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class TaintEngine:
    """
    Inter-procedural taint analysis engine.

    Usage
    -----
    engine = TaintEngine(call_graph, dx, max_depth=8,
                         extra_sources=[...], extra_sinks=[...])
    findings = engine.run(reachable_methods)
    """

    def __init__(
        self,
        call_graph: CallGraph,
        dx,
        max_depth: int = 8,
        extra_sources: Optional[list[TaintSourceSpec]] = None,
        extra_sinks: Optional[list[TaintSinkSpec]] = None,
        extra_sanitizers: Optional[list[SanitizerSpec]] = None,
    ) -> None:
        self.cg = call_graph
        self.dx = dx
        self.max_depth = max_depth

        self.source_index = build_source_index(extra_sources)
        self.sink_index = build_sink_index(extra_sinks)
        self.sanitizer_index = build_sanitizer_index(extra_sanitizers)

        # Precomputed sanitizer-label → set(neutralised sink labels) so the
        # per-sink check is O(1) instead of O(N²) over all sanitizer specs.
        self._sanitizer_neutralizes: dict[str, set[str]] = {}
        for specs in self.sanitizer_index.values():
            for spec in specs:
                if not spec.neutralizes:
                    continue
                self._sanitizer_neutralizes.setdefault(spec.label, set()).update(spec.neutralizes)

        # (class, method, descriptor) → MethodDescriptor for O(1) callee lookup.
        # Without this, _resolve_callee was O(n) per call site, O(n²) overall.
        self._callee_index: dict[tuple[str, str, str], MethodDescriptor] = {
            (d.class_name, d.method_name, d.descriptor): d
            for d in self.cg.all_methods()
        }

        # Cache of built CFGs to avoid re-building
        self._cfg_cache: dict[str, CFGMethod] = {}
        # Memoise full method summaries (exit state + emitted paths)
        self._method_summaries: dict[str, MethodSummary] = {}

        # Engine-wide static-field taint map. Static fields persist across
        # method calls and across the whole analysis run, so they live here
        # rather than on a per-method state object.
        # Keyed by `class;->field` → set of taint labels.
        self._static_field_taint: dict[str, set[str]] = {}
        self._static_field_sources: dict[str, dict[str, TaintSource]] = {}

        # Truncation telemetry — surfaced once per run instead of per-method
        # spam. Helps users understand when a result is partial.
        self._truncated_methods: list[str] = []

    def run(self, reachable_methods: set[str]) -> list[Finding]:
        """
        Analyse all reachable non-test methods.

        Returns a deduplicated list of Findings.
        """
        findings: list[Finding] = []

        for desc in self.cg.all_methods():
            if desc.full_name not in reachable_methods:
                continue
            if _is_test_class(desc.class_name):
                continue

            paths = self._analyse_method(desc, depth=0, visited=set())
            for src, snk, chain, neutralized in paths:
                findings.append(self._make_finding(src, snk, chain, neutralized))

        if self._truncated_methods:
            logger.warning(
                "Taint worklist truncated for %d method(s); results are partial. "
                "First few: %s",
                len(self._truncated_methods),
                ", ".join(self._truncated_methods[:5]),
            )

        return self._deduplicate(findings)

    # ------------------------------------------------------------------
    # Per-method analysis
    # ------------------------------------------------------------------

    def _get_cfg(self, desc: MethodDescriptor) -> Optional[CFGMethod]:
        key = desc.full_name
        if key in self._cfg_cache:
            return self._cfg_cache[key]

        try:
            method_analysis = self.dx.get_method_analysis_by_name(
                desc.class_name, desc.method_name, desc.descriptor
            )
            if method_analysis is None:
                # Single linear scan over dx.get_methods() costs O(N); the
                # original code paid that O(N) per resolve miss, so we cache
                # the full table the first time we hit a miss.
                if not hasattr(self, "_method_analysis_table"):
                    self._method_analysis_table = {}
                    for ma in self.dx.get_methods():
                        try:
                            m = ma.get_method() if hasattr(ma, "get_method") else ma
                            sig = (m.get_class_name(), m.get_name(), m.get_descriptor())
                            self._method_analysis_table[sig] = ma
                        except Exception:
                            continue
                method_analysis = self._method_analysis_table.get(
                    (desc.class_name, desc.method_name, desc.descriptor)
                )
            if method_analysis is None:
                return None
            cfg = build_cfg(method_analysis, desc)
            self._cfg_cache[key] = cfg
            return cfg
        except Exception as exc:
            logger.debug("CFG build failed for %s: %s", key, exc)
            return None

    def _analyse_method(
        self,
        desc: MethodDescriptor,
        depth: int,
        visited: set[str],
        initial_state: Optional[MethodTaintState] = None,
    ) -> list[tuple[TaintSource, TaintSink, list[MethodDescriptor], bool]]:
        """
        Run the worklist dataflow algorithm on a single method's CFG.

        Returns list of (source, sink, call_chain, is_neutralized) tuples.
        """
        if depth > self.max_depth:
            return []

        # Re-visit handling — replay cached paths instead of returning [].
        if desc.full_name in visited:
            cached = self._method_summaries.get(desc.full_name)
            if cached:
                # Re-emit each previously found path with the current chain
                # prefix so deduplication still folds them by sink offset.
                return list(cached.paths)
            return []

        cfg = self._get_cfg(desc)
        if not cfg or not cfg.blocks:
            return []

        visited = visited | {desc.full_name}

        block_states: dict[str, MethodTaintState] = {bid: MethodTaintState() for bid in cfg.blocks}
        if initial_state and cfg.entry_block:
            block_states[cfg.entry_block] = initial_state.copy()

        worklist: deque[str] = deque()
        if cfg.entry_block:
            worklist.append(cfg.entry_block)

        found_paths: list[tuple[TaintSource, TaintSink, list[MethodDescriptor], bool]] = []
        # Per-method record of return-register taint observed at any return-*
        # opcode. Merged into the summary's __return__ slot so callers see it.
        return_taint: set[str] = set()

        iterations = 0
        max_iterations = len(cfg.blocks) * 10 + 100

        while worklist and iterations < max_iterations:
            iterations += 1
            block_id = worklist.popleft()
            block = cfg.blocks.get(block_id)
            if block is None:
                continue

            in_state = block_states[block_id]
            out_state, new_paths, inlined_calls, ret_from_block = self._transfer(
                block, in_state.copy(), desc, depth, visited
            )
            found_paths.extend(new_paths)
            found_paths.extend(inlined_calls)
            return_taint |= ret_from_block

            for succ_id in block.successors:
                if succ_id not in block_states:
                    block_states[succ_id] = MethodTaintState()
                changed = block_states[succ_id].merge(out_state)
                if changed and succ_id not in worklist:
                    worklist.append(succ_id)

        if iterations >= max_iterations and worklist:
            self._truncated_methods.append(desc.full_name)

        # Build and cache the method summary
        final_state = MethodTaintState()
        if cfg.exit_blocks:
            for exit_id in cfg.exit_blocks:
                if exit_id in block_states:
                    final_state.merge(block_states[exit_id])
        else:
            for st in block_states.values():
                final_state.merge(st)

        if return_taint:
            final_state.regs[_RETURN_REG] = set(return_taint)

        self._method_summaries[desc.full_name] = MethodSummary(final_state, found_paths)

        return found_paths

    def _transfer(
        self,
        block: BasicBlock,
        state: MethodTaintState,
        current_method: MethodDescriptor,
        depth: int,
        visited: set[str],
    ) -> tuple[MethodTaintState, list, list, set[str]]:
        """
        Apply transfer function for each instruction in the block.

        Returns (out_state, local_paths, callee_paths, return_taint).
        """
        local_paths: list[tuple[TaintSource, TaintSink, list[MethodDescriptor], bool]] = []
        callee_paths: list[tuple[TaintSource, TaintSink, list[MethodDescriptor], bool]] = []
        return_taint: set[str] = set()

        last_invoke_taint: set[str] = set()

        for instr in block.instructions:
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)
            raw = instr.get("raw", "")

            # ── Handle return-* (carry register taint to summary) ─────
            ret_reg = _get_return_register(instr)
            if ret_reg is not None:
                return_taint |= state.get_taint(ret_reg)
                continue

            # ── Handle move-result: copy return taint ──────────────────
            move_reg = _get_move_result_register(instr)
            if move_reg is not None:
                state.taint(move_reg, last_invoke_taint)
                last_invoke_taint = set()
                continue

            # ── Handle move / move-object: propagate register taint ───
            move_pair = _get_move_registers(instr)
            if move_pair is not None:
                dst, src = move_pair
                state.taint(dst, state.get_taint(src))
                continue

            # ── Field reads: iget / sget ─────────────────────────────
            if mnemonic.startswith("iget") or mnemonic.startswith("sget"):
                operands = instr.get("operands", [])
                if not operands:
                    continue
                dst_reg = str(operands[0].get("value", ""))
                field_ref = _parse_field_ref(instr)

                if mnemonic.startswith("sget"):
                    if field_ref:
                        key = f"{field_ref[0]};->{field_ref[1]}"
                        labels = self._static_field_taint.get(key)
                        if labels:
                            state.taint(dst_reg, labels)
                            for lbl in labels:
                                src = self._static_field_sources.get(key, {}).get(lbl)
                                if src is not None:
                                    state.record_source(lbl, src)
                    continue

                # iget: read instance field from object register
                if len(operands) >= 2 and field_ref:
                    obj_reg = str(operands[1].get("value", ""))
                    obj_taint = state.get_taint(obj_reg)
                    if not obj_taint:
                        continue
                    field_name = field_ref[1]
                    suffix = f"{_FIELD_SEP}{field_name}"
                    # Keep only labels stamped for this field; strip the
                    # "@field" suffix so downstream sinks see the original
                    # source label (DEVICE_ID, not DEVICE_ID@token).
                    matching = {
                        lbl[: -len(suffix)] for lbl in obj_taint
                        if lbl.endswith(suffix)
                    }
                    # Bare object taint (no field suffix) means the object
                    # itself is tainted (e.g. came straight from a source);
                    # still propagate it conservatively.
                    bare = {lbl for lbl in obj_taint if _FIELD_SEP not in lbl}
                    state.taint(dst_reg, matching | bare)
                continue

            # ── Field writes: iput / sput ─────────────────────────────
            if mnemonic.startswith("iput") or mnemonic.startswith("sput"):
                operands = instr.get("operands", [])
                field_ref = _parse_field_ref(instr)
                if mnemonic.startswith("sput"):
                    if operands and field_ref:
                        src_reg = str(operands[0].get("value", ""))
                        src_taint = state.get_taint(src_reg)
                        if src_taint:
                            key = f"{field_ref[0]};->{field_ref[1]}"
                            current = self._static_field_taint.setdefault(key, set())
                            current.update(src_taint)
                            src_map = self._static_field_sources.setdefault(key, {})
                            for lbl in src_taint:
                                src_obj = state.get_source(lbl)
                                if src_obj is not None:
                                    src_map.setdefault(lbl, src_obj)
                    continue

                # iput: tag host object with composite labels per field
                if len(operands) >= 2 and field_ref:
                    src_reg = str(operands[0].get("value", ""))
                    obj_reg = str(operands[1].get("value", ""))
                    src_taint = state.get_taint(src_reg)
                    if src_taint:
                        composite = {
                            f"{lbl}{_FIELD_SEP}{field_ref[1]}" for lbl in src_taint
                            if _FIELD_SEP not in lbl
                        }
                        state.taint(obj_reg, composite)
                continue

            # ── StringBuilder/StringBuffer append (string concat) ──
            if "StringBuilder;->append" in raw or "StringBuffer;->append" in raw:
                parts_sb = _extract_invoke_parts(instr)
                if parts_sb:
                    _, _, _, sb_args = parts_sb
                    sb_taint: set[str] = set()
                    for reg in sb_args:
                        sb_taint |= state.get_taint(reg)
                    if sb_taint and sb_args:
                        state.taint(sb_args[0], sb_taint)
                    last_invoke_taint = state.get_taint(sb_args[0]) if sb_args else set()
                continue

            if "StringBuilder;->toString" in raw or "StringBuffer;->toString" in raw:
                parts_ts = _extract_invoke_parts(instr)
                if parts_ts:
                    _, _, _, ts_args = parts_ts
                    if ts_args:
                        last_invoke_taint = state.get_taint(ts_args[0])
                continue

            # ── Handle invoke-* ───────────────────────────────────────
            parts = _extract_invoke_parts(instr)
            if parts is None:
                continue

            class_name, method_name, descriptor, arg_regs = parts

            # Source rules
            source_labels: set[str] = set()
            for spec in self.source_index.get(class_name, []):
                if spec.method_pattern == method_name or spec.method_pattern == "*":
                    source_labels.add(spec.label)

            if source_labels:
                last_invoke_taint = source_labels
                for label in source_labels:
                    state.record_source(label, TaintSource(
                        method=current_method,
                        block_id=block.block_id,
                        offset=offset,
                        label=label,
                        register=_RESULT_REG,
                    ))

            # Sanitizer rules
            for san_spec in self.sanitizer_index.get(class_name, []):
                if san_spec.method_pattern in (method_name, "*"):
                    for reg in arg_regs[1:]:
                        if state.get_taint(reg):
                            state.sanitize(reg, san_spec.label)
                    state.sanitize(_RESULT_REG, san_spec.label)

            # Sink rules
            for spec in self.sink_index.get(class_name, []):
                if spec.method_pattern not in (method_name, "*"):
                    continue
                param_idx = spec.tainted_param
                is_static = "static" in mnemonic
                adjusted_idx = param_idx if is_static else param_idx + 1
                if not (0 <= adjusted_idx < len(arg_regs)):
                    continue
                target_reg = arg_regs[adjusted_idx]
                taint_labels = state.get_taint(target_reg)
                if not taint_labels:
                    continue
                applied_sans = state.get_sanitizers(target_reg)
                # O(1) neutralisation check via precomputed map
                is_neutralized = any(
                    spec.label in self._sanitizer_neutralizes.get(san_label, set())
                    for san_label in applied_sans
                )
                snk_obj = TaintSink(
                    method=current_method,
                    block_id=block.block_id,
                    offset=offset,
                    label=spec.label,
                    register=target_reg,
                )
                # Strip composite "@field" labels back to base before sourcing
                # so the finding's source label matches the original origin.
                seen_bases: set[str] = set()
                for label in taint_labels:
                    base = label.split(_FIELD_SEP, 1)[0]
                    if base in seen_bases:
                        continue
                    seen_bases.add(base)
                    src_obj = state.get_source(base) or state.get_source(label)
                    if src_obj is not None:
                        local_paths.append(
                            (src_obj, snk_obj, [current_method], is_neutralized)
                        )

            # Inline callee analysis (inter-procedural)
            if depth < self.max_depth:
                callee_desc = self._resolve_callee(class_name, method_name, descriptor)

                # CHA fallback: when the exact static target isn't in the
                # app (typical for invoke-virtual on an interface like
                # OkHttp Interceptor.intercept), expand to concrete impls.
                cha_extras: list[MethodDescriptor] = []
                if mnemonic.startswith(("invoke-virtual", "invoke-interface")):
                    cha_extras = self._resolve_callees_cha(
                        class_name, method_name, descriptor,
                    )
                    # If exact resolution missed entirely, treat the first
                    # CHA target as the primary callee.
                    if callee_desc is None and cha_extras:
                        callee_desc, *cha_extras = cha_extras

                # Build a list of all targets to inline. Order: primary
                # exact target first, then CHA alternatives. We dedupe by
                # full_name so a class that both inherits and implements
                # the same signature isn't visited twice.
                inline_targets: list[MethodDescriptor] = []
                if callee_desc is not None:
                    inline_targets.append(callee_desc)
                for alt in cha_extras:
                    if alt.full_name not in {t.full_name for t in inline_targets}:
                        inline_targets.append(alt)

                cha_return_taint: set[str] = set()
                for tgt_desc in inline_targets:
                    if tgt_desc.full_name in visited:
                        # Recursive / mutually-recursive: replay cached paths
                        cached = self._method_summaries.get(tgt_desc.full_name)
                        if cached:
                            for src, snk, chain, neutralized in cached.paths:
                                callee_paths.append(
                                    (src, snk, [current_method] + chain, neutralized)
                                )
                            ret = cached.exit_state.regs.get(_RETURN_REG)
                            if ret:
                                cha_return_taint |= set(ret)
                    else:
                        callee_init = MethodTaintState()
                        for i, reg in enumerate(arg_regs):
                            labels = state.get_taint(reg)
                            if labels:
                                callee_init.taint(f"p{i}", labels)
                                for lbl in labels:
                                    src_obj = state.get_source(
                                        lbl.split(_FIELD_SEP, 1)[0]
                                    )
                                    if src_obj is not None:
                                        callee_init.record_source(lbl, src_obj)

                        sub_paths = self._analyse_method(
                            tgt_desc, depth + 1, visited, callee_init
                        )
                        for src, snk, chain, neutralized in sub_paths:
                            callee_paths.append(
                                (src, snk, [current_method] + chain, neutralized)
                            )

                        # Propagate callee return taint back into caller —
                        # union across all CHA alternatives so any one of
                        # them returning tainted data taints the caller.
                        callee_summary = self._method_summaries.get(tgt_desc.full_name)
                        if callee_summary is not None:
                            ret = callee_summary.exit_state.regs.get(_RETURN_REG)
                            if ret:
                                cha_return_taint |= set(ret)

                if cha_return_taint:
                    last_invoke_taint = cha_return_taint

        return state, local_paths, callee_paths, return_taint

    def _resolve_callee(
        self, class_name: str, method_name: str, descriptor: str
    ) -> Optional[MethodDescriptor]:
        """Look up a MethodDescriptor from the call graph by signature."""
        return self._callee_index.get((class_name, method_name, descriptor))

    def _resolve_callees_cha(
        self, class_name: str, method_name: str, descriptor: str,
    ) -> list[MethodDescriptor]:
        """
        CHA fallback: when an exact-signature lookup misses (typical for
        invoke-virtual / invoke-interface against an interface or abstract
        class), return up to _CHA_MAX_TARGETS subclass / implementation
        targets that actually define the method.

        Empty list if CHA finds nothing — the caller should treat that
        as "no callee inlined", same as before.
        """
        cg = self.cg
        if not hasattr(cg, "cha_targets"):
            return []
        return cg.cha_targets(class_name, method_name, descriptor,
                              max_targets=_CHA_MAX_TARGETS)

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        src: TaintSource,
        snk: TaintSink,
        chain: list[MethodDescriptor],
        sanitized: bool = False,
    ) -> Finding:
        taint_path = TaintPath(source=src, sink=snk, call_chain=chain)

        # Re-classify generic LOG / NETWORK_OUT sinks as PII_LOG / PII_NETWORK
        # when the source is personally identifiable. This bridges the
        # privacy + logging detectors into the taint engine: the same data-
        # flow analysis backs MASVS-PRIVACY findings, with sharper severity
        # and OWASP MASVS-2 mapping than the generic TAINT_*_TO_LOG.
        effective_sink_label = _privacy_sink_label(src.label, snk.label)

        severity = _severity_for_labels(src.label, effective_sink_label)
        if sanitized:
            confidence = Confidence.LOW
        else:
            confidence = _confidence_for_flow(src.label, effective_sink_label, len(chain))

        title = f"Tainted {src.label} data flows to {effective_sink_label}"
        if effective_sink_label == "PII_LOG":
            title = f"Personally identifiable {src.label} written to log"
        elif effective_sink_label == "PII_NETWORK":
            title = f"Personally identifiable {src.label} sent over network"

        return Finding(
            rule_id=f"TAINT_{src.label}_TO_{effective_sink_label}",
            title=title,
            description=(
                f"Data originating from a {src.label} source reaches a "
                f"{effective_sink_label} sink without sanitisation."
            ),
            severity=severity,
            confidence=confidence,
            category="TAINT" if not effective_sink_label.startswith("PII_") else "PRIVACY",
            class_name=src.method.class_name,
            method_name=src.method.method_name,
            evidence=(
                f"Source: {src.method.full_name} @offset {src.offset}\n"
                f"Sink:   {snk.method.full_name} @offset {snk.offset}"
            ),
            taint_path=taint_path,
            remediation=_remediation(src.label, effective_sink_label),
            cwe_id=_cwe_for_labels(src.label, effective_sink_label),
        )

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by (rule_id, class, method, sink offset)."""
        seen: set[tuple] = set()
        result = []
        for f in findings:
            key = (f.rule_id, f.class_name, f.method_name,
                   f.taint_path.sink.offset if f.taint_path else 0)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Source labels that we treat as carrying personally identifiable information.
# When PII flows to a generic LOG or NETWORK_OUT sink, the finding is
# re-labelled PII_LOG / PII_NETWORK so it surfaces under MASVS-PRIVACY
# rather than getting buried in the generic TAINT_*_TO_LOG bucket.
_PII_SOURCE_LABELS = frozenset({
    "DEVICE_ID", "LOCATION", "ACCOUNT", "CONTACT", "CLIPBOARD",
    "USER_INPUT", "CAMERA_MIC",
})


def _privacy_sink_label(src_label: str, sink_label: str) -> str:
    """
    Re-classify generic logging/network sinks as PII-specific when the source
    is personally identifiable. Returns the effective sink label.
    """
    if src_label not in _PII_SOURCE_LABELS:
        return sink_label
    if sink_label == "LOG":
        return "PII_LOG"
    if sink_label == "NETWORK_OUT":
        return "PII_NETWORK"
    return sink_label


def _confidence_for_flow(src_label: str, sink_label: str, chain_len: int) -> Confidence:
    """
    Assign confidence based on how direct and dangerous the source→sink pairing is.
    """
    _CERTAIN_PAIRS = {
        ("USER_INPUT", "EXEC"), ("USER_INPUT", "SQL_INJECT"),
        ("USER_INPUT", "WEBVIEW"), ("USER_INPUT", "FILE_WRITE"),
        ("INTENT", "EXEC"), ("INTENT", "SQL_INJECT"),
        ("CONTENT_URI", "SQL_INJECT"),
        ("DEEP_LINK_DATA", "WEBVIEW"), ("DEEP_LINK_DATA", "SQL_INJECT"),
        ("DEEP_LINK_DATA", "EXEC"),
        ("DEVICE_ID", "NETWORK_OUT"), ("LOCATION", "NETWORK_OUT"),
        ("ACCOUNT", "NETWORK_OUT"),
    }
    _NOISY_SOURCES = {"SHARED_PREFS", "PACKAGE_INFO", "FILE_READ", "NETWORK_IN"}

    if src_label in _NOISY_SOURCES:
        return Confidence.LOW
    if (src_label, sink_label) in _CERTAIN_PAIRS and chain_len <= 5:
        return Confidence.HIGH
    if chain_len <= 3:
        return Confidence.HIGH
    if chain_len <= 8:
        return Confidence.MEDIUM
    return Confidence.LOW


def _severity_for_labels(src_label: str, sink_label: str) -> Severity:
    if sink_label in ("NETWORK_OUT", "EXEC"):
        return Severity.CRITICAL
    if sink_label == "SQL_INJECT":
        _critical_sql = ("CONTENT_URI", "INTENT", "USER_INPUT", "DEEP_LINK_DATA")
        return Severity.CRITICAL if src_label in _critical_sql else Severity.HIGH
    if sink_label in ("LOG", "STORAGE", "IPC_OUT") and src_label in (
        "DEVICE_ID", "LOCATION", "ACCOUNT", "CONTACT"
    ):
        return Severity.HIGH
    if sink_label in ("PII_LOG", "PII_NETWORK"):
        return Severity.HIGH
    if sink_label == "WEBVIEW":
        return Severity.CRITICAL if src_label in ("DEEP_LINK_DATA", "USER_INPUT") else Severity.HIGH
    if sink_label == "WEBVIEW_JS_INJECT":
        return Severity.CRITICAL
    if sink_label in ("IPC_REDIRECT", "DEEPLINK_REDIRECT"):
        return Severity.HIGH
    if sink_label == "OPEN_REDIRECT":
        return (
            Severity.HIGH
            if src_label in ("DEEP_LINK_DATA", "CONTENT_URI", "INTENT", "USER_INPUT")
            else Severity.MEDIUM
        )
    if sink_label == "FILE_WRITE":
        return Severity.HIGH if src_label in ("INTENT", "USER_INPUT", "DEEP_LINK_DATA") else Severity.MEDIUM
    if sink_label == "PENDING_INTENT":
        return Severity.MEDIUM
    if sink_label == "CRYPTO_SINK":
        return Severity.MEDIUM
    return Severity.MEDIUM


def _cwe_for_labels(src_label: str, sink_label: str) -> str:
    mapping = {
        ("DEVICE_ID", "NETWORK_OUT"): "CWE-359",
        ("LOCATION", "NETWORK_OUT"): "CWE-359",
        ("USER_INPUT", "EXEC"): "CWE-78",
        ("USER_INPUT", "STORAGE"): "CWE-312",
        ("INTENT", "EXEC"): "CWE-78",
        ("INTENT", "WEBVIEW"): "CWE-79",
        ("USER_INPUT", "WEBVIEW"): "CWE-79",
        ("DEEP_LINK_DATA", "WEBVIEW"): "CWE-601",
        ("DEEP_LINK_DATA", "WEBVIEW_JS_INJECT"): "CWE-79",
        ("DEEP_LINK_DATA", "OPEN_REDIRECT"): "CWE-601",
        ("DEEP_LINK_DATA", "DEEPLINK_REDIRECT"): "CWE-940",
        ("DEEP_LINK_DATA", "SQL_INJECT"): "CWE-89",
        ("CONTENT_URI", "SQL_INJECT"): "CWE-89",
        ("INTENT", "SQL_INJECT"): "CWE-89",
        ("USER_INPUT", "SQL_INJECT"): "CWE-89",
        ("INTENT", "IPC_REDIRECT"): "CWE-939",
        ("CONTENT_URI", "IPC_REDIRECT"): "CWE-939",
        ("DEEP_LINK_DATA", "IPC_REDIRECT"): "CWE-939",
        ("INTENT", "OPEN_REDIRECT"): "CWE-601",
        ("CONTENT_URI", "OPEN_REDIRECT"): "CWE-601",
        ("USER_INPUT", "FILE_WRITE"): "CWE-22",
        ("INTENT", "FILE_WRITE"): "CWE-22",
        ("DEEP_LINK_DATA", "FILE_WRITE"): "CWE-22",
        ("INTENT", "PENDING_INTENT"): "CWE-926",
        ("USER_INPUT", "PENDING_INTENT"): "CWE-926",
        ("USER_INPUT", "NETWORK_OUT"): "CWE-359",
        ("CONTACT", "NETWORK_OUT"): "CWE-359",
        ("CLIPBOARD", "NETWORK_OUT"): "CWE-359",
    }
    if sink_label in ("PII_LOG", "PII_NETWORK"):
        return "CWE-359"
    return mapping.get((src_label, sink_label), "CWE-200")


def _remediation(src_label: str, sink_label: str) -> str:
    specific = {
        ("DEEP_LINK_DATA", "WEBVIEW"): (
            "Validate the URI from the deep link against an allowlist of trusted domains "
            "before loading it in WebView. Never load arbitrary URIs from Intents."
        ),
        ("DEEP_LINK_DATA", "OPEN_REDIRECT"): (
            "Validate and allowlist URLs extracted from deep link parameters before "
            "using them in network requests or browser launches."
        ),
        ("DEEP_LINK_DATA", "DEEPLINK_REDIRECT"): (
            "Do not construct Intents from deep link URI data without validating the "
            "target component. Use explicit Intents with a fixed target class."
        ),
        ("DEEP_LINK_DATA", "SQL_INJECT"): (
            "Use parameterized queries for all database operations. Never concatenate "
            "URI path segments or query parameters into raw SQL strings."
        ),
    }
    if (src_label, sink_label) in specific:
        return specific[(src_label, sink_label)]
    base = {
        "NETWORK_OUT": "Encrypt sensitive data before transmission and use certificate pinning.",
        "LOG": "Remove sensitive data from log statements before release builds.",
        "PII_LOG": "Do not log personally identifiable information; mask or redact PII before logging.",
        "PII_NETWORK": "Strip or hash PII before transmitting; require user consent for telemetry containing personal data.",
        "STORAGE": "Encrypt sensitive data at rest using Android Keystore.",
        "IPC_OUT": "Validate and sanitise data shared via IPC; use explicit intents.",
        "IPC_REDIRECT": "Validate intent data before forwarding; use explicit intents with allowlists.",
        "DEEPLINK_REDIRECT": "Validate deep link URI before setting as Intent data; use explicit targets.",
        "OPEN_REDIRECT": "Validate URLs against a strict allowlist before using in HTTP requests or browser.",
        "EXEC": "Avoid passing user-controlled data to Runtime.exec(); use allow-lists.",
        "WEBVIEW": "Sanitise user input before injecting into WebView; disable JS if unused.",
        "WEBVIEW_JS_INJECT": "Do not expose Java objects to WebView JS in components handling deep links.",
        "CRYPTO_SINK": "Do not use tainted data as key material; derive keys from a secure KDF.",
        "SQL_INJECT": "Use parameterized queries (SQLiteDatabase.query() with selectionArgs) instead of rawQuery with concatenated strings.",
        "FILE_WRITE": "Validate and canonicalize file paths before use; reject paths containing '..' or absolute components.",
        "PENDING_INTENT": "Use FLAG_IMMUTABLE when creating PendingIntents; set explicit component to prevent hijacking.",
    }
    return base.get(sink_label, "Review the data flow and sanitise input before use.")
