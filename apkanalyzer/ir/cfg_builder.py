"""
Per-method CFG builder using androguard's BasicBlock API.

Design notes
------------
- androguard natively exposes BasicBlocks via MethodAnalysis.get_basic_blocks().
  We wrap them in our own CFGMethod/BasicBlock so upper layers never import
  androguard directly.
- Instructions are stored as dicts with keys: offset, mnemonic, operands.
  This makes them serialisable and easy to pattern-match in analysers.
- We propagate taint_in/taint_out as empty sets; the taint engine fills them.
"""

from __future__ import annotations

import logging
from typing import Optional

from apkanalyzer.ir.models import BasicBlock, CFGMethod, MethodDescriptor

logger = logging.getLogger(__name__)


# Android 8+ (API 26) opcodes that use call-site references instead of method refs.
# We normalise their mnemonics so the engine treats them as regular invocations.
_POLY_OPCODE_MAP = {
    "invoke-polymorphic": "invoke-virtual",
    "invoke-polymorphic/range": "invoke-virtual",
    "invoke-custom": "invoke-static",
    "invoke-custom/range": "invoke-static",
    "const-method-handle": "const-string",
    "const-method-type": "const-string",
}


def _instr_to_dict(instr) -> dict:
    """Flatten an androguard Instruction to a plain dict."""
    operands = []
    try:
        for kind, value, raw in instr.get_operands():
            operands.append({"kind": kind, "value": value, "raw": str(raw)})
    except Exception:
        pass

    mnemonic = instr.get_name().lower()
    # Normalise Android 8+ polymorphic/custom invoke opcodes
    mnemonic = _POLY_OPCODE_MAP.get(mnemonic, mnemonic)

    raw_output = ""
    try:
        raw_output = instr.get_output() if hasattr(instr, "get_output") else ""
    except Exception:
        pass

    return {
        "offset": instr.get_address(),
        "mnemonic": mnemonic,
        "operands": operands,
        "raw": raw_output,
    }


def build_cfg(method_analysis, descriptor: MethodDescriptor) -> CFGMethod:
    """
    Build a CFGMethod from an androguard MethodAnalysis.

    Parameters
    ----------
    method_analysis : androguard.core.analysis.analysis.MethodAnalysis
    descriptor      : MethodDescriptor  (pre-built by caller)
    """
    cfg = CFGMethod(descriptor=descriptor)

    try:
        bb_iter = method_analysis.get_basic_blocks().get()
    except Exception as exc:
        logger.debug("Could not get basic blocks for %s: %s", descriptor.full_name, exc)
        return cfg

    first = True
    for bb in bb_iter:
        block_id = str(bb.start)
        instructions = [_instr_to_dict(i) for i in bb.get_instructions()]

        block = BasicBlock(
            block_id=block_id,
            method=descriptor,
            instructions=instructions,
        )
        cfg.blocks[block_id] = block

        if first:
            cfg.entry_block = block_id
            first = False

    # Wire up successor/predecessor edges
    try:
        for bb in method_analysis.get_basic_blocks().get():
            block_id = str(bb.start)
            for _, child_bb in bb.get_next():
                child_id = str(child_bb.start)
                if block_id in cfg.blocks and child_id in cfg.blocks:
                    cfg.blocks[block_id].successors.append(child_id)
                    cfg.blocks[child_id].predecessors.append(block_id)
    except Exception as exc:
        logger.debug("CFG edge wiring failed for %s: %s", descriptor.full_name, exc)

    # Exit blocks: no successors
    cfg.exit_blocks = [
        bid for bid, block in cfg.blocks.items() if not block.successors
    ]

    return cfg


def get_all_instructions(cfg: CFGMethod) -> list[dict]:
    """Flatten all instructions in program order (by offset)."""
    instrs = []
    for block in cfg.blocks.values():
        instrs.extend(block.instructions)
    return sorted(instrs, key=lambda i: i["offset"])
