"""
Native / JNI taint summaries.

What this is
------------
A name-driven bestiary describing what happens to taint when control crosses
the Java → native boundary. The static analyser cannot follow the C/C++ side
of `Java_<Class>_<method>` exports, so historically every native call was a
black hole that swallowed taint provenance.

Each :class:`NativeSummary` declares, for one (class_pattern, method_pattern)
signature, how taint should flow:

    * `propagate_args` — argument indices whose taint should be unioned
      onto the return value (the typical "decrypt(byte[]) → tainted output").
    * `taints_return` — synthetic source labels stamped onto the return value
      regardless of inputs (e.g., `Java_com_app_Crypto_loadKey` always returns
      key material → `CRYPTO_KEY`).
    * `sanitises_args` — sanitiser labels applied to specific argument
      registers, mirroring the YAML sanitiser machinery (e.g., a JNI
      `hash_password` is a one-way hash → marks its arg as `HMAC_DIGEST`).
    * `sinks_args` — sink labels with the tainted-arg index when the native
      function is itself a sink (e.g., `native_post(url, body)` is a
      `NETWORK_OUT` sink consuming arg 1).

This is a deliberate simplification of NDroid / JN-SAF — we do not lift
the native side, we *summarise* it. The cost is that every native function
needs an entry to be modelled. The benefit is zero-emulation overhead and
no LLVM toolchain dependency.

Default bestiary
----------------
Hard-coded entries cover the JNI patterns we have seen most often in the
real-world APK corpus (StringObfuscator-style decryptors, OpenSSL wrappers,
crypto libraries that ship native symbols). Users extend it via YAML:

    - class: "Lcom/example/Crypto;"
      method: "decrypt"
      propagate_args: [0]            # arg 0 → return
      taints_return: ["CRYPTO_KEY"]  # always tainted

The loader is shared with the rest of the taint config — the same
`load_native_summaries(paths)` helper feeds both CLI `--native-summaries` and
the auto-loaded `rules/native_summaries.yaml`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NativeSummary:
    """One summary spec for a (class, method) signature.

    The matcher is pattern-based — `class_pattern` is the exact Dalvik class
    name (e.g., ``Lcom/foo/Crypto;``) and `method_pattern` is the method
    name. Use ``"*"`` as a wildcard for either field to match every method
    or every class — typically only the latter is useful (e.g., wildcard
    *method* on a class whose methods are all known JNI shims).
    """

    class_pattern: str
    method_pattern: str
    # Arg indices whose taint flows to the return register.
    propagate_args: tuple[int, ...] = field(default_factory=tuple)
    # Labels that are always stamped on the return register, regardless
    # of input taint. Use for native sources (loadKey, getDeviceFingerprint).
    taints_return: tuple[str, ...] = field(default_factory=tuple)
    # Sanitiser labels applied to each (arg_index, label) tuple. Drives
    # the same neutralisation machinery as Java sanitisers.
    sanitises_args: tuple[tuple[int, str], ...] = field(default_factory=tuple)
    # Native function is itself a sink: list of (arg_index, sink_label).
    sinks_args: tuple[tuple[int, str], ...] = field(default_factory=tuple)


# The default bestiary. Entries are intentionally conservative — only
# patterns we have observed across multiple unrelated APKs make it in.
# Extend through YAML rather than editing this list, so user policy is
# version-controlled separately from the engine.
DEFAULT_BESTIARY: tuple[NativeSummary, ...] = (
    # ── Generic decrypt / decode wrappers (StringObfuscator, Bangcle, etc.) ──
    NativeSummary("*", "decrypt", propagate_args=(0,)),
    NativeSummary("*", "decryptString", propagate_args=(0,)),
    NativeSummary("*", "decryptBytes", propagate_args=(0,)),
    NativeSummary("*", "decode", propagate_args=(0,)),
    NativeSummary("*", "deobfuscate", propagate_args=(0,)),
    NativeSummary("*", "unwrap", propagate_args=(0,)),
    NativeSummary("*", "decodeString", propagate_args=(0,)),

    # ── Generic encrypt / encode wrappers ────────────────────────────────
    NativeSummary("*", "encrypt", propagate_args=(0,)),
    NativeSummary("*", "encryptString", propagate_args=(0,)),
    NativeSummary("*", "encryptBytes", propagate_args=(0,)),
    NativeSummary("*", "encode", propagate_args=(0,)),

    # ── One-way hashes — sanitiser, not propagator ──────────────────────
    NativeSummary("*", "hash", sanitises_args=((0, "HMAC_DIGEST"),)),
    NativeSummary("*", "hashBytes", sanitises_args=((0, "HMAC_DIGEST"),)),
    NativeSummary("*", "sha256", sanitises_args=((0, "HMAC_DIGEST"),)),
    NativeSummary("*", "sha512", sanitises_args=((0, "HMAC_DIGEST"),)),
    NativeSummary("*", "hmac", sanitises_args=((0, "HMAC_DIGEST"),)),

    # ── Native sources — always return tainted material ─────────────────
    NativeSummary("*", "loadKey", taints_return=("CRYPTO_KEY",)),
    NativeSummary("*", "getApiKey", taints_return=("CRYPTO_KEY",)),
    NativeSummary("*", "getSecret", taints_return=("CRYPTO_KEY",)),
    NativeSummary("*", "getDeviceFingerprint", taints_return=("DEVICE_ID",)),
    NativeSummary("*", "getInstallationId", taints_return=("DEVICE_ID",)),

    # ── Native sinks — common HTTP/socket bridges from C ────────────────
    NativeSummary("*", "nativePost", sinks_args=((1, "NETWORK_OUT"),)),
    NativeSummary("*", "nativeSend", sinks_args=((1, "NETWORK_OUT"),)),
    NativeSummary("*", "nativeWrite", sinks_args=((1, "FILE_WRITE"),)),
    NativeSummary("*", "nativeExec", sinks_args=((0, "EXEC"),)),
)


# ---------------------------------------------------------------------------
# Lookup index
# ---------------------------------------------------------------------------

class NativeSummaryIndex:
    """O(1) lookup keyed by (class, method) with wildcard fallback.

    Both class and method may be ``"*"`` in a spec, so we maintain four
    dispatch maps and consult them in specificity order:

        1. exact class + exact method
        2. exact class + wildcard method
        3. wildcard class + exact method
        4. wildcard class + wildcard method
    """

    def __init__(self, specs: list[NativeSummary]) -> None:
        self._exact: dict[tuple[str, str], list[NativeSummary]] = {}
        self._cls_wild: dict[str, list[NativeSummary]] = {}
        self._meth_wild: dict[str, list[NativeSummary]] = {}
        self._all: list[NativeSummary] = []
        for spec in specs:
            cls_wild = spec.class_pattern == "*"
            meth_wild = spec.method_pattern == "*"
            if cls_wild and meth_wild:
                self._all.append(spec)
            elif cls_wild:
                self._meth_wild.setdefault(spec.method_pattern, []).append(spec)
            elif meth_wild:
                self._cls_wild.setdefault(spec.class_pattern, []).append(spec)
            else:
                self._exact.setdefault(
                    (spec.class_pattern, spec.method_pattern), []
                ).append(spec)

    def lookup(self, class_name: str, method_name: str) -> list[NativeSummary]:
        """Return every summary that applies to this (class, method)."""
        out: list[NativeSummary] = []
        out.extend(self._exact.get((class_name, method_name), ()))
        out.extend(self._cls_wild.get(class_name, ()))
        out.extend(self._meth_wild.get(method_name, ()))
        out.extend(self._all)
        return out


def build_native_index(extra: Optional[list[NativeSummary]] = None) -> NativeSummaryIndex:
    """Build a `NativeSummaryIndex` from defaults plus optional user specs."""
    specs = list(DEFAULT_BESTIARY)
    if extra:
        specs.extend(extra)
    return NativeSummaryIndex(specs)


# ---------------------------------------------------------------------------
# YAML / JSON loader
# ---------------------------------------------------------------------------

def load_native_summaries(paths: Optional[list[str]]) -> list[NativeSummary]:
    """Load NativeSummary entries from one or more YAML/JSON files.

    File shape (either YAML or JSON, same schema)::

        native_summaries:
          - class: "Lcom/example/Crypto;"
            method: "decrypt"
            propagate_args: [0]
            taints_return: ["CRYPTO_KEY"]
            sanitises_args:
              - [0, "HMAC_DIGEST"]
            sinks_args:
              - [1, "NETWORK_OUT"]

    Returns an empty list when `paths` is None/empty. Malformed entries are
    logged and skipped — never abort the scan because the user mistyped one
    line in a bestiary file.
    """
    out: list[NativeSummary] = []
    if not paths:
        return out

    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            logger.warning("native-summaries file not found: %s", path)
            continue
        try:
            text = path.read_text()
            if path.suffix.lower() in (".yaml", ".yml"):
                import yaml
                data = yaml.safe_load(text) or {}
            else:
                data = json.loads(text) if text.strip() else {}
        except Exception as exc:
            logger.error("Failed to parse native summaries %s: %s", path, exc)
            continue

        if not isinstance(data, dict):
            logger.warning("%s: top-level must be a mapping", path)
            continue

        entries = data.get("native_summaries") or data.get("summaries") or []
        for entry in entries:
            spec = _build_spec(entry, path)
            if spec is not None:
                out.append(spec)

    if out:
        logger.info("Loaded %d native summary entries from %d file(s)",
                    len(out), len(paths))
    return out


def _build_spec(entry: dict, source_file: Path) -> Optional[NativeSummary]:
    if not isinstance(entry, dict):
        logger.warning("%s: native summary entry is not a mapping: %r",
                       source_file, entry)
        return None
    cls = entry.get("class") or entry.get("class_pattern")
    method = entry.get("method") or entry.get("method_pattern")
    if not (cls and method):
        logger.warning("%s: native summary missing class/method: %r",
                       source_file, entry)
        return None
    try:
        return NativeSummary(
            class_pattern=str(cls),
            method_pattern=str(method),
            propagate_args=tuple(int(i) for i in (entry.get("propagate_args") or ())),
            taints_return=tuple(str(s) for s in (entry.get("taints_return") or ())),
            sanitises_args=tuple(
                (int(i), str(lbl))
                for i, lbl in (entry.get("sanitises_args") or ())
            ),
            sinks_args=tuple(
                (int(i), str(lbl))
                for i, lbl in (entry.get("sinks_args") or ())
            ),
        )
    except (TypeError, ValueError) as exc:
        logger.warning("%s: invalid native summary %r: %s",
                       source_file, entry, exc)
        return None


# ---------------------------------------------------------------------------
# Auto-load helper
# ---------------------------------------------------------------------------

def autoload_default_bestiary() -> list[NativeSummary]:
    """Look for `rules/native_summaries.yaml` next to the package and load it.

    Lets users extend the bestiary by dropping a YAML file alongside the
    other rule files without needing to pass `--native-summaries` on the
    CLI. Returns an empty list when the file is missing.
    """
    rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "rules"
    candidate = rules_dir / "native_summaries.yaml"
    if candidate.is_file():
        return load_native_summaries([str(candidate)])
    return []
