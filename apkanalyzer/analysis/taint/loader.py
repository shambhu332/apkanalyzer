"""
Load user-supplied taint sources, sinks, and sanitizers from JSON or YAML.

File format (either JSON or YAML — the same shape):

    sources:
      - class: "Lcom/example/MySdk;"
        method: "getApiKey"
        label: "DEVICE_ID"
        param_index: -1            # optional, defaults to -1 (return value)
    sinks:
      - class: "Lcom/example/MyLogger;"
        method: "log"
        label: "LOG"
        tainted_param: 0           # optional, defaults to 0
    sanitizers:
      - class: "Lcom/example/Escaper;"
        method: "html"
        label: "HTML_ESCAPE"
        neutralizes: ["WEBVIEW", "LOG"]

Top-level may contain any subset of `sources`, `sinks`, `sanitizers`. Files
without a recognised section are ignored with a warning.

The loader is forgiving: malformed entries are skipped with a warning rather
than aborting the run, so a typo in one entry does not block the whole scan.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from apkanalyzer.analysis.taint.sources import TaintSourceSpec
from apkanalyzer.analysis.taint.sinks import TaintSinkSpec
from apkanalyzer.analysis.taint.sanitizers import SanitizerSpec

logger = logging.getLogger(__name__)


def _read_file(path: Path) -> dict:
    text = path.read_text()
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError(
                f"PyYAML is required to load {path}; install pyyaml or use JSON"
            ) from exc
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) if text.strip() else {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be a mapping")
    return data


def load_specs(paths: list[str] | None) -> tuple[
    list[TaintSourceSpec], list[TaintSinkSpec], list[SanitizerSpec]
]:
    """
    Load and merge taint specs from one or more files.

    Returns three lists (sources, sinks, sanitizers) ready to pass into
    `build_*_index(extra_*=...)` or directly into `TaintEngine(...)`.

    Unknown keys in entries are ignored. Missing required keys cause that
    entry to be skipped with a warning — we don't abort the scan because a
    user-supplied spec file is *additive* by intent.
    """
    sources: list[TaintSourceSpec] = []
    sinks: list[TaintSinkSpec] = []
    sanitizers: list[SanitizerSpec] = []
    if not paths:
        return sources, sinks, sanitizers

    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            logger.warning("Spec file not found: %s", path)
            continue
        try:
            data = _read_file(path)
        except Exception as exc:
            logger.error("Failed to parse %s: %s", path, exc)
            continue

        for entry in data.get("sources") or []:
            spec = _build_source(entry, path)
            if spec is not None:
                sources.append(spec)

        for entry in data.get("sinks") or []:
            spec = _build_sink(entry, path)
            if spec is not None:
                sinks.append(spec)

        for entry in data.get("sanitizers") or []:
            spec = _build_sanitizer(entry, path)
            if spec is not None:
                sanitizers.append(spec)

    logger.info(
        "Loaded %d extra sources, %d sinks, %d sanitizers from %d file(s)",
        len(sources), len(sinks), len(sanitizers), len(paths),
    )
    return sources, sinks, sanitizers


def _build_source(entry: dict, source_file: Path) -> TaintSourceSpec | None:
    if not isinstance(entry, dict):
        logger.warning("%s: source entry is not a mapping: %r", source_file, entry)
        return None
    cls = entry.get("class") or entry.get("class_pattern")
    method = entry.get("method") or entry.get("method_pattern")
    label = entry.get("label")
    if not (cls and method and label):
        logger.warning("%s: source missing class/method/label: %r", source_file, entry)
        return None
    try:
        return TaintSourceSpec(
            class_pattern=str(cls),
            method_pattern=str(method),
            label=str(label),
            param_index=int(entry.get("param_index", -1)),
        )
    except (TypeError, ValueError) as exc:
        logger.warning("%s: invalid source %r: %s", source_file, entry, exc)
        return None


def _build_sink(entry: dict, source_file: Path) -> TaintSinkSpec | None:
    if not isinstance(entry, dict):
        logger.warning("%s: sink entry is not a mapping: %r", source_file, entry)
        return None
    cls = entry.get("class") or entry.get("class_pattern")
    method = entry.get("method") or entry.get("method_pattern")
    label = entry.get("label")
    if not (cls and method and label):
        logger.warning("%s: sink missing class/method/label: %r", source_file, entry)
        return None
    try:
        return TaintSinkSpec(
            class_pattern=str(cls),
            method_pattern=str(method),
            label=str(label),
            tainted_param=int(entry.get("tainted_param", 0)),
        )
    except (TypeError, ValueError) as exc:
        logger.warning("%s: invalid sink %r: %s", source_file, entry, exc)
        return None


def _build_sanitizer(entry: dict, source_file: Path) -> SanitizerSpec | None:
    if not isinstance(entry, dict):
        logger.warning("%s: sanitizer entry is not a mapping: %r", source_file, entry)
        return None
    cls = entry.get("class") or entry.get("class_pattern")
    method = entry.get("method") or entry.get("method_pattern")
    label = entry.get("label")
    if not (cls and method and label):
        logger.warning("%s: sanitizer missing class/method/label: %r", source_file, entry)
        return None
    neutralizes = entry.get("neutralizes") or []
    if isinstance(neutralizes, str):
        neutralizes = [neutralizes]
    try:
        return SanitizerSpec(
            class_pattern=str(cls),
            method_pattern=str(method),
            label=str(label),
            neutralizes=set(str(x) for x in neutralizes),
        )
    except (TypeError, ValueError) as exc:
        logger.warning("%s: invalid sanitizer %r: %s", source_file, entry, exc)
        return None
