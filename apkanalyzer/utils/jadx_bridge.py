"""
Optional JADX subprocess bridge.

When the `jadx` binary is on PATH this module decompiles the APK to Java
source so YAML rules can grep through patterns that smali bytecode
obscures (Kotlin lambdas, coroutine state machines, sealed-class
deserialisation glue). The bridge is strictly optional — when jadx is
absent everything else still works; this module simply returns None.

The CLI invocation is intentionally narrow:
    jadx --no-res --no-imports -d <out_dir> <apk_path>

We disable resource extraction (`--no-res`) because apktool already
handles resources, and we suppress import lines (`--no-imports`) so the
generated Java is line-grep friendly. Stderr is captured to
`<out_dir>/jadx.log`; stdout is discarded.
"""

from __future__ import annotations

import functools
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def is_available() -> bool:
    """True if a `jadx` executable is reachable on PATH."""
    return shutil.which("jadx") is not None


def decompile(
    apk_path: str,
    out_dir: str,
    *,
    timeout: int = 600,
) -> Optional[Path]:
    """
    Run jadx against `apk_path`, write Java source under `out_dir`.

    Returns the Path to the Java source root on success, or None when
    jadx is missing, the subprocess fails, or it exceeds `timeout`.
    Errors are logged at INFO (missing tool) or WARNING (run failure)
    so a CI pipeline that turns warnings into failures can spot them.
    """
    if not is_available():
        # One INFO log per process — the bridge is opt-in.
        logger.info("jadx not on PATH; skipping Java decompilation stage")
        return None

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    log_file = out / "jadx.log"

    cmd = [
        "jadx",
        "--no-res",
        "--no-imports",
        "-d", str(out),
        str(apk_path),
    ]

    try:
        with log_file.open("w", encoding="utf-8") as logf:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=logf,
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired:
        logger.warning("jadx timed out after %ds on %s", timeout, apk_path)
        return None
    except OSError as exc:
        logger.warning("jadx failed to launch: %s", exc)
        return None

    # Treat exit 0 and 1 as usable — jadx returns 1 when *some* classes
    # failed to decompile but the rest of the source tree is valid.
    if proc.returncode not in (0, 1):
        logger.warning("jadx exited %d (see %s)", proc.returncode, log_file)
        return None

    sources = out / "sources"
    return sources if sources.is_dir() else out
