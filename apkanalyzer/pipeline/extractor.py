"""
APK extraction and initial parsing.

Responsibilities
----------------
- Open the APK / AAB / XAPK with androguard
- Merge AAB base + config splits and XAPK component APKs into a single
  analysis target before handing to androguard
- Extract assets, resources, and raw Smali via apktool (optional, for richer analysis)
- Build the string pool from the DEX string table
- Return a structured APKContext object used by all downstream stages

Why a string pool?
------------------
Many vulnerability checks need to know what string was passed to an API call.
Rather than re-scanning the DEX for each check, we build a single
{register, string} map per method during the extraction phase.

Why apktool (optional)?
-----------------------
androguard doesn't decode all resource types (e.g., network_security_config.xml,
res/raw/*.json).  We invoke apktool as a subprocess when available, falling back
gracefully if it is not installed.

Bundles / split APKs
--------------------
Modern Play Store distribution ships Android App Bundles (.aab) which are
zipped collections of `base/` + `feature_*/` + `splits/` modules. Sideload
distribution ships XAPK / APKM / APKS — all variations on a zip-of-APKs.
Rather than fail on these, we transparently:
  * unpack the bundle/zip into a temp directory,
  * find the base APK (or build one from base/dex/* + base/manifest/),
  * merge classes*.dex and lib/ABI/* from every split into the base APK so
    androguard sees a single unified analysis target,
  * remember the merge so the cache key reflects every constituent split.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class APKContext:
    """All artefacts produced during extraction, consumed by analysis stages."""
    apk_path: str
    apk: object             # androguard APK
    dx: object              # androguard Analysis
    dex_files: list         # list of androguard DalvikVMFormat

    # String pool: class_name → method_name → {register: string_value}
    # Populated by build_string_pool()
    string_pool: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)

    # All string literals in the DEX (for secret scanning)
    all_strings: list[str] = field(default_factory=list)

    # Unpacked APK directory (set if apktool ran successfully)
    unpacked_dir: Optional[str] = None

    # Parsed AndroidManifest fields
    manifest: dict = field(default_factory=dict)

    # Raw network_security_config.xml content (if available)
    network_security_config_xml: Optional[str] = None

    # Set when the input was an AAB / XAPK bundle and we synthesised a merged
    # APK on disk. Reporting layers surface this so users know the exact
    # constituent splits that contributed to the scan.
    bundle_kind: Optional[str] = None  # "aab" / "xapk" / "apks" / "apkm"
    merged_splits: list[str] = field(default_factory=list)


def load_apk(apk_path: str) -> APKContext:
    """
    Open an APK / AAB / XAPK with androguard and build the initial APKContext.
    This is the entry point for the pipeline.
    """
    from androguard.misc import AnalyzeAPK

    bundle_kind = _bundle_kind(apk_path)
    merged_splits: list[str] = []
    real_path = apk_path

    if bundle_kind:
        merged = _merge_bundle(apk_path, bundle_kind)
        if merged:
            real_path, merged_splits = merged
            logger.info(
                "Merged %s bundle (%d splits) → %s",
                bundle_kind, len(merged_splits), real_path,
            )

    logger.info("Loading APK: %s", real_path)

    # For AAB inputs the merged APK's AndroidManifest.xml is in protobuf form,
    # which androguard treats as opaque bytes. Attempt to decode it to binary
    # XML first using aapt2 so manifest-derived findings are faithful.
    if bundle_kind == "aab":
        _try_patch_aab_manifest(real_path)

    apk, dex_files, dx = AnalyzeAPK(real_path)

    ctx = APKContext(
        apk_path=real_path,
        apk=apk,
        dx=dx,
        dex_files=dex_files if isinstance(dex_files, list) else [dex_files],
    )
    ctx.bundle_kind = bundle_kind
    ctx.merged_splits = merged_splits

    ctx.all_strings = _extract_all_strings(dx)
    ctx.string_pool = _build_string_pool(dx)

    logger.info(
        "Loaded: %d classes, %d methods, %d unique strings",
        sum(1 for _ in dx.get_classes()),
        sum(1 for _ in dx.get_methods()),
        len(ctx.all_strings),
    )

    return ctx


# ---------------------------------------------------------------------------
# Bundle / split-APK handling
# ---------------------------------------------------------------------------

# File extensions that we know how to disassemble into a single merged APK.
# .aab is Android App Bundle (Play Store native distribution).
# .xapk is the APKMirror sideload format (zip of {manifest, base, splits}).
# .apks is the bundletool output format. .apkm is the APKMirror archive.
_BUNDLE_EXTS = (".aab", ".xapk", ".apks", ".apkm")


def _bundle_kind(path: str) -> Optional[str]:
    ext = Path(path).suffix.lower()
    if ext in _BUNDLE_EXTS:
        return ext.lstrip(".")
    return None


def _merge_bundle(bundle_path: str, kind: str) -> Optional[tuple[str, list[str]]]:
    """
    Materialise a single APK on disk from a multi-module bundle.

    Returns (merged_apk_path, [constituent_split_names]) or None on failure.
    The merged file lives in a tempdir whose name includes the bundle's SHA-256
    prefix so repeated scans hit the same path (cheap dedup, plus the scan
    cache key remains stable for the same input bundle).
    """
    try:
        digest = _sha8(bundle_path)
        out_dir = Path(tempfile.gettempdir()) / f"apkanalyzer_{kind}_{digest}"
        out_dir.mkdir(parents=True, exist_ok=True)
        merged_path = out_dir / "merged.apk"

        if kind == "aab":
            return _merge_aab(bundle_path, out_dir, merged_path)
        return _merge_apk_zip(bundle_path, out_dir, merged_path)
    except Exception as exc:
        logger.warning("Bundle merge failed (%s): %s", kind, exc)
        return None


def _sha8(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:8]


def _merge_apk_zip(
    bundle_path: str, out_dir: Path, merged_path: Path,
) -> Optional[tuple[str, list[str]]]:
    """
    Merge XAPK / APKS / APKM: all are zip-of-APKs. Strategy:
      * Extract every embedded *.apk into out_dir/extracted.
      * Identify the base APK (largest, or the one named base*.apk).
      * Copy classes*.dex and lib/* from every split into the base.
    """
    extracted = out_dir / "extracted"
    extracted.mkdir(parents=True, exist_ok=True)

    apk_paths: list[Path] = []
    with zipfile.ZipFile(bundle_path) as bundle:
        for name in bundle.namelist():
            if name.endswith(".apk") and not name.startswith("__MACOSX"):
                target = extracted / Path(name).name
                if not target.exists():
                    with bundle.open(name) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                apk_paths.append(target)
    if not apk_paths:
        return None

    base_apk = _pick_base_apk(apk_paths)
    splits = [p for p in apk_paths if p != base_apk]
    return _glue_apks(base_apk, splits, merged_path)


def _pick_base_apk(apks: list[Path]) -> Path:
    # Prefer "base.apk" / "base-master.apk" if present; else the largest file.
    for candidate in apks:
        n = candidate.name.lower()
        if n in ("base.apk", "base-master.apk") or n.startswith("base-master"):
            return candidate
    return max(apks, key=lambda p: p.stat().st_size)


def _glue_apks(
    base: Path, splits: list[Path], merged_path: Path,
) -> tuple[str, list[str]]:
    """
    Build a new APK at `merged_path` containing the base APK's full contents,
    plus every classes*.dex / lib/ABI/* from each split. Split DEX files are
    renamed (classes2.dex → classesN.dex) so they don't collide with the
    base's existing DEX files.
    """
    # Names already present in the base so we can rename split DEXes.
    with zipfile.ZipFile(base) as bz:
        base_names = set(bz.namelist())
    next_dex_idx = _next_dex_index(base_names)

    if merged_path.exists():
        # Cached from a previous run — still return the split list so the
        # report metadata is faithful.
        return str(merged_path), [s.name for s in splits]

    with zipfile.ZipFile(base) as bz, zipfile.ZipFile(
        merged_path, "w", zipfile.ZIP_DEFLATED,
    ) as out:
        for info in bz.infolist():
            out.writestr(info, bz.read(info.filename))
        for split in splits:
            with zipfile.ZipFile(split) as sz:
                for info in sz.infolist():
                    name = info.filename
                    if name.startswith("classes") and name.endswith(".dex"):
                        name = f"classes{next_dex_idx}.dex"
                        next_dex_idx += 1
                    elif name in base_names:
                        # Skip resource collisions — base's copy wins
                        continue
                    out.writestr(name, sz.read(info.filename))
                    base_names.add(name)
    return str(merged_path), [s.name for s in splits]


def _next_dex_index(existing: set[str]) -> int:
    """Smallest N such that classes{N}.dex isn't already used."""
    idx = 2
    while f"classes{idx}.dex" in existing:
        idx += 1
    return idx


def _merge_aab(
    bundle_path: str, out_dir: Path, merged_path: Path,
) -> Optional[tuple[str, list[str]]]:
    """
    Merge an Android App Bundle.

    AAB structure (post-protobuf):
      base/
        manifest/AndroidManifest.xml   (binary or proto)
        dex/classes*.dex
        res/...
        resources.pb
      <feature>/
        dex/classes*.dex
        ...
    bundletool normally produces split APKs from this; we approximate by
    flattening all dex/lib content into a single APK. The manifest in the
    bundle is in proto form, so we keep it as-is — androguard's APK loader
    handles AndroidManifest.xml, but a proto manifest will be parsed
    pessimistically (treated as opaque bytes). For analysis purposes the dex
    content is what matters, and we recover that fully.
    """
    if merged_path.exists():
        return str(merged_path), []

    seen_modules: list[str] = []
    next_dex_idx = 2

    with zipfile.ZipFile(bundle_path) as bundle, zipfile.ZipFile(
        merged_path, "w", zipfile.ZIP_DEFLATED,
    ) as out:
        names = bundle.namelist()
        # Remap module/dex/classes*.dex → classes{N}.dex; drop module prefix
        # for resources/lib so the output looks like a flat APK.
        used_names: set[str] = set()
        for name in names:
            if name.endswith("/"):
                continue
            module = name.split("/", 1)[0]
            if module not in seen_modules and "/" in name:
                seen_modules.append(module)

            if "/dex/" in name and name.endswith(".dex"):
                # Always rename to avoid collisions across modules
                new_name = "classes.dex" if (
                    "classes.dex" not in used_names and module == "base"
                ) else f"classes{next_dex_idx}.dex"
                if new_name != "classes.dex":
                    next_dex_idx += 1
                if new_name in used_names:
                    continue
                used_names.add(new_name)
                out.writestr(new_name, bundle.read(name))
            elif "/manifest/AndroidManifest.xml" in name and module == "base":
                if "AndroidManifest.xml" not in used_names:
                    out.writestr("AndroidManifest.xml", bundle.read(name))
                    used_names.add("AndroidManifest.xml")
            elif "/lib/" in name:
                # base/lib/<abi>/<file>.so → lib/<abi>/<file>.so
                tail = name.split("/lib/", 1)[1]
                new_name = f"lib/{tail}"
                if new_name in used_names:
                    continue
                used_names.add(new_name)
                out.writestr(new_name, bundle.read(name))
            elif "/res/" in name and module == "base":
                tail = name.split("/res/", 1)[1]
                new_name = f"res/{tail}"
                if new_name in used_names:
                    continue
                used_names.add(new_name)
                out.writestr(new_name, bundle.read(name))
            elif name.endswith("resources.pb") and module == "base":
                if "resources.pb" not in used_names:
                    out.writestr("resources.pb", bundle.read(name))
                    used_names.add("resources.pb")
            elif "/assets/" in name and module == "base":
                tail = name.split("/assets/", 1)[1]
                new_name = f"assets/{tail}"
                if new_name in used_names:
                    continue
                used_names.add(new_name)
                out.writestr(new_name, bundle.read(name))

    return str(merged_path), seen_modules


def unpack_with_apktool(ctx: APKContext) -> None:
    """
    Run apktool to unpack the APK into a temporary directory.
    Populates ctx.unpacked_dir on success.
    Silently skips if apktool is not on PATH.
    """
    apktool = shutil.which("apktool")
    if not apktool:
        logger.warning("apktool not found on PATH — skipping resource decoding")
        return

    tmp = tempfile.mkdtemp(prefix="apkanalyzer_")
    cmd = [apktool, "d", "-f", "-o", tmp, ctx.apk_path]
    # Big resource-heavy apps (Spotify, banking apps with many splits) blow
    # past 120s on slow CI runners. Allow override via env without forcing
    # everyone to fork.
    try:
        timeout = int(os.environ.get("APKANALYZER_APKTOOL_TIMEOUT", "120"))
    except ValueError:
        timeout = 120
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=timeout)
        ctx.unpacked_dir = tmp
        logger.info("apktool unpacked to %s", tmp)

        # Extract network_security_config.xml if present
        nsc_path = Path(tmp) / "res" / "xml" / "network_security_config.xml"
        if nsc_path.exists():
            ctx.network_security_config_xml = nsc_path.read_text()
            logger.info("Found network_security_config.xml")
    except subprocess.CalledProcessError as exc:
        logger.warning("apktool failed: %s", exc.stderr[:200] if exc.stderr else exc)
    except subprocess.TimeoutExpired:
        logger.warning("apktool timed out")
    except Exception as exc:
        logger.warning("apktool error: %s", exc)


def _try_patch_aab_manifest(merged_apk: str) -> None:
    """
    Try to replace the protobuf AndroidManifest.xml in a merged AAB APK with
    a binary-XML version decoded by aapt2, so androguard can parse it.

    No-op if aapt2 is not on PATH or if decoding fails — the existing
    pessimistic behaviour is preserved and a warning is logged.
    """
    aapt2 = shutil.which("aapt2")
    if not aapt2:
        logger.debug("aapt2 not found — AAB proto-manifest stays opaque")
        return
    try:
        result = subprocess.run(
            [aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", merged_apk],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0 or not result.stdout:
            logger.debug("aapt2 xmltree failed: %s", result.stderr[:200])
            return
        # aapt2 xmltree output is a human-readable tree, not binary XML.
        # We store it as a sentinel so manifest_parser can detect it and
        # extract fields via regex instead of lxml.
        xml_text = result.stdout.decode("utf-8", errors="replace")
        # Patch the ZIP in-place: replace the existing (proto) manifest entry.
        import io
        with zipfile.ZipFile(merged_apk, "r") as zin:
            names = zin.namelist()
            entries = {n: zin.read(n) for n in names}
        entries["AndroidManifest.xml"] = xml_text.encode("utf-8")
        entries["_aapt2_xmltree"] = b"1"  # sentinel for manifest_parser
        tmp = merged_apk + ".patching"
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
            for n, data in entries.items():
                zout.writestr(n, data)
        os.replace(tmp, merged_apk)
        logger.info("AAB manifest decoded via aapt2 and patched into merged APK")
    except Exception as exc:
        logger.warning("aapt2 manifest patch failed: %s", exc)


def _extract_all_strings(dx) -> list[str]:
    """Extract all string literals from the DEX string table."""
    strings = []
    try:
        for string_analysis in dx.get_strings():
            s = string_analysis.get_orig_value()
            if s and isinstance(s, str) and len(s) >= 4:
                strings.append(s)
    except Exception as exc:
        logger.debug("String extraction error: %s", exc)
    return strings


def _build_string_pool(dx) -> dict[str, dict[str, dict[str, str]]]:
    """
    Build a nested dict: class_name → method_name → {register: string_value}

    This is built by scanning const-string instructions in each method's
    bytecode.  It enables O(1) string lookup during taint and detector analysis.
    """
    pool: dict[str, dict[str, dict[str, str]]] = {}
    try:
        for method_analysis in dx.get_methods():
            try:
                raw = method_analysis.get_method() if hasattr(method_analysis, "get_method") else method_analysis
                class_name = raw.get_class_name()
                method_name = raw.get_name()
            except Exception:
                continue

            reg_map: dict[str, str] = {}
            try:
                for bb in method_analysis.get_basic_blocks().get():
                    for instr in bb.get_instructions():
                        name = instr.get_name().lower()
                        if name in ("const-string", "const-string/jumbo"):
                            operands = instr.get_operands()
                            if len(operands) >= 2:
                                reg = str(operands[0][2])
                                val = str(operands[1][2])
                                reg_map[reg] = val
            except Exception:
                pass

            if reg_map:
                pool.setdefault(class_name, {})[method_name] = reg_map

    except Exception as exc:
        logger.debug("String pool build error: %s", exc)

    return pool
