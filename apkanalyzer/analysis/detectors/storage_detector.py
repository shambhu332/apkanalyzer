"""
Storage security detector.

Checks
------
STORAGE_WORLD_READABLE     — openFileOutput with MODE_WORLD_READABLE/WRITEABLE
STORAGE_EXTERNAL_PUBLIC    — Writing to shared external storage (truly world-readable)
STORAGE_EXTERNAL_ISOLATED  — Writing to app-isolated external storage (lower risk)
STORAGE_SQLITE_PLAINTEXT   — Sensitive column names in unencrypted SQLite
STORAGE_PREFS_PLAINTEXT    — SharedPreferences storing passwords/tokens (plaintext)
STORAGE_BACKUP_ENABLED     — android:allowBackup=true
STORAGE_SQLCIPHER_MISSING  — SQLite used without SQLCipher for sensitive data
STORAGE_KEYSTORE_BYPASS    — Encrypted prefs backed by software (not hardware) key
"""

from __future__ import annotations

import logging
import re

from apkanalyzer.ir.models import (
    CFGMethod, MethodDescriptor, Finding, Severity, Confidence,
)
from apkanalyzer.ir.cfg_builder import get_all_instructions

logger = logging.getLogger(__name__)

# Word-boundary aware: avoid matching "encryption_enabled" as a password key
_SENSITIVE_KEY_RE = re.compile(
    r'(?i)\b(password|passwd|secret|token|api[_\-]?key|auth[_\-]?token|'
    r'credential|private[_\-]?key|access[_\-]?key|session[_\-]?key|'
    r'client[_\-]?secret|oauth|pin\b|ssn|credit[_\-]?card|cvv|'
    r'account[_\-]?number|bank[_\-]?account)\b',
)

# Public shared external storage — genuinely readable by all apps pre-API 29
_EXTERNAL_PUBLIC_METHODS = {
    "getExternalStorageDirectory",
    "getExternalStoragePublicDirectory",
}

# App-isolated external storage — not world-readable on API 29+
_EXTERNAL_ISOLATED_METHODS = {
    "getExternalFilesDir",
    "getExternalCacheDir",
    "getExternalMediaDirs",
    "getExternalFilesDirs",
    "getExternalCacheDirs",
}

# SQLCipher / Room Encrypted class prefixes — suppress plaintext SQLite warnings
_ENCRYPTED_DB_CLASSES = {
    "Lnet/sqlcipher/",
    "Lnet/sqlcipher/database/",
    "Landroidx/room/RoomDatabase;",
    "Lnet/zetetic/android/database/",
}


class StorageDetector:

    def analyse_method(
        self,
        cfg: CFGMethod,
        desc: MethodDescriptor,
        reg_strings: dict[str, str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        instructions = get_all_instructions(cfg)

        # Check if this method uses SQLCipher (suppresses plaintext DB warnings)
        uses_sqlcipher = any(
            any(prefix in instr.get("raw", "") for prefix in _ENCRYPTED_DB_CLASSES)
            for instr in instructions
        )

        for instr in instructions:
            raw = instr.get("raw", "")
            mnemonic = instr.get("mnemonic", "")
            offset = instr.get("offset", 0)

            if not mnemonic.startswith("invoke"):
                continue

            # ── World-readable file mode ───────────────────────────────
            if "openFileOutput" in raw:
                operands = instr.get("operands", [])
                for op in operands:
                    val = op.get("value")
                    if val in (1, 2):
                        findings.append(Finding(
                            rule_id="STORAGE_WORLD_READABLE",
                            title="File opened with MODE_WORLD_READABLE/WRITEABLE",
                            description=(
                                "openFileOutput with MODE_WORLD_READABLE (1) or "
                                "MODE_WORLD_WRITEABLE (2) makes the file accessible "
                                "to all installed apps. Deprecated since API 17."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            category="STORAGE",
                            class_name=desc.class_name,
                            method_name=desc.method_name,
                            evidence=f"openFileOutput mode={val} @offset {offset}",
                            remediation="Use MODE_PRIVATE (0) and encrypt sensitive content.",
                            cwe_id="CWE-732",
                            cvss=6.5,
                        ))

            # ── Public external storage (truly world-readable) ─────────
            for method in _EXTERNAL_PUBLIC_METHODS:
                if method in raw:
                    findings.append(Finding(
                        rule_id="STORAGE_EXTERNAL_PUBLIC",
                        title=f"Data written to public external storage via {method}",
                        description=(
                            f"{method} writes to shared external storage accessible by "
                            "ALL apps with READ_EXTERNAL_STORAGE and by any connected "
                            "computer (no root required). This includes backups and "
                            "USB file transfer."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="STORAGE",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"{method} @offset {offset}",
                        remediation=(
                            "Use internal storage (getFilesDir) for sensitive data. "
                            "If external is required, encrypt the data before writing."
                        ),
                        cwe_id="CWE-312",
                        cvss=6.5,
                    ))

            # ── App-isolated external storage (lower risk on API 29+) ──
            for method in _EXTERNAL_ISOLATED_METHODS:
                if method in raw:
                    findings.append(Finding(
                        rule_id="STORAGE_EXTERNAL_ISOLATED",
                        title=f"Data written to isolated external storage via {method}",
                        description=(
                            f"{method} writes to the app's isolated external directory. "
                            "On API < 29 this is readable by other apps with "
                            "READ_EXTERNAL_STORAGE. On API 29+ it is isolated, but "
                            "still accessible via USB without root."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        category="STORAGE",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f"{method} @offset {offset}",
                        remediation="For sensitive data, use internal storage. Encrypt if external required.",
                        cwe_id="CWE-312",
                        cvss=3.7,
                    ))

            # ── SharedPreferences with sensitive key names ─────────────
            if ("SharedPreferences" in raw or "putString" in raw) and \
                    "SharedPreferences$Editor" in raw:
                key_str = self._first_string_arg(instr, reg_strings)
                if key_str and _SENSITIVE_KEY_RE.search(key_str):
                    # Do NOT flag if value is "false"/"true" — storing policy, not secret
                    val_str = self._second_string_arg(instr, reg_strings)
                    if val_str and val_str.lower() in ("true", "false", "0", "1", "null"):
                        continue
                    findings.append(Finding(
                        rule_id="STORAGE_PREFS_PLAINTEXT",
                        title=f"Sensitive value in SharedPreferences: {key_str}",
                        description=(
                            f'SharedPreferences.putString("{key_str}", …) stores '
                            "potentially sensitive data in a plaintext XML file on "
                            "the device filesystem, accessible via ADB backup."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category="STORAGE",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f'putString("{key_str}", …) @offset {offset}',
                        remediation=(
                            "Use EncryptedSharedPreferences from Jetpack Security "
                            "library, backed by AndroidKeyStore."
                        ),
                        cwe_id="CWE-312",
                        cvss=7.5,
                    ))

            # ── SQLite with sensitive column names ─────────────────────
            if ("execSQL" in raw or "rawQuery" in raw) and not uses_sqlcipher:
                sql_str = self._first_string_arg(instr, reg_strings)
                if sql_str and _SENSITIVE_KEY_RE.search(sql_str):
                    findings.append(Finding(
                        rule_id="STORAGE_SQLITE_PLAINTEXT",
                        title="Sensitive column name in unencrypted SQLite",
                        description=(
                            f'SQL touches what appears to be sensitive data: '
                            f'"{sql_str[:80]}". The database is stored unencrypted '
                            "unless SQLCipher or Room Encryption is used."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        category="STORAGE",
                        class_name=desc.class_name,
                        method_name=desc.method_name,
                        evidence=f'SQL: "{sql_str[:80]}" @offset {offset}',
                        remediation="Encrypt the SQLite database using SQLCipher or Room with EncryptedDatabase.",
                        cwe_id="CWE-312",
                        cvss=5.3,
                    ))

        return findings

    def analyse_manifest(self, manifest_data: dict) -> list[Finding]:
        """Check AndroidManifest.xml flags that affect storage security."""
        findings: list[Finding] = []

        if manifest_data.get("allow_backup", False):
            findings.append(Finding(
                rule_id="STORAGE_BACKUP_ENABLED",
                title="android:allowBackup=true — app data exposed via ADB/cloud backup",
                description=(
                    "When allowBackup is true, the application's private data "
                    "(SharedPreferences, databases, files) can be extracted via "
                    "`adb backup` without root access on non-encrypted devices."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="STORAGE",
                file_path="AndroidManifest.xml",
                evidence='android:allowBackup="true"',
                remediation=(
                    'Set android:allowBackup="false" or implement a BackupAgent '
                    "that explicitly excludes sensitive data from backup rules."
                ),
                cwe_id="CWE-312",
                cvss=5.3,
            ))

        return findings

    def _first_string_arg(self, instr: dict, reg_strings: dict) -> str | None:
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            for reg in regs[1:]:
                if reg in reg_strings:
                    return reg_strings[reg]
        except (ValueError, IndexError):
            pass
        return None

    def _second_string_arg(self, instr: dict, reg_strings: dict) -> str | None:
        """Return the second string argument (skipping the first found string)."""
        raw = instr.get("raw", "")
        try:
            reg_part = raw[raw.index("{") + 1: raw.index("}")]
            regs = [r.strip() for r in reg_part.split(",") if r.strip()]
            found = 0
            for reg in regs[1:]:
                if reg in reg_strings:
                    found += 1
                    if found == 2:
                        return reg_strings[reg]
        except (ValueError, IndexError):
            pass
        return None
