"""
AndroidManifest.xml parser.

Extracts security-relevant flags and component configurations that cannot
be determined from bytecode alone.
"""

from __future__ import annotations

import logging
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(element, name: str, default=None):
    return element.get(f"{{{ANDROID_NS}}}{name}", default)


# Full Android dangerous permission list up to API 33 (Tiramisu)
DANGEROUS_PERMISSIONS: frozenset[str] = frozenset({
    # Location
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    # Contacts / call log
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    # Calendar
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    # SMS / phone
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    # Storage (legacy)
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    # Media (API 33+)
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    # Camera / microphone
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    # Sensors / biometrics
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.ACTIVITY_RECOGNITION",
    # Accounts
    "android.permission.GET_ACCOUNTS",
    # Bluetooth (API 31+)
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    # Nearby / UWB (API 31-33)
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.UWB_RANGING",
    # Notifications (API 33+)
    "android.permission.POST_NOTIFICATIONS",
    # Alarms (API 31+)
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.USE_EXACT_ALARM",
    # Media management (API 31+)
    "android.permission.MANAGE_MEDIA",
    # Overlays (API 31+)
    "android.permission.HIDE_OVERLAY_WINDOWS",
    # WiFi management (API 31+)
    "android.permission.MANAGE_WIFI_INTERFACES",
    # Other sensitive
    "android.permission.READ_BASIC_PHONE_STATE",
})


def parse_manifest(apk) -> dict:
    """
    Parse AndroidManifest from an androguard APK object.

    Returns a flat dict with security-relevant fields.
    """
    result = {
        "package": apk.get_package(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "allow_backup": False,
        "debuggable": False,
        "network_security_config": None,
        "uses_cleartext_traffic": False,
        "full_backup_content": None,
        "data_extraction_rules": None,
        "app_process": None,
        "exported_activities": [],
        "exported_services": [],
        "exported_receivers": [],
        "exported_providers": [],
        "permissions": list(apk.get_permissions()),
        "dangerous_permissions": [],
        "custom_permissions": [],
    }

    result["dangerous_permissions"] = [
        p for p in result["permissions"] if p in DANGEROUS_PERMISSIONS
    ]

    try:
        manifest_xml = apk.get_android_manifest_axml().get_xml()
        root = ET.fromstring(manifest_xml)
    except Exception as exc:
        logger.warning("Failed to parse manifest XML: %s", exc)
        return result

    # Application element flags
    app_elem = root.find("application")
    if app_elem is not None:
        allow_backup_val = _attr(app_elem, "allowBackup", None)
        # allowBackup defaults to TRUE on API < 31, FALSE on API >= 31
        target_sdk = int(result.get("target_sdk") or 0)
        if allow_backup_val is not None:
            result["allow_backup"] = allow_backup_val.lower() == "true"
        else:
            # Implicit default: true below API 31
            result["allow_backup"] = target_sdk < 31

        result["debuggable"] = _attr(app_elem, "debuggable", "false").lower() == "true"
        result["uses_cleartext_traffic"] = (
            _attr(app_elem, "usesCleartextTraffic", "false").lower() == "true"
        )
        nsc = _attr(app_elem, "networkSecurityConfig")
        if nsc:
            result["network_security_config"] = nsc

        # Backup-related attributes
        fbc = _attr(app_elem, "fullBackupContent")
        if fbc:
            result["full_backup_content"] = fbc
        der = _attr(app_elem, "dataExtractionRules")
        if der:
            result["data_extraction_rules"] = der

        # Process isolation
        result["app_process"] = _attr(app_elem, "process")

        # Exported components
        for tag, key in [
            ("activity", "exported_activities"),
            ("service", "exported_services"),
            ("receiver", "exported_receivers"),
            ("provider", "exported_providers"),
        ]:
            for elem in app_elem.findall(tag):
                name = _attr(elem, "name", "")
                exported_raw = _attr(elem, "exported", None)
                has_intent_filter = elem.find("intent-filter") is not None
                authorities = _attr(elem, "authorities")

                if tag == "provider":
                    # ContentProviders with authorities are exported by default
                    # unless explicitly marked exported=false (pre-API 17 behaviour
                    # persists for apps targeting old SDKs)
                    if exported_raw == "false":
                        is_exported = False
                    elif exported_raw == "true":
                        is_exported = True
                    else:
                        # Default: exported if has intent-filter OR has authorities
                        # on API < 17 (but we conservatively flag both)
                        is_exported = has_intent_filter or bool(authorities)
                else:
                    is_exported = (
                        exported_raw == "true"
                        or (has_intent_filter and exported_raw != "false")
                    )

                if is_exported:
                    deep_links = []
                    for intent_filter in elem.findall("intent-filter"):
                        auto_verify = (
                            _attr(intent_filter, "autoVerify", "false").lower() == "true"
                        )
                        actions = [
                            _attr(a, "name", "") for a in intent_filter.findall("action")
                        ]
                        categories = [
                            _attr(c, "name", "") for c in intent_filter.findall("category")
                        ]
                        is_browsable = "android.intent.category.BROWSABLE" in categories
                        is_view_action = "android.intent.action.VIEW" in actions

                        for data in intent_filter.findall("data"):
                            scheme = _attr(data, "scheme")
                            host = _attr(data, "host")
                            path = _attr(data, "path") or ""
                            path_prefix = _attr(data, "pathPrefix") or ""
                            path_pattern = _attr(data, "pathPattern") or ""
                            port = _attr(data, "port") or ""
                            mime_type = _attr(data, "mimeType") or ""
                            if scheme:
                                has_path_constraint = bool(
                                    path or path_prefix or path_pattern
                                )
                                deep_links.append({
                                    "scheme": scheme,
                                    "host": host or "",
                                    "path": path,
                                    "path_prefix": path_prefix,
                                    "path_pattern": path_pattern,
                                    "port": port,
                                    "mime_type": mime_type,
                                    "uri": (
                                        f"{scheme}://{host or '*'}"
                                        f"{path or path_prefix or (path_pattern and f'({path_pattern})') or '/*'}"
                                    ),
                                    "auto_verify": auto_verify,
                                    "actions": actions,
                                    "categories": categories,
                                    "is_browsable": is_browsable,
                                    "is_view_action": is_view_action,
                                    "is_app_link": (
                                        scheme in ("http", "https") and auto_verify
                                    ),
                                    "has_path_constraint": has_path_constraint,
                                })

                    component_info: dict = {
                        "name": name,
                        "permission": _attr(elem, "permission"),
                        "has_intent_filter": has_intent_filter,
                        "deep_links": deep_links,
                        "process": _attr(elem, "process"),
                    }
                    if tag == "provider":
                        component_info["authorities"] = authorities or ""
                        component_info["read_permission"] = _attr(elem, "readPermission")
                        component_info["write_permission"] = _attr(elem, "writePermission")
                        component_info["grant_uri_permissions"] = (
                            _attr(elem, "grantUriPermissions", "false").lower() == "true"
                        )
                    result[key].append(component_info)

    # Custom permissions
    for perm in root.findall("permission"):
        result["custom_permissions"].append({
            "name": _attr(perm, "name", ""),
            "protectionLevel": _attr(perm, "protectionLevel", "normal"),
        })

    return result
