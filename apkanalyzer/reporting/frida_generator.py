"""
Frida hook script generator.

Produces a ready-to-use Frida JavaScript intercept script from a report's
CRITICAL and HIGH findings, enabling dynamic validation of static analysis
results.

Each finding type maps to a Frida hook template:
  - TAINT findings     → hook the source method to log the tainted value
  - CRYPTO findings    → hook Cipher.getInstance / MessageDigest.getInstance
  - NETWORK findings   → hook OkHttp / HttpURLConnection
  - SECRET findings    → passive (string already found; no hook needed)
  - WEBVIEW findings   → hook loadUrl / evaluateJavascript
  - STORAGE findings   → hook SharedPreferences.putString / execSQL
  - OBFUSC findings    → hook DexClassLoader / Class.forName

Usage
-----
  apkanalyzer scan app.apk --format frida
  # → writes apkanalyzer_report/hooks.js

  frida -U -f com.example.app -l hooks.js
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


_HEADER = """\
/**
 * APKAnalyzer Auto-generated Frida hooks
 * Package : {package}
 * Grade   : {grade}
 * Findings: {total} ({critical} CRITICAL, {high} HIGH)
 *
 * Usage:
 *   frida -U -f {package} -l hooks.js
 *   frida -U --attach-name {package} -l hooks.js
 *
 * ⚠  For authorised security testing only.
 */

'use strict';

const TAG = '[APKAnalyzer]';

function log(msg) {{
  console.log(TAG + ' ' + msg);
}}

Java.perform(function () {{
"""

_FOOTER = """
}); // end Java.perform
"""

# ── Hook templates ────────────────────────────────────────────────────────────

_CIPHER_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {{
      log('Cipher.getInstance("' + algo + '") called from: ' + {cls});
      return this.getInstance(algo);
    }};
  }} catch(e) {{ log('Hook failed: Cipher.getInstance: ' + e); }}
"""

_MESSAGE_DIGEST_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var MD = Java.use('java.security.MessageDigest');
    MD.getInstance.overload('java.lang.String').implementation = function(algo) {{
      log('MessageDigest.getInstance("' + algo + '") called');
      return this.getInstance(algo);
    }};
  }} catch(e) {{ log('Hook failed: MessageDigest.getInstance: ' + e); }}
"""

_WEBVIEW_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {{
      log('WebView.loadUrl("' + url + '") called from {cls}');
      return this.loadUrl(url);
    }};
  }} catch(e) {{ log('Hook failed: WebView.loadUrl: ' + e); }}
"""

_SHARED_PREFS_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var Editor = Java.use('android.content.SharedPreferences$Editor');
    Editor.putString.implementation = function(key, value) {{
      log('SharedPreferences.putString("' + key + '", "' + value + '") in {cls}');
      return this.putString(key, value);
    }};
  }} catch(e) {{ log('Hook failed: SharedPreferences.putString: ' + e); }}
"""

_SQLITE_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation =
      function(sql, args) {{
        log('SQLiteDatabase.rawQuery("' + sql + '") in {cls}');
        return this.rawQuery(sql, args);
      }};
    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {{
      log('SQLiteDatabase.execSQL("' + sql + '") in {cls}');
      return this.execSQL(sql);
    }};
  }} catch(e) {{ log('Hook failed: SQLiteDatabase: ' + e); }}
"""

_DEX_CLASSLOADER_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libPath, parent) {{
      log('DexClassLoader instantiated with dexPath: ' + dexPath);
      return this.$init(dexPath, optimizedDir, libPath, parent);
    }};
  }} catch(e) {{ log('Hook failed: DexClassLoader: ' + e); }}
"""

_REFLECTION_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var Class = Java.use('java.lang.Class');
    Class.forName.overload('java.lang.String').implementation = function(name) {{
      log('Class.forName("' + name + '") called from {cls}');
      return this.forName(name);
    }};
  }} catch(e) {{ log('Hook failed: Class.forName: ' + e); }}
"""

_OKHTTP_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.execute.implementation = function() {{
      var req = this.request();
      log('OkHttp request: ' + req.method() + ' ' + req.url().toString());
      return this.execute();
    }};
  }} catch(e) {{ log('Hook failed: OkHttp: ' + e); }}
"""

_TRUSTMANAGER_HOOK = """\
  // [{rule_id}] {title}  — verify custom TrustManager is actually validating
  try {{
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {{
      log('checkServerTrusted called — authType: ' + authType +
          ', subject: ' + (chain.length > 0 ? chain[0].getSubjectDN() : 'none'));
      return this.checkServerTrusted(chain, authType);
    }};
  }} catch(e) {{ log('Hook failed: TrustManager: ' + e); }}
"""

_TAINT_SOURCE_HOOK = """\
  // [{rule_id}] {title}
  // Taint source: {source_label} → sink: {sink_label}
  try {{
    var TelephonyManager = Java.use('android.telephony.TelephonyManager');
    TelephonyManager.getDeviceId.overload().implementation = function() {{
      var result = this.getDeviceId();
      log('getDeviceId() returned: ' + result + ' [taint source]');
      return result;
    }};
  }} catch(e) {{ log('Hook failed: getDeviceId: ' + e); }}
"""

_GENERIC_CLASS_HOOK = """\
  // [{rule_id}] {title}
  try {{
    var target = Java.use('{java_class}');
    log('Loaded class: {java_class}');
  }} catch(e) {{ log('Class not found: {java_class}'); }}
"""


def _dalvik_to_java(dalvik: str) -> str:
    """Convert Lcom/example/Foo; → com.example.Foo"""
    return dalvik.lstrip("L").rstrip(";").replace("/", ".")


def _hook_for_finding(f: dict) -> str:
    rule_id = f.get("rule_id", "")
    title = f.get("title", "")
    cls = _dalvik_to_java(f.get("location", {}).get("class", "") or "")
    java_cls = f"Java.use('{cls}')" if cls else "'(unknown)'"

    if rule_id.startswith("CRYPTO_ECB") or rule_id.startswith("CRYPTO_WEAK_ALGO"):
        return _CIPHER_HOOK.format(rule_id=rule_id, title=title, cls=java_cls)
    if rule_id.startswith("CRYPTO_WEAK_HASH"):
        return _MESSAGE_DIGEST_HOOK.format(rule_id=rule_id, title=title)
    if rule_id.startswith("WEBVIEW"):
        return _WEBVIEW_HOOK.format(rule_id=rule_id, title=title, cls=cls)
    if rule_id.startswith("STORAGE_PREFS"):
        return _SHARED_PREFS_HOOK.format(rule_id=rule_id, title=title, cls=cls)
    if rule_id.startswith("STORAGE_SQLITE") or "SQL_INJECT" in rule_id:
        return _SQLITE_HOOK.format(rule_id=rule_id, title=title, cls=cls)
    if rule_id.startswith("OBFUSC_DYNAMIC_DEX"):
        return _DEX_CLASSLOADER_HOOK.format(rule_id=rule_id, title=title)
    if rule_id.startswith("OBFUSC_REFLECTION"):
        return _REFLECTION_HOOK.format(rule_id=rule_id, title=title, cls=java_cls)
    if rule_id.startswith("NETWORK_SSL") or rule_id.startswith("NETWORK_TRUST"):
        return _TRUSTMANAGER_HOOK.format(rule_id=rule_id, title=title)
    if rule_id.startswith("NETWORK_CLEARTEXT") or rule_id.startswith("NETWORK_OKHTTP"):
        return _OKHTTP_HOOK.format(rule_id=rule_id, title=title)
    if rule_id.startswith("TAINT_"):
        tf = f.get("taint_flow", {})
        src_label = tf.get("source", {}).get("label", "?")
        snk_label = tf.get("sink", {}).get("label", "?")
        return _TAINT_SOURCE_HOOK.format(
            rule_id=rule_id, title=title,
            source_label=src_label, sink_label=snk_label,
        )
    if cls:
        return _GENERIC_CLASS_HOOK.format(
            rule_id=rule_id, title=title, java_class=cls,
        )
    return f"  // [{rule_id}] {title} — no hook template available\n"


class FridaGenerator:
    """Generate a Frida JS hook script from a scan report."""

    def write(self, report: dict, path: str) -> None:
        meta = report.get("metadata", {})
        summary = report.get("summary", {})
        findings = report.get("findings", [])

        # Only hook CRITICAL and HIGH findings to keep the script manageable
        hookable = [
            f for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH")
        ]

        # Deduplicate by hook template to avoid identical hook blocks
        seen_hooks: set[str] = set()
        hook_blocks: list[str] = []
        for f in hookable:
            hook = _hook_for_finding(f)
            key = hook[:80]  # first 80 chars as dedup key
            if key not in seen_hooks:
                seen_hooks.add(key)
                hook_blocks.append(hook)

        header = _HEADER.format(
            package=meta.get("package", "unknown"),
            grade=summary.get("risk_grade", "?"),
            total=summary.get("total", 0),
            critical=summary.get("by_severity", {}).get("CRITICAL", 0),
            high=summary.get("by_severity", {}).get("HIGH", 0),
        )

        script = header + "\n".join(hook_blocks) + _FOOTER
        Path(path).write_text(script, encoding="utf-8")
