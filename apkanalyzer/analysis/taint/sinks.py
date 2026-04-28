"""
Taint sink definitions.

Sink categories
---------------
LOG              — android.util.Log, System.out — data in app logs
NETWORK_OUT      — HTTP/socket write — data exfiltrated over network
STORAGE          — SharedPreferences write, file write — persistence
IPC_OUT          — sending data via Intents, Binder, ContentProvider
IPC_REDIRECT     — startActivity/startService with tainted Intent — component hijack
CRYPTO_SINK      — data used as key/IV (weak if tainted)
EXEC             — Runtime.exec — command injection
WEBVIEW          — WebView.loadUrl / evaluateJavascript — XSS / open redirect
WEBVIEW_JS_INJECT — WebView.addJavascriptInterface — JS bridge with tainted object
SQL_INJECT       — rawQuery/execSQL with unsanitised user input
FILE_WRITE       — writing to filesystem path derived from taint
DEEPLINK_REDIRECT — Intent.setData/setAction with tainted URI
OPEN_REDIRECT    — URL/URI construction from taint — network-level open redirect
PENDING_INTENT   — PendingIntent constructed from tainted data
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class TaintSinkSpec:
    class_pattern: str
    method_pattern: str
    label: str
    tainted_param: int = 0  # which argument carries the tainted value


DEFAULT_SINKS: list[TaintSinkSpec] = [

    # ── Logging ───────────────────────────────────────────────────────────
    TaintSinkSpec("Landroid/util/Log;", "d", "LOG", 1),
    TaintSinkSpec("Landroid/util/Log;", "e", "LOG", 1),
    TaintSinkSpec("Landroid/util/Log;", "i", "LOG", 1),
    TaintSinkSpec("Landroid/util/Log;", "v", "LOG", 1),
    TaintSinkSpec("Landroid/util/Log;", "w", "LOG", 1),
    TaintSinkSpec("Landroid/util/Log;", "wtf", "LOG", 1),
    TaintSinkSpec("Ljava/io/PrintStream;", "println", "LOG", 0),
    TaintSinkSpec("Ljava/io/PrintStream;", "print", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber;", "d", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber;", "e", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber;", "i", "LOG", 0),

    # ── Network output ────────────────────────────────────────────────────
    TaintSinkSpec("Ljava/io/OutputStream;", "write", "NETWORK_OUT", 0),
    TaintSinkSpec("Lokhttp3/Request$Builder;", "url", "NETWORK_OUT", 0),
    TaintSinkSpec("Lokhttp3/FormBody$Builder;", "add", "NETWORK_OUT", 1),
    TaintSinkSpec("Lokhttp3/FormBody$Builder;", "addEncoded", "NETWORK_OUT", 1),
    TaintSinkSpec("Lokhttp3/MultipartBody$Builder;", "addFormDataPart", "NETWORK_OUT", 1),
    TaintSinkSpec("Lretrofit2/http/Body;", "*", "NETWORK_OUT", 0),
    TaintSinkSpec("Ljava/net/HttpURLConnection;", "getOutputStream", "NETWORK_OUT", -1),
    TaintSinkSpec("Ljava/net/URLConnection;", "setRequestProperty", "NETWORK_OUT", 1),
    TaintSinkSpec("Lorg/apache/http/client/methods/HttpPost;", "setEntity", "NETWORK_OUT", 0),
    TaintSinkSpec("Lcom/android/volley/toolbox/StringRequest;", "<init>", "NETWORK_OUT", 2),

    # ── Storage ───────────────────────────────────────────────────────────
    TaintSinkSpec("Landroid/content/SharedPreferences$Editor;", "putString", "STORAGE", 1),
    TaintSinkSpec("Landroid/content/SharedPreferences$Editor;", "putInt", "STORAGE", 1),
    TaintSinkSpec("Landroid/content/SharedPreferences$Editor;", "putLong", "STORAGE", 1),
    TaintSinkSpec("Landroid/content/SharedPreferences$Editor;", "putBoolean", "STORAGE", 1),
    TaintSinkSpec("Landroid/database/sqlite/SQLiteDatabase;", "execSQL", "STORAGE", 0),
    TaintSinkSpec("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery", "STORAGE", 0),
    TaintSinkSpec("Ljava/io/FileOutputStream;", "write", "STORAGE", 0),
    TaintSinkSpec("Ljava/io/FileWriter;", "write", "STORAGE", 0),
    TaintSinkSpec("Ljava/nio/file/Files;", "write", "STORAGE", 1),

    # ── File path construction (path traversal) ───────────────────────────
    TaintSinkSpec("Ljava/io/File;", "<init>", "FILE_WRITE", 0),
    TaintSinkSpec("Ljava/io/FileOutputStream;", "<init>", "FILE_WRITE", 0),
    TaintSinkSpec("Landroid/content/Context;", "openFileOutput", "FILE_WRITE", 0),
    TaintSinkSpec("Landroid/content/Context;", "deleteFile", "FILE_WRITE", 0),

    # ── IPC out ───────────────────────────────────────────────────────────
    TaintSinkSpec("Landroid/content/Intent;", "putExtra", "IPC_OUT", 1),
    TaintSinkSpec("Landroid/os/Bundle;", "putString", "IPC_OUT", 1),
    TaintSinkSpec("Landroid/os/Bundle;", "putInt", "IPC_OUT", 1),
    TaintSinkSpec("Landroid/os/Bundle;", "putParcelable", "IPC_OUT", 1),
    TaintSinkSpec("Landroid/os/Parcel;", "writeString", "IPC_OUT", 0),

    # IPC redirect: tainted Intent sent to startActivity etc.
    TaintSinkSpec("Landroid/content/Context;", "startActivity", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Context;", "startActivityForResult", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Context;", "startService", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Context;", "bindService", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Context;", "sendBroadcast", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Context;", "sendOrderedBroadcast", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Context;", "sendStickyBroadcast", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/app/Activity;", "startActivity", "IPC_REDIRECT", 0),
    TaintSinkSpec("Landroid/app/Activity;", "startActivityForResult", "IPC_REDIRECT", 0),

    # ── PendingIntent (hijackable by other apps if not explicit) ─────────
    TaintSinkSpec("Landroid/app/PendingIntent;", "getActivity", "PENDING_INTENT", 2),
    TaintSinkSpec("Landroid/app/PendingIntent;", "getService", "PENDING_INTENT", 2),
    TaintSinkSpec("Landroid/app/PendingIntent;", "getBroadcast", "PENDING_INTENT", 2),

    # ── Crypto (tainted key material) ────────────────────────────────────
    TaintSinkSpec("Ljavax/crypto/spec/SecretKeySpec;", "<init>", "CRYPTO_SINK", 0),
    TaintSinkSpec("Ljavax/crypto/spec/IvParameterSpec;", "<init>", "CRYPTO_SINK", 0),
    TaintSinkSpec("Ljava/security/MessageDigest;", "update", "CRYPTO_SINK", 0),
    TaintSinkSpec("Ljavax/crypto/Mac;", "update", "CRYPTO_SINK", 0),

    # ── SQL injection sinks ───────────────────────────────────────────────
    TaintSinkSpec("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery", "SQL_INJECT", 0),
    TaintSinkSpec("Landroid/database/sqlite/SQLiteDatabase;", "execSQL", "SQL_INJECT", 0),
    TaintSinkSpec("Landroid/database/sqlite/SQLiteDatabase;", "compileStatement", "SQL_INJECT", 0),
    TaintSinkSpec("Landroid/content/ContentResolver;", "delete", "SQL_INJECT", 2),
    TaintSinkSpec("Landroid/content/ContentResolver;", "update", "SQL_INJECT", 2),
    TaintSinkSpec("Landroid/content/ContentResolver;", "insert", "SQL_INJECT", 1),
    TaintSinkSpec("Landroid/content/ContentResolver;", "query", "SQL_INJECT", 2),

    # ── Command execution ─────────────────────────────────────────────────
    TaintSinkSpec("Ljava/lang/Runtime;", "exec", "EXEC", 0),
    TaintSinkSpec("Ljava/lang/ProcessBuilder;", "<init>", "EXEC", 0),
    TaintSinkSpec("Ljava/lang/ProcessBuilder;", "command", "EXEC", 0),

    # ── WebView ───────────────────────────────────────────────────────────
    TaintSinkSpec("Landroid/webkit/WebView;", "loadUrl", "WEBVIEW", 0),
    TaintSinkSpec("Landroid/webkit/WebView;", "evaluateJavascript", "WEBVIEW", 0),
    TaintSinkSpec("Landroid/webkit/WebView;", "loadData", "WEBVIEW", 0),
    TaintSinkSpec("Landroid/webkit/WebView;", "loadDataWithBaseURL", "WEBVIEW", 1),
    TaintSinkSpec("Landroid/webkit/WebView;", "postUrl", "WEBVIEW", 0),
    TaintSinkSpec("Landroid/webkit/WebView;", "addJavascriptInterface", "WEBVIEW_JS_INJECT", 0),

    # ── Deep link / open redirect sinks ──────────────────────────────────
    TaintSinkSpec("Landroid/content/Intent;", "setData", "DEEPLINK_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Intent;", "setDataAndType", "DEEPLINK_REDIRECT", 0),
    TaintSinkSpec("Landroid/content/Intent;", "setAction", "DEEPLINK_REDIRECT", 0),
    TaintSinkSpec("Ljava/net/URL;", "<init>", "OPEN_REDIRECT", 0),
    TaintSinkSpec("Ljava/net/URI;", "<init>", "OPEN_REDIRECT", 0),
    TaintSinkSpec("Ljava/net/URI;", "create", "OPEN_REDIRECT", 0),
    TaintSinkSpec("Lokhttp3/Request$Builder;", "url", "OPEN_REDIRECT", 0),
    TaintSinkSpec("Landroidx/browser/customtabs/CustomTabsIntent;", "launchUrl", "OPEN_REDIRECT", 1),

    # ── Ktor client requests ──────────────────────────────────────────────
    # Ktor's HttpClient.get/post/etc are extension methods that boil down to
    # request() calls; we shim the common ones so URL/body args are sinks.
    TaintSinkSpec("Lio/ktor/client/request/HttpRequestBuilder;", "url", "NETWORK_OUT", 0),
    TaintSinkSpec("Lio/ktor/client/request/HttpRequestBuilder;", "setBody", "NETWORK_OUT", 0),
    TaintSinkSpec("Lio/ktor/client/HttpClient;", "request", "NETWORK_OUT", 0),

    # ── DataStore writes (modern SharedPreferences replacement) ───────────
    TaintSinkSpec("Landroidx/datastore/preferences/core/MutablePreferences;", "set", "STORAGE", 1),
    TaintSinkSpec("Landroidx/datastore/core/DataStore;", "updateData", "STORAGE", 0),

    # ── Compose intent / navigation ────────────────────────────────────────
    # Compose nav graph navigation taking tainted route strings is the JC
    # equivalent of Activity.startActivity for IPC_REDIRECT purposes.
    TaintSinkSpec("Landroidx/navigation/NavController;", "navigate", "IPC_REDIRECT", 0),

    # ── Bouncy Castle (tainted key material) ──────────────────────────────
    TaintSinkSpec("Lorg/bouncycastle/crypto/params/KeyParameter;", "<init>", "CRYPTO_SINK", 0),
    TaintSinkSpec("Lorg/bouncycastle/jce/spec/IESParameterSpec;", "<init>", "CRYPTO_SINK", 0),

    # ── Volley request constructors with tainted URL/body ─────────────────
    TaintSinkSpec("Lcom/android/volley/toolbox/JsonObjectRequest;", "<init>", "NETWORK_OUT", 1),
    TaintSinkSpec("Lcom/android/volley/Request;", "<init>", "NETWORK_OUT", 1),

    # ── Apollo / GraphQL queries ──────────────────────────────────────────
    TaintSinkSpec("Lcom/apollographql/apollo3/ApolloClient;", "query", "NETWORK_OUT", 0),
    TaintSinkSpec("Lcom/apollographql/apollo3/ApolloClient;", "mutation", "NETWORK_OUT", 0),

    # ── Timber additional levels (Kotlin Timber.tag().d() pattern) ────────
    TaintSinkSpec("Ltimber/log/Timber$Tree;", "d", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber$Tree;", "e", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber$Tree;", "i", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber$Tree;", "w", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber;", "w", "LOG", 0),
    TaintSinkSpec("Ltimber/log/Timber;", "v", "LOG", 0),

    # ── Kotlin println — `print(x)` in Kotlin compiles to System.out, but
    # the kotlin.io kt class also exists in some setups
    TaintSinkSpec("Lkotlin/io/ConsoleKt;", "println", "LOG", 0),
    TaintSinkSpec("Lkotlin/io/ConsoleKt;", "print", "LOG", 0),
]


def build_sink_index(
    extra_sinks: list[TaintSinkSpec] | None = None,
) -> dict[str, list[TaintSinkSpec]]:
    all_sinks = list(DEFAULT_SINKS)
    if extra_sinks:
        all_sinks.extend(extra_sinks)
    index: dict[str, list[TaintSinkSpec]] = {}
    for spec in all_sinks:
        index.setdefault(spec.class_pattern, []).append(spec)
    return index
