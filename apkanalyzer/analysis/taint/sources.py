"""
Taint source definitions.

Source categories
-----------------
DEVICE_ID      — unique hardware/software identifiers (IMEI, Android ID, …)
LOCATION       — GPS / network location
USER_INPUT     — data typed by the user (EditText, search, clipboard)
INTENT         — data from incoming Intents / IPC (Activity, BroadcastReceiver, Service)
DEEP_LINK_DATA — URI data from deep links / App Links
CONTENT_URI    — ContentProvider URI path/query parameters
CAMERA_MIC     — raw media sensor data
ACCOUNT        — account name, auth tokens
CLIPBOARD      — clipboard contents
CONTACT        — contact database reads
NETWORK_IN     — data received from the network (HTTP response bodies)
FILE_READ      — data read from files on the filesystem
SHARED_PREFS   — data read from SharedPreferences (may hold attacker-controlled values)
PACKAGE_INFO   — package metadata that can be manipulated via repackaging
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TaintSourceSpec:
    class_pattern: str    # Dalvik descriptor, e.g. Landroid/telephony/TelephonyManager;
    method_pattern: str   # exact method name or glob (*)
    label: str            # logical category
    param_index: int = -1  # -1 = return value; 0..n = parameter


DEFAULT_SOURCES: list[TaintSourceSpec] = [

    # ── Device identifiers ────────────────────────────────────────────────
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getDeviceId", "DEVICE_ID"),
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getImei", "DEVICE_ID"),
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getMeid", "DEVICE_ID"),
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getSubscriberId", "DEVICE_ID"),
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getSimSerialNumber", "DEVICE_ID"),
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getLine1Number", "DEVICE_ID"),
    TaintSourceSpec("Landroid/telephony/TelephonyManager;", "getNetworkOperatorName", "DEVICE_ID"),
    TaintSourceSpec("Landroid/provider/Settings$Secure;", "getString", "DEVICE_ID"),
    TaintSourceSpec("Landroid/provider/Settings$System;", "getString", "DEVICE_ID"),
    TaintSourceSpec("Landroid/os/Build;", "getSerial", "DEVICE_ID"),
    # Android Advertising ID
    TaintSourceSpec("Lcom/google/android/gms/ads/identifier/AdvertisingIdClient;",
                    "getAdvertisingIdInfo", "DEVICE_ID"),

    # ── Location ─────────────────────────────────────────────────────────
    TaintSourceSpec("Landroid/location/LocationManager;", "getLastKnownLocation", "LOCATION"),
    TaintSourceSpec("Landroid/location/LocationManager;", "requestLocationUpdates", "LOCATION"),
    TaintSourceSpec("Landroid/location/Location;", "getLatitude", "LOCATION"),
    TaintSourceSpec("Landroid/location/Location;", "getLongitude", "LOCATION"),
    TaintSourceSpec("Landroid/location/Location;", "getAltitude", "LOCATION"),
    TaintSourceSpec("Landroid/location/Location;", "getSpeed", "LOCATION"),
    TaintSourceSpec("Lcom/google/android/gms/location/FusedLocationProviderClient;",
                    "getLastLocation", "LOCATION"),
    TaintSourceSpec("Lcom/google/android/gms/location/LocationResult;",
                    "getLastLocation", "LOCATION"),

    # ── User input ────────────────────────────────────────────────────────
    TaintSourceSpec("Landroid/widget/EditText;", "getText", "USER_INPUT"),
    TaintSourceSpec("Landroid/widget/TextView;", "getText", "USER_INPUT"),
    TaintSourceSpec("Landroid/widget/SearchView;", "getQuery", "USER_INPUT"),
    TaintSourceSpec("Landroid/widget/AutoCompleteTextView;", "getText", "USER_INPUT"),

    # ── Intent / IPC (Activity entry point) ─────────────────────────────
    TaintSourceSpec("Landroid/content/Intent;", "getStringExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getIntExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getLongExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getBooleanExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getFloatExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getDoubleExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getByteArrayExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getSerializableExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getParcelableExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getBundleExtra", "INTENT"),
    TaintSourceSpec("Landroid/content/Intent;", "getExtras", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getString", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getInt", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getLong", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getBoolean", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getFloat", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getDouble", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getByteArray", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getSerializable", "INTENT"),
    TaintSourceSpec("Landroid/os/Bundle;", "getParcelable", "INTENT"),
    # BroadcastReceiver.onReceive intent parameter (param 1)
    TaintSourceSpec("Landroid/content/BroadcastReceiver;", "onReceive", "INTENT", param_index=1),
    # Service.onStartCommand intent parameter (param 1)
    TaintSourceSpec("Landroid/app/Service;", "onStartCommand", "INTENT", param_index=1),
    # Fragment.getArguments() — Jetpack Navigation passes deep link args here
    TaintSourceSpec("Landroidx/fragment/app/Fragment;", "getArguments", "INTENT"),
    TaintSourceSpec("Landroid/app/Fragment;", "getArguments", "INTENT"),

    # ── Clipboard ─────────────────────────────────────────────────────────
    TaintSourceSpec("Landroid/content/ClipboardManager;", "getPrimaryClip", "CLIPBOARD"),
    TaintSourceSpec("Landroid/content/ClipData$Item;", "getText", "CLIPBOARD"),
    TaintSourceSpec("Landroid/content/ClipData$Item;", "getUri", "CLIPBOARD"),

    # ── Contacts ─────────────────────────────────────────────────────────
    TaintSourceSpec("Landroid/content/ContentResolver;", "query", "CONTACT"),
    TaintSourceSpec("Landroid/database/Cursor;", "getString", "CONTACT"),
    TaintSourceSpec("Landroid/database/Cursor;", "getInt", "CONTACT"),
    TaintSourceSpec("Landroid/database/Cursor;", "getLong", "CONTACT"),
    TaintSourceSpec("Landroid/database/Cursor;", "getBlob", "CONTACT"),

    # ── Accounts ─────────────────────────────────────────────────────────
    TaintSourceSpec("Landroid/accounts/AccountManager;", "getAccounts", "ACCOUNT"),
    TaintSourceSpec("Landroid/accounts/AccountManager;", "getAccountsByType", "ACCOUNT"),
    TaintSourceSpec("Landroid/accounts/AccountManager;", "blockingGetAuthToken", "ACCOUNT"),
    TaintSourceSpec("Landroid/accounts/AccountManager;", "getAuthToken", "ACCOUNT"),
    TaintSourceSpec("Landroid/accounts/AccountManager;", "peekAuthToken", "ACCOUNT"),

    # ── Inbound network data ──────────────────────────────────────────────
    TaintSourceSpec("Ljava/io/InputStream;", "read", "NETWORK_IN"),
    TaintSourceSpec("Ljava/io/BufferedReader;", "readLine", "NETWORK_IN"),
    TaintSourceSpec("Lokhttp3/ResponseBody;", "string", "NETWORK_IN"),
    TaintSourceSpec("Lokhttp3/ResponseBody;", "bytes", "NETWORK_IN"),
    TaintSourceSpec("Lokhttp3/Response;", "body", "NETWORK_IN"),
    TaintSourceSpec("Lretrofit2/Response;", "body", "NETWORK_IN"),
    TaintSourceSpec("Ljava/net/HttpURLConnection;", "getInputStream", "NETWORK_IN"),
    TaintSourceSpec("Lorg/apache/http/HttpEntity;", "getContent", "NETWORK_IN"),

    # ── File reads ────────────────────────────────────────────────────────
    TaintSourceSpec("Ljava/io/FileInputStream;", "read", "FILE_READ"),
    TaintSourceSpec("Ljava/io/FileReader;", "read", "FILE_READ"),
    TaintSourceSpec("Ljava/nio/file/Files;", "readAllBytes", "FILE_READ"),
    TaintSourceSpec("Ljava/nio/file/Files;", "readString", "FILE_READ"),
    TaintSourceSpec("Landroid/content/Context;", "openFileInput", "FILE_READ"),

    # ── SharedPreferences reads (may hold attacker-provided values) ───────
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getString", "SHARED_PREFS"),
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getInt", "SHARED_PREFS"),
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getLong", "SHARED_PREFS"),
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getBoolean", "SHARED_PREFS"),
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getFloat", "SHARED_PREFS"),
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getStringSet", "SHARED_PREFS"),
    TaintSourceSpec("Landroid/content/SharedPreferences;", "getAll", "SHARED_PREFS"),

    # ── Package / application metadata ────────────────────────────────────
    TaintSourceSpec("Landroid/content/pm/PackageManager;", "getPackageInfo", "PACKAGE_INFO"),
    TaintSourceSpec("Landroid/content/pm/PackageManager;", "getApplicationInfo", "PACKAGE_INFO"),
    TaintSourceSpec("Landroid/content/pm/PackageManager;", "getInstalledPackages", "PACKAGE_INFO"),

    # ── ContentProvider URI / query params ────────────────────────────────
    TaintSourceSpec("Landroid/content/Intent;", "getData", "CONTENT_URI"),
    TaintSourceSpec("Landroid/content/Intent;", "getDataString", "CONTENT_URI"),
    TaintSourceSpec("Landroid/net/Uri;", "getPathSegments", "CONTENT_URI"),
    TaintSourceSpec("Landroid/net/Uri;", "getQueryParameter", "CONTENT_URI"),
    TaintSourceSpec("Landroid/net/Uri;", "getLastPathSegment", "CONTENT_URI"),
    TaintSourceSpec("Landroid/net/Uri;", "getPath", "CONTENT_URI"),
    TaintSourceSpec("Landroid/content/ContentProvider;", "query", "CONTENT_URI"),
    TaintSourceSpec("Landroid/content/ContentProvider;", "insert", "CONTENT_URI"),
    TaintSourceSpec("Landroid/content/ContentProvider;", "update", "CONTENT_URI"),
    TaintSourceSpec("Landroid/content/ContentProvider;", "delete", "CONTENT_URI"),
    TaintSourceSpec("Landroid/content/ContentProvider;", "call", "CONTENT_URI"),

    # ── Deep link URI data ─────────────────────────────────────────────────
    TaintSourceSpec("Landroid/app/Activity;", "getIntent", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "parse", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getFragment", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getEncodedFragment", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getEncodedQuery", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getQueryParameterNames", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getSchemeSpecificPart", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getAuthority", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/net/Uri;", "getUserInfo", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroid/content/Intent;", "toUri", "DEEP_LINK_DATA"),
    TaintSourceSpec("Landroidx/navigation/NavBackStackEntry;", "getArguments", "DEEP_LINK_DATA"),

    # ── Kotlin Flow / StateFlow / SharedFlow ───────────────────────────────
    # Modern Kotlin apps deliver IO results through Flow. Treat any value
    # collected from a Flow as carrying the upstream source's taint.
    TaintSourceSpec("Lkotlinx/coroutines/flow/StateFlow;", "getValue", "NETWORK_IN"),
    TaintSourceSpec("Lkotlinx/coroutines/flow/MutableStateFlow;", "getValue", "NETWORK_IN"),
    TaintSourceSpec("Lkotlinx/coroutines/flow/SharedFlow;", "getReplayCache", "NETWORK_IN"),
    TaintSourceSpec("Lkotlinx/coroutines/flow/FlowKt;", "first", "NETWORK_IN"),
    TaintSourceSpec("Lkotlinx/coroutines/flow/FlowKt;", "single", "NETWORK_IN"),
    TaintSourceSpec("Lkotlinx/coroutines/channels/Channel;", "receive", "NETWORK_IN"),

    # ── RxJava 2/3 ─────────────────────────────────────────────────────────
    TaintSourceSpec("Lio/reactivex/Observable;", "blockingFirst", "NETWORK_IN"),
    TaintSourceSpec("Lio/reactivex/Observable;", "blockingSingle", "NETWORK_IN"),
    TaintSourceSpec("Lio/reactivex/Single;", "blockingGet", "NETWORK_IN"),
    TaintSourceSpec("Lio/reactivex/Maybe;", "blockingGet", "NETWORK_IN"),
    TaintSourceSpec("Lio/reactivex/Flowable;", "blockingFirst", "NETWORK_IN"),
    TaintSourceSpec("Lio/reactivex/rxjava3/core/Single;", "blockingGet", "NETWORK_IN"),
    TaintSourceSpec("Lio/reactivex/rxjava3/core/Observable;", "blockingFirst", "NETWORK_IN"),

    # ── LiveData ───────────────────────────────────────────────────────────
    TaintSourceSpec("Landroidx/lifecycle/LiveData;", "getValue", "NETWORK_IN"),
    TaintSourceSpec("Landroidx/lifecycle/MutableLiveData;", "getValue", "NETWORK_IN"),

    # ── Jetpack DataStore ──────────────────────────────────────────────────
    # DataStore is the modern replacement for SharedPreferences — same trust
    # boundary (attacker-controlled if the device is compromised).
    TaintSourceSpec("Landroidx/datastore/preferences/core/Preferences;", "get", "SHARED_PREFS"),
    TaintSourceSpec("Landroidx/datastore/core/DataStore;", "getData", "SHARED_PREFS"),

    # ── Ktor (Kotlin HTTP client) ──────────────────────────────────────────
    TaintSourceSpec("Lio/ktor/client/statement/HttpResponse;", "bodyAsText", "NETWORK_IN"),
    TaintSourceSpec("Lio/ktor/client/statement/HttpResponse;", "readBytes", "NETWORK_IN"),
    TaintSourceSpec("Lio/ktor/client/statement/HttpResponse;", "body", "NETWORK_IN"),

    # ── Volley ─────────────────────────────────────────────────────────────
    # NetworkResponse.data is the raw byte[] body delivered to listeners.
    TaintSourceSpec("Lcom/android/volley/NetworkResponse;", "data", "NETWORK_IN"),
    TaintSourceSpec("Lcom/android/volley/Response;", "result", "NETWORK_IN"),

    # ── Apollo (GraphQL) ───────────────────────────────────────────────────
    TaintSourceSpec("Lcom/apollographql/apollo3/api/ApolloResponse;", "data", "NETWORK_IN"),
    TaintSourceSpec("Lcom/apollographql/apollo/api/Response;", "data", "NETWORK_IN"),

    # ── Jsoup (HTML parser — frequently fed network bytes) ─────────────────
    TaintSourceSpec("Lorg/jsoup/Jsoup;", "parse", "NETWORK_IN"),
    TaintSourceSpec("Lorg/jsoup/nodes/Element;", "text", "NETWORK_IN"),
    TaintSourceSpec("Lorg/jsoup/nodes/Element;", "html", "NETWORK_IN"),
]


def build_source_index(
    extra_sources: list[TaintSourceSpec] | None = None,
) -> dict[str, list[TaintSourceSpec]]:
    """Build a lookup dict keyed by class name for O(1) matching."""
    all_sources = list(DEFAULT_SOURCES)
    if extra_sources:
        all_sources.extend(extra_sources)
    index: dict[str, list[TaintSourceSpec]] = {}
    for spec in all_sources:
        index.setdefault(spec.class_pattern, []).append(spec)
    return index
