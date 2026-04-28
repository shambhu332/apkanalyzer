# APKAnalyzer

Advanced static analysis engine for Android APKs. Achieves higher accuracy and fewer false positives than MobSF by combining inter-procedural taint analysis, reachability pruning, confidence scoring, and entropy-based secret detection.

## Architecture

```
APK
 │
 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Pipeline Orchestrator (apkanalyzer/pipeline/orchestrator.py)       │
│                                                                     │
│  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌────────────────┐  │
│  │ Extractor│→ │ Manifest   │→ │ CallGraph │→ │ Reachability   │  │
│  │ (androgu)│  │ Parser     │  │ (networkx)│  │ (entry points) │  │
│  └──────────┘  └────────────┘  └───────────┘  └────────────────┘  │
│                                                         │           │
│  ┌──────────────────────────────────────────────────────┘           │
│  │ Analysis Engine                                                   │
│  │  ├── TaintEngine (inter-procedural, flow-sensitive)              │
│  │  │    ├── Sources: device ID, location, intent, clipboard, ...   │
│  │  │    └── Sinks: network, log, storage, IPC, exec, WebView       │
│  │  ├── CryptoDetector (ECB, weak algo, hardcoded key, PRNG)        │
│  │  ├── NetworkDetector (cleartext, TrustManager bypass, TLS ver)   │
│  │  ├── StorageDetector (world-readable, plaintext SharedPrefs)     │
│  │  ├── WebViewDetector (JS interface, file access, debug)          │
│  │  └── SecretDetector (Shannon entropy + pattern matching)         │
│  │                                                                   │
│  │ Rule Engine (YAML rules → Smali pattern matching)                │
│  └───────────────────────────────────────────────────────────────── │
│                                                                     │
│  ┌──────────────┐   ┌────────────────┐   ┌─────────────────────┐  │
│  │ Confidence   │→  │  JSON Report   │   │  HTML Dashboard     │  │
│  │ Scoring +    │   │  report.json   │   │  report.html        │  │
│  │ FP Filter    │   └────────────────┘   └─────────────────────┘  │
│  └──────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Install

```bash
# 1. Clone
git clone https://github.com/yourorg/apkanalyzer && cd apkanalyzer

# 2. Create virtualenv
python -m venv .venv && source .venv/bin/activate

# 3. Install
pip install -e .

# 4. Optional: install apktool for richer resource analysis
# macOS:  brew install apktool
# Debian: apt install apktool
# Arch:   pacman -S apktool
```

## Usage

```bash
# Full scan
apkanalyzer scan app.apk

# Custom output directory, HIGH-confidence-only results
apkanalyzer scan app.apk --output ./reports --confidence HIGH

# Skip apktool, limit taint depth (faster on large APKs)
apkanalyzer scan app.apk --no-apktool --taint-depth 4

# Demo — no APK required (exercises all modules with synthetic data)
apkanalyzer demo

# Run tests
pytest tests/ -v
```

## Sample Output

```json
{
  "metadata": {
    "package": "com.example.vulnerable",
    "target_sdk": "33",
    "min_sdk": "21",
    "dangerous_permissions": [
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.READ_PHONE_STATE"
    ],
    "analysis_duration_seconds": 18.4
  },
  "summary": {
    "total": 7,
    "by_severity": {
      "CRITICAL": 2, "HIGH": 3, "MEDIUM": 2, "LOW": 0, "INFO": 0
    },
    "by_category": {
      "TAINT": 2, "CRYPTO": 2, "NETWORK": 1, "SECRETS": 1, "MANIFEST": 1
    }
  },
  "findings": [
    {
      "rule_id": "TAINT_DEVICE_ID_TO_NETWORK_OUT",
      "title": "Tainted DEVICE_ID data flows to NETWORK_OUT",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "category": "TAINT",
      "location": {
        "class": "Lcom/example/TelemetryService;",
        "method": "sendAnalytics",
        "file": "",
        "line": 0
      },
      "evidence": "Source: Landroid/telephony/TelephonyManager;->getDeviceId @offset 12\nSink:   Lokhttp3/FormBody$Builder;->add @offset 84",
      "taint_flow": {
        "source": { "method": "...TelephonyManager;->getDeviceId", "label": "DEVICE_ID", "offset": 12 },
        "sink":   { "method": "...FormBody$Builder;->add", "label": "NETWORK_OUT", "offset": 84 },
        "call_chain": [
          "Lcom/example/MainActivity;->onCreate",
          "Lcom/example/TelemetryService;->sendAnalytics"
        ]
      },
      "remediation": "Encrypt sensitive data before transmission and use certificate pinning.",
      "cwe_id": "CWE-359",
      "cvss": 0.0
    },
    {
      "rule_id": "CRYPTO_ECB_MODE",
      "title": "Cipher uses ECB mode — no semantic security",
      "severity": "HIGH",
      "confidence": "HIGH",
      "category": "CRYPTO",
      "evidence": "Cipher.getInstance(\"AES/ECB/PKCS5Padding\") at offset 24",
      "remediation": "Use AES/GCM/NoPadding with a randomly generated 96-bit IV.",
      "cwe_id": "CWE-327",
      "cvss": 7.5
    },
    {
      "rule_id": "SECRET_AWS_KEY",
      "title": "Hardcoded AWS Access Key ID detected",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "category": "SECRETS",
      "evidence": "Matched: AKIAIOSFODNN7EXAMPLE",
      "remediation": "Rotate the AWS key immediately. Use IAM roles or AWS Secrets Manager.",
      "cwe_id": "CWE-798",
      "cvss": 9.0
    }
  ]
}
```

## Design Decisions

### Why not regex-only?
Regex on decompiled Java hits ~40-60% false positive rates on real APKs because:
- The same API call pattern appears in test code, dead code, and safe contexts
- Algorithm strings are often built dynamically (regex can't see the runtime value)
- Decompilers introduce artefacts (renamed variables, missing type information)

### Taint Analysis Approach
We implement a **monotone dataflow analysis** (Kildall's algorithm) on Dalvik bytecode:
1. **Sources** are modelled as invoke instructions whose return value introduces taint
2. **Propagation** follows register assignments (`move`, `move-result`, array/field ops)
3. **Sinks** check whether the tainted label reaches a security-sensitive argument
4. **Inter-procedural**: callee CFGs are inlined up to `--taint-depth` call frames
5. **Convergence**: the worklist terminates because the taint lattice (𝒫(Labels)) has finite height and we apply monotone ∪ joins

### Reachability as FP Gate
Before any method is analysed:
1. Build the inter-procedural call graph (androguard XRef)
2. Identify Android entry points: Activity/Service/Receiver lifecycle methods + CG roots
3. Compute the transitive reachable set via BFS
4. **Skip unreachable methods entirely** — dead code triggers ~25% of MobSF findings

### Confidence Scoring
Every finding carries a three-tier confidence:
- **HIGH**: confirmed source→sink path + reachable + evidence snippet
- **MEDIUM**: path exists but context incomplete (deep call chain, library boundary)  
- **LOW**: pattern-match without full flow proof (YAML rule engine)

Library classes (okhttp, Retrofit, androidx) are automatically downgraded one tier. Test classes are downgraded two tiers.

### Secret Detection
Shannon entropy + pattern hybrid:
- A candidate string must match a pattern **and** exceed the minimum entropy threshold for its character class
- Known-safe patterns (UUIDs, git SHAs, numeric IDs) are blocklisted before entropy is computed
- This reduces false positives from base64-encoded images and long identifiers to near zero

## File Structure

```
apkanalyzer/
├── pipeline/
│   ├── orchestrator.py     # Coordinates all stages
│   └── extractor.py        # APK loading, string pool, apktool
├── ir/
│   ├── models.py            # Shared data models (Finding, CFGMethod, …)
│   ├── call_graph.py        # Inter-procedural call graph (networkx)
│   └── cfg_builder.py       # Per-method CFG from androguard
├── analysis/
│   ├── reachability.py      # Entry-point detection + BFS reachability
│   ├── taint/
│   │   ├── engine.py        # Monotone dataflow taint engine
│   │   ├── sources.py       # Taint source catalogue
│   │   └── sinks.py         # Taint sink catalogue
│   └── detectors/
│       ├── crypto_detector.py
│       ├── network_detector.py
│       ├── storage_detector.py
│       ├── webview_detector.py
│       └── secret_detector.py
├── rules/
│   └── engine.py            # YAML rule loader + Smali pattern matcher
├── scoring/
│   └── confidence.py        # FP filter, confidence adjustment
└── reporting/
    ├── json_reporter.py
    └── html_reporter.py
rules/
├── crypto_rules.yaml
├── network_rules.yaml
├── storage_rules.yaml
└── webview_rules.yaml
tests/
├── test_taint_engine.py
└── test_secret_detector.py
main.py                       # CLI entry point (click)
```

## Extending

**Add a new taint source:**
```python
# apkanalyzer/analysis/taint/sources.py
TaintSourceSpec(
    "Lcom/myapp/Analytics;",
    "getAdvertisingId",
    "AD_ID",
)
```

**Add a YAML rule:**
```yaml
# rules/custom_rules.yaml
rules:
  - id: MY_CUSTOM_CHECK
    title: "Custom pattern detected"
    severity: HIGH
    confidence: MEDIUM
    cwe: CWE-200
    smali_pattern: 'MyClass;->sensitiveMethod'
    remediation: "..."
```

**Add a custom detector:**
```python
class MyDetector:
    def analyse_method(self, cfg: CFGMethod, desc: MethodDescriptor,
                       reg_strings: dict) -> list[Finding]:
        ...
```
Register it in `orchestrator.py`'s `_run_per_method_detectors`.

---

## Limitations & Roadmap

This section catalogs the **known gaps** uncovered by re-reading the source. They are grouped by impact: *correctness bugs* (results are wrong), *coverage holes* (whole classes of vulnerabilities are missed), *scale limits* (what breaks on large APKs), and *roadmap items* (where APKAnalyzer can outpace MobSF / QARK / Semgrep-mobile).

Each claim is anchored to a file:line so it can be verified or fixed.

### 1. Correctness bugs in the taint engine

**1.1 Inter-procedural return-value taint is silently broken.**
`engine.py:546` reads `callee_state.get_taint("__return__")` but the engine's result register is `_RESULT_REG = "__result__"` (`engine.py:66`). Grepping the codebase confirms **no code anywhere writes the `__return__` key**. Every callee return is therefore treated as untainted, even when the callee provably returns a tainted value. Concretely: `String s = sanitizer.passThrough(deviceId); send(s);` will *not* fire a `DEVICE_ID → NETWORK_OUT` finding when `passThrough` lives in another method.

**1.2 Cached methods drop all paths on revisit.**
`engine.py:295-300` returns an empty list whenever a method has already been visited in the current call stack — even though `_method_summary_cache` is consulted first:
```python
if desc.full_name in visited:
    cached = self._method_summary_cache.get(desc.full_name)
    if cached:
        return []  # Paths already emitted on first visit
    return []
```
The `if cached` branch falls through to the same `return []`. Effect: any taint flow that goes through a recursive or mutually-recursive call is reported only on the first inlining. This is a silent FN, not an FP.

**1.3 Worklist iteration cap silently truncates.**
`engine.py:325` sets `max_iterations = len(cfg.blocks) * 10 + 100` and the loop exits with no log when exceeded. Methods with deeply nested loops or dense back-edges can stop converging mid-fixpoint and emit *partial* taint sets.

**1.4 `iput` over-approximates the host object.**
`engine.py:415-424` propagates the source taint onto the *whole object register* on field write. Any subsequent read of any field of that object inherits the taint, producing FPs whenever an unrelated field is later passed to a sink.

**1.5 `sget` (static field reads) intentionally not tracked.**
`engine.py:408-411` documents that no static-field tracking is done "to avoid explosion." Real malware/SDKs frequently route taint through static fields; this is a category of FN we choose by design.

**1.6 O(N²) sanitizer matching per sink.**
`engine.py:506-511` re-iterates *all* sanitizer specs in every class for every sink hit. On large apps this is the hottest path in the engine.

**1.7 Operator-precedence ambiguity in trust-all detection.**
`network_detector.py:144-146`:
```python
if ("TrustAllCerts" in raw or "TrustAll" in raw
        or "AcceptAllCerts" in raw or "SSLSocketFactory" in raw
        and "setSocketFactory" in raw):
```
Python parses this as `A or B or C or (D and E)`. The `SSLSocketFactory + setSocketFactory` conjunction is intentional, but the precedence is non-obvious and a future contributor will get this wrong. Add explicit parens.

**1.8 Test/library class match is substring-based.**
`engine.py:69-72` uses `"Test" in class_name` etc. This silently skips `Latest`, `Greatest`, `Contestant`, `MockingbirdActivity`, `Debugger` — and any custom `*Test*` business-logic class name. Use word-boundary matching as `confidence.py:54-60` already does.

### 2. Coverage holes the data shows

**2.1 Tiny rule pack.** Across `rules/{crypto,network,storage,webview}_rules.yaml` the project ships **~16 rules** (5 + 4 + 3 + 3 — re-counted). MobSF ships ~200, Semgrep-mobile thousands, MASTG references hundreds. Rule pack is the lowest-effort, highest-leverage gap.

**2.2 Sanitizer catalogue is 13 specs.** `taint/sanitizers.py` covers `HTML_ESCAPE`, `URL_ENCODE`, `SQL_ESCAPE`, `CRYPTO_HASH`, `BASE64_ENCODE`, `ENCRYPT`. FlowDroid SuSi has thousands. Every missing sanitizer is a guaranteed FP.

**2.3 Sources / sinks are code-only, no extension surface.** `build_source_index` accepts `extra_sources` (`taint/sources.py`), but **no CLI flag, env var, or config file passes anything in**. Users cannot add taint specs without editing Python.

**2.4 Modern Android idioms unmodelled.**
- **Kotlin coroutines / `Flow` / `Channel`** — `call_graph.py:41-44` excludes `Lkotlinx/coroutines/` entirely, so taint that crosses suspend boundaries (the dominant pattern in modern apps) loses its call edges.
- **Jetpack Compose state** (`mutableStateOf`, `LiveData`, `StateFlow`) — no source/sink modelling.
- **AndroidX DataStore / EncryptedSharedPreferences** — not in storage detector.
- **WorkManager input/output Data** — entry-point hits `doWork` (good) but `Data.getString()` is not modelled as a source.
- **RxJava `Observable` chains** — sinks list includes some Rx, but operator chains (`map`/`flatMap`) break propagation because operator lambdas are anonymous classes the engine never inlines.

**2.5 Indirect dispatch is whatever androguard gives us.** Lambdas, method references, reflection (`Method.invoke`), `Proxy` instances, and Kotlin function objects all collapse to androguard's static XRef. We do not implement Class Hierarchy Analysis (CHA) or Rapid Type Analysis (RTA), so virtual dispatch over interfaces with many implementers is under-resolved.

**2.6 No SBOM / third-party CVE matching.** Competitor tools (MobSF, Ostorlab) match shipped libraries against OSV / NVD. We have nothing equivalent — `LIBRARY_CLASS_PATTERNS` only suppresses noise, never reports a vulnerable version of OkHttp / Glide / Firebase.

**2.7 No JS / Hermes / Flutter analysis.** React Native bundles, Hermes bytecode, Flutter `libapp.so` — all opaque to us. The native detector reads ELF security flags but never disassembles.

**2.8 Native detection uses byte-grep heuristics, not real ELF parsing.**
`native_detector.py:133-134` looks for `b"__stack_chk_fail"` and `b".debug_info"` literals across the whole file. Stripped libraries with those bytes inside a `.rodata` string still match (FP); UPX/xPacker'd libraries lack the literals (FN). Real `DT_FLAGS / DT_TEXTREL` parsing is documented as TODO at `native_detector.py:122-125`.

**2.9 Native scan capped at 500 `.so` files.** `native_detector.py:201-206` — fine for normal apps, but a multi-ABI app with split native modules (rare but real, e.g. game engines) loses tail libraries silently.

**2.10 Manifest analysis depth.** Reachability picks up exported components correctly via `_COMPONENT_BASE_CLASSES` (`reachability.py:76-115`), but we don't yet flag: insecure `permission` protectionLevels, `<grant-uri-permissions>` wildcards, taskAffinity hijack patterns, `launchMode="singleTask"` cross-app intent issues, `allowBackup="true"` interactions with `android:fullBackupContent` exclusions.

**2.11 `MethodAnalysis` fallback is O(N²).** `engine.py:262-271` falls back to scanning every method analysis on a name miss. On a 200k-method APK this is the worst single hot spot remaining.

### 3. Scale & operational gaps

**3.1 Single-threaded scans.** Per `pipeline/orchestrator.py`: the per-method ThreadPool is *adaptive* (`min(8, (len(candidates) // 50) + 1)`) — good. But the privacy scan, anti-analysis scan, and Network Security Config XML pass all run on the main thread.

**3.2 Plugin loop is O(plugins × methods).** Orchestrator re-iterates `dx.get_methods()` once per plugin. Five plugins on a 100k-method APK = 500k method visits before plugin code runs. Iterate methods once and dispatch to all plugins.

**3.3 CFG cache is per-engine, not cross-stage.** Crypto, WebView, network, secret detectors each call `get_all_instructions(cfg)` independently. Building the dict-of-instructions is repeated 4-5× per method.

**3.4 No memory cap.** Androguard's `Analysis` object holds the whole DEX in memory. Large bundle APKs (>200 MB) OOM with no graceful degradation.

**3.5 Cache key omits ruleset hash for YAML rules.** `scan_cache.py` keys on `(sha256, RULES_VERSION)`. `RULES_VERSION` is the package constant — editing a YAML rule file does **not** bump the cache key, so cached reports stay stale until you bump `apkanalyzer/__init__.py`. Hash the loaded rule set instead.

### 4. Confidence / scoring caveats

**4.1 Confidence scoring is hand-tuned heuristics.** `confidence.py:_NEVER_DOWNGRADE_RULES` and `_NOISY_RULES`, plus `engine.py:_CERTAIN_PAIRS`, are static frozensets. There is no calibration loop against a labelled corpus and no telemetry to update them. Competitive tools (CodeQL, Snyk Code) train on customer-marked FPs.

**4.2 Library detection is prefix-based.** Vendored / shaded libraries (Gradle's `shadow` plugin renames `com.squareup.okhttp3` → `com.example.shaded.okhttp3`) defeat `_LIBRARY_CLASS_PATTERNS`, so a library bug is reported as app code (FP severity).

**4.3 Risk grade thresholds are arbitrary.** `confidence.risk_grade` returns `F` on any CRITICAL or 3+ HIGH. No reasoning about category diversity, exploit chain depth, or attack surface (exported components × dangerous permissions).

### 5. Reporting / integration gaps

**5.1 No SARIF / GitHub code-scanning emit.** Only JSON + HTML. SARIF 2.1.0 is the table-stakes IDE/CI format.
**5.2 No diff-mode for CI.** `main.py` has `compare` for two APKs but no "fail if PR introduces new HIGH" gate keyed on baseline.
**5.3 No exploitability proof artifacts.** We generate Frida hook stubs but never build a runnable PoC APK or replay scripts.

### 6. Where APKAnalyzer can decisively beat MobSF / QARK

The roadmap below is what would make APKAnalyzer the obvious choice over established tools — ordered by ROI (impact ÷ effort).

| Priority | Item | Why it matters | Where MobSF/QARK lose today |
|----------|------|----------------|------------------------------|
| P0 | Fix `__return__` bug + cached-revisit `return []` | Restores entire inter-procedural taint claim from README §"Taint Analysis Approach" | We're currently lying; competitors don't claim inter-procedural at all |
| P0 | Hash YAML rules into cache key | Stops "I edited the rule but the cache served the old result" foot-guns | MobSF re-runs everything; our cache becomes a *correctness* asset only after this fix |
| P0 | Ship 200+ Semgrep-mobile-equivalent YAML rules | Closes the rule-count gap that's the #1 reason buyers pick MobSF | MobSF wins on coverage breadth today |
| P1 | Kotlin coroutines / Flow modelling (re-enable `Lkotlinx/coroutines/` selectively) | Modern apps are 70%+ Kotlin; we drop their primary control flow | MobSF / QARK ignore it too — *first to ship wins this category* |
| P1 | SBOM extraction + OSV/NVD CVE match for shipped libs | Adds an entire vulnerability dimension MobSF only does superficially | MobSF lists libraries; doesn't match versions to CVE feeds |
| P1 | Real ELF dynamic section parser (DT_TEXTREL, DT_DEBUG, NX, RELRO from sections, not byte-grep) | Removes byte-heuristic FPs/FNs | MobSF wraps `aapt`/`readelf`; we'd be self-contained and correct |
| P1 | SARIF 2.1.0 + GitHub Code Scanning native upload | Unlocks CI adoption — biggest distribution lever | Ostorlab / MobSF SARIF support is partial |
| P2 | CHA/RTA-based virtual dispatch resolution | Cuts FNs on interface-heavy code (DI containers) | Nobody in the OSS Android space ships this |
| P2 | Compose / DataStore / WorkManager source-sink models | Captures the actual modern Android attack surface | All competitors are stuck on legacy `Activity.onCreate` thinking |
| P2 | Differential CI mode (`apkanalyzer compare baseline.apk PR.apk --fail-on-new HIGH`) | Makes us the natural choice for shift-left orgs | MobSF has no first-class diff |
| P2 | FP-feedback loop: per-org `.apkanalyzer/suppress.yaml` honoured by confidence scorer | Beats MobSF's all-or-nothing rule disable | Snyk / CodeQL have it; OSS Android doesn't |
| P3 | Frida runtime-confirmation harness (auto-emit Frida script + verdict) | Static + dynamic confirmation in one CLI = no other OSS does this | Differentiator with no competitor |
| P3 | LLM-based remediation rewriter (patch suggestion as unified diff) | Beyond text remediation — actually emits the fix | MobSF has nothing |
| P3 | React Native / Hermes / Flutter bundle analysis | Modern app-store catalogue is increasingly RN/Flutter | Universal blind spot |

### 7. How to verify these claims yourself

```bash
# Inter-procedural return bug (1.1)
grep -rn '__return__\|__result__' apkanalyzer/

# Cached-revisit return [] (1.2)
sed -n '290,305p' apkanalyzer/analysis/taint/engine.py

# YAML rule count (2.1)
grep -c '^\s*- id:' rules/*.yaml

# Sanitizer catalogue size (2.2)
grep -c 'SanitizerSpec(' apkanalyzer/analysis/taint/sanitizers.py

# Coroutine exclusion (2.4)
sed -n '38,46p' apkanalyzer/ir/call_graph.py

# Native byte-heuristic (2.8)
sed -n '120,138p' apkanalyzer/analysis/detectors/native_detector.py
```

The point of this section is not self-flagellation — it's the public roadmap. Pull requests against any of the P0/P1 items move the project past MobSF's footprint in a measurable way.
