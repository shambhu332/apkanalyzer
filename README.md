# APKAnalyzer

Advanced static analysis engine for Android APKs. Higher accuracy and fewer false positives than MobSF/QARK because it does the things pure pattern-matchers can't: inter-procedural Kildall taint with method-summary path replay, container-aware propagation (Map/List/Bundle/array elements), CHA-augmented virtual dispatch, **reflection edge synthesis** (resolves `Class.forName`→`getMethod`→`invoke` to synthetic call-graph edges), **best-effort string deobfuscation** (Base64/Hex/XOR/ROT/reverse), **JNI native-summary bridging**, optional JADX decompilation for Java-source rules, and Quark-style malware behaviour scoring — on top of reachability pruning, three-tier confidence scoring, and entropy-based secret detection.

## Architecture

```
APK / AAB / XAPK
 │
 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Pipeline Orchestrator (apkanalyzer/pipeline/orchestrator.py)            │
│                                                                          │
│  ┌──────────┐  ┌────────────┐  ┌───────────┐  ┌────────────────┐        │
│  │ Extractor│→ │ Manifest   │→ │ CallGraph │→ │ Reachability   │        │
│  │ androguard│  │ Parser     │  │ (networkx)│  │ + entry points │        │
│  │ + apktool │  │            │  │ + CHA     │  │                │        │
│  └──────────┘  └────────────┘  └─────┬─────┘  └────────┬───────┘        │
│                                      │                  │                │
│                  ┌───────────────────┴──────────────────┘                │
│                  │   Reflection edge synthesis (analysis/reflection.py)  │
│                  │   String deobfuscation (utils/deobfuscate.py)         │
│                  │   Optional JADX decompile (utils/jadx_bridge.py)      │
│                  ▼                                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Analysis Engine                                                    │ │
│  │  ├── TaintEngine — inter-procedural, flow-sensitive, container-    │ │
│  │  │     aware, CHA-augmented, JNI-summary-bridged                   │ │
│  │  │     ├── ~130 sources (DeviceID/Location/Clipboard/Intent/Flow…) │ │
│  │  │     ├── ~100 sinks (Network/Log/Storage/IPC/exec/WebView/Crypto)│ │
│  │  │     └── ~20 sanitizers with tri-state neutralisation            │ │
│  │  ├── CryptoDetector (ECB, weak algo, hardcoded key, PRNG, IV reuse)│ │
│  │  ├── NetworkDetector (cleartext, TrustManager bypass, TLS, NSC)    │ │
│  │  ├── StorageDetector (world-readable, plaintext SharedPrefs)       │ │
│  │  ├── WebViewDetector (JS bridge, file access, debug, geo, SafeBrw) │ │
│  │  ├── SecretDetector (Shannon entropy + pattern + deobfuscation)    │ │
│  │  ├── NativeDetector (real ELF parser: RELRO/NX/TEXTREL/DT_DEBUG)   │ │
│  │  ├── SBOMDetector (CycloneDX SBOM + offline OSV/NVD CVE feed)      │ │
│  │  ├── TrackerDetector (Exodus-Privacy ETIP signatures)              │ │
│  │  ├── Intent / Deeplink / Privacy / Logging / SDK / Resource…       │ │
│  │  └── Rule Engine (YAML — smali patterns + Semgrep-style data_flow) │ │
│  └─────────────────────────────────┬──────────────────────────────────┘ │
│                                    │                                    │
│  ┌─────────────────┐   ┌───────────┴──────────────┐   ┌───────────────┐ │
│  │ Confidence /    │→  │ MASVS profile filter +    │→  │ Quark-style   │ │
│  │ FP scorer       │   │ CVSS 3.1 + OWASP Mobile   │   │ behaviour     │ │
│  │ (3-tier)        │   │ Top 10 2024 enrichment    │   │ scoring       │ │
│  └─────────────────┘   └───────────────────────────┘   └───────────────┘ │
│                                    │                                    │
│        ┌───────────────────────────┴───────────────────────────┐        │
│        ▼            ▼               ▼              ▼            ▼        │
│   report.json  report.html   report.sarif   sbom.cdx.json   frida/      │
│                              (+ baselining, --fail-on-new, diff mode)   │
└──────────────────────────────────────────────────────────────────────────┘
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
# Full scan (writes JSON + HTML + SARIF + Frida hooks under ./apkanalyzer_report)
apkanalyzer scan app.apk

# Custom output directory, HIGH-confidence-only results, SARIF only
apkanalyzer scan app.apk -o ./reports -c HIGH -f sarif

# MASVS profile gating (L1/L2/R) — drops findings outside the requested profile
apkanalyzer scan app.apk --masvs L2

# Baseline-aware CI gate: fail only on findings new vs the baseline
apkanalyzer scan app.apk --baseline baseline.json --fail-on-new

# Capture the current run as a baseline for future diffs
apkanalyzer scan app.apk --write-baseline baseline.json

# Custom taint specs + JNI bestiary (each flag is repeatable)
apkanalyzer scan app.apk \
    --sources my_sources.yaml --sinks my_sinks.yaml \
    --native-summaries my_jni.yaml

# Skip jadx (faster) or skip apktool (faster, fewer resource findings)
apkanalyzer scan app.apk --no-jadx --no-apktool --taint-depth 4

# Other commands
apkanalyzer batch app1.apk app2.apk app3.apk -o ./reports   # parallel batch
apkanalyzer compare old.apk new.apk -o ./diff               # delta scan
apkanalyzer cache --list / --clear                          # manage scan cache
apkanalyzer demo                                            # no APK needed

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
  "malware_behaviors": [
    {
      "name": "EXFIL_OVER_NETWORK",
      "description": "PII source flows into an unpinned or cleartext network sink — either intentional exfiltration or a textbook MASVS-NETWORK fail.",
      "weight": 6,
      "severity": "HIGH",
      "mitre_tactic": "TA0010 — Exfiltration",
      "contributing_rule_ids": ["TAINT_DEVICE_ID_TO_NETWORK_OUT"]
    }
  ],
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
        ],
        "transforms": []
      },
      "remediation": "Encrypt sensitive data before transmission and use certificate pinning.",
      "cwe_id": "CWE-359",
      "cvss": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "owasp_category": "M2"
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
- The string-pool feed is run through `utils/deobfuscate.py` first, so Base64 / Hex / single-byte XOR / ROT-encoded secrets that the literal DEX pool would hide are recovered before pattern + entropy run
- Together this drops false positives from base64-encoded images and long identifiers to near zero while catching encoded API keys

### Reflection Edge Synthesis
`Class.forName(s).getMethod(m).invoke(...)` collapses to a single androguard XRef edge to `Method.invoke`, which would let any reflectively-dispatched call hide from the call graph. `analysis/reflection.py` walks every reachable method, tracks `const-string` writes plus deobfuscator output through registers, and when it sees a complete `forName → getMethod → invoke` chain it splices a synthetic edge `caller → resolved target` into the call graph **before** reachability and taint run. The taint engine then inlines the reflective callee through normal callee resolution. Limitations: the recogniser is intra-block; cross-CFG-branch chains aren't yet resolved (see `LIMITATIONS.md` §1.4).

### JNI Native Taint Summaries
The Java→C boundary is a black hole for static analysis. Rather than lifting native code, `analysis/taint/native_summaries.py` lets users describe what each JNI export does to taint via a YAML bestiary (`rules/native_summaries.yaml` ships defaults; `--native-summaries` adds more). A summary declares `propagate_args` (taint flows from arg N to return), `taints_return` (synthetic source labels — e.g. `Java_..._loadKey` always returns `CRYPTO_KEY`), `sanitises_args` (e.g. `hash_password` produces `HMAC_DIGEST`), or `sinks_args` (the native function is itself a sink). The taint engine consumes summaries as if they were Java method summaries, so reflective + native + Java flows compose end-to-end.

### ELF Native Detector
`native_detector.py` is a pure-Python ELF parser — no `readelf`, no `pyelftools`. It walks program and dynamic headers to detect `PT_GNU_RELRO`, `PT_GNU_STACK`, `DT_TEXTREL`, `DT_DEBUG`, and the dynamic-flag bits, so `NATIVE_NO_RELRO` / `NATIVE_TEXTREL` / `NATIVE_DEBUG_SYMBOLS` findings reflect actual ELF state, not byte-grep heuristics. `.so` count and total-bytes caps are configurable via `APKANALYZER_MAX_SO_FILES` / `APKANALYZER_MAX_SO_BYTES`.

### Malware Behaviour Scoring
`scoring/behavior.py` takes the raw findings list and synthesises Quark-style behaviours — composite indicators like "exfiltrates device identifiers over the network" or "loads code dynamically" — each tagged with a MITRE ATT&CK for Mobile technique ID and a confidence score derived from the underlying findings. The result is emitted as a top-level `malware_behaviors` array in the JSON report and surfaced in HTML / SARIF.

### CVSS, OWASP, MASVS, SARIF Baselining
Every finding carries a CVSS 3.1 vector + numeric score (`scoring/cvss.py`) and an OWASP Mobile Top 10 2024 category (`scoring/owasp.py`). `--masvs L1|L2|R` filters to the requested MASVS profile. `--baseline` + `--fail-on-new` give CI a shift-left gate keyed on per-finding fingerprints, and the SARIF reporter emits `baselineState` (`new` / `unchanged`) so GitHub Code Scanning displays the diff natively.

## File Structure

```
apkanalyzer/
├── pipeline/
│   ├── orchestrator.py        # Coordinates all stages
│   └── extractor.py           # APK / AAB / XAPK loading, string pool, apktool
├── ir/
│   ├── models.py              # Shared data models (Finding, CFGMethod, TaintPath, …)
│   ├── call_graph.py          # Inter-procedural call graph (networkx) + CHA
│   └── cfg_builder.py         # Per-method CFG from androguard
├── analysis/
│   ├── reachability.py        # Entry-point detection + BFS reachability pruning
│   ├── reflection.py          # Class.forName→getMethod→invoke synthetic edges
│   ├── taint/
│   │   ├── engine.py          # Inter-procedural Kildall taint w/ method summaries
│   │   ├── sources.py         # ~130 source specs (Kotlin Flow / Rx / DataStore / …)
│   │   ├── sinks.py           # ~100 sink specs
│   │   ├── sanitizers.py      # Tri-state sanitiser neutralisation
│   │   ├── native_summaries.py# JNI bestiary (Java→C taint bridging)
│   │   └── loader.py          # YAML/JSON loader for extra source/sink/sanitiser specs
│   └── detectors/
│       ├── crypto_detector.py     # ECB / weak algo / hardcoded key / PRNG / IV reuse
│       ├── network_detector.py    # Cleartext / TrustManager / TLS / NSC
│       ├── storage_detector.py    # World-readable / plaintext SharedPrefs / DataStore
│       ├── webview_detector.py    # JS bridge / file access / debug / Safe-Browsing
│       ├── secret_detector.py     # Entropy + pattern + deobfuscation
│       ├── native_detector.py     # Pure-Python ELF parser
│       ├── sbom_detector.py       # CycloneDX SBOM + offline OSV/NVD CVE feed
│       ├── tracker_detector.py    # Exodus-Privacy ETIP signatures
│       ├── intent_detector.py / deeplink_detector.py / privacy_detector.py
│       ├── logging_detector.py / sdk_detector.py / resource_detector.py
│       ├── obfuscation_detector.py / antianalysis_detector.py
├── rules/
│   └── engine.py              # YAML rule loader (smali patterns + data_flow specs)
├── scoring/
│   ├── confidence.py          # FP filter, three-tier confidence
│   ├── cvss.py                # CVSS 3.1 vector + score per finding
│   ├── owasp.py               # OWASP Mobile Top 10 2024 mapping
│   ├── masvs.py               # MASVS L1 / L2 / R profile gating
│   └── behavior.py            # Quark-style malware behaviour scoring
├── reporting/
│   ├── json_reporter.py / html_reporter.py / sarif_reporter.py
│   ├── frida_generator.py     # Frida hook stub generator
│   ├── diff_reporter.py       # Two-APK delta scan
│   └── baseline.py            # Per-finding fingerprinting for --baseline
├── cache/
│   └── scan_cache.py          # SQLite full-report + per-detector incremental cache
├── plugins/
│   └── loader.py              # AST-sandboxed plugin loader
└── utils/
    ├── deobfuscate.py         # Base64 / Hex / XOR / ROT / reverse decoders
    ├── jadx_bridge.py         # Optional JADX subprocess bridge
    ├── manifest_parser.py / smali_parser.py / entropy.py / test_class.py
rules/
├── crypto_rules.yaml / network_rules.yaml / storage_rules.yaml
├── webview_rules.yaml / extended_rules.yaml / android_modern_rules.yaml
├── misc_rules.yaml / jadx_java_rules.yaml
└── native_summaries.yaml      # Default JNI bestiary
.github/workflows/apkanalyzer.yml      # GitHub Action template
.gitlab-ci.yml.template                # GitLab CI template
web/openapi.yaml                       # OpenAPI 3.1 spec for the HTTP API
tests/                                 # pytest suite
main.py                                # CLI entry point (click)
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

The canonical, code-anchored list of gaps and the priority-ordered roadmap to surpass MobSF lives in **[`LIMITATIONS.md`](./LIMITATIONS.md)**. It is kept in sync with the source: items that ship are removed (not crossed out), so anything still listed is still missing. Today the headline gaps are AAB-proto-manifest fidelity (bundle ingest works but the AAB manifest stays in protobuf form), k=1 context-sensitive taint, rule-pack breadth, cross-CFG-branch reflection, and `RegisterNatives` table extraction for dynamically-bound JNI exports.

