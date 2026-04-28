# APKAnalyzer — Limitations & Roadmap

This document is the canonical list of what APKAnalyzer **cannot** do today.
It is kept in sync with the code: items that get fixed are removed (not
crossed out), so anything still listed is still missing.

The architecture is solid — inter-procedural Kildall taint with method-summary
path replay, field-tagged `iput`/`iget`, static-field tracking, CHA-augmented
virtual dispatch, MASVS profile gating, CVSS/OWASP enrichment, SARIF baselining,
and an AST-sandboxed plugin loader puts APKAnalyzer ahead of pattern-matching
tools like MobSF/QARK in raw analysis quality. The remaining gaps below are
what blocks the "better than MobSF on coverage" claim.

---

## 1. Taint engine — algorithmic gaps

| #  | Gap | File | Why it costs you accuracy |
|----|-----|------|---------------------------|
| 1  | **Context-insensitivity (k=0)** — every callee is summarized once, keyed by `desc.full_name`; all callers share the same summary | `analysis/taint/engine.py` `_method_summaries` | A method called from a sanitized path *and* an unsanitized path will conflate them. False positives in DI-heavy Kotlin apps. FlowDroid uses k-CFA / object-sensitive contexts. |
| 2  | **Bounded worklist (`len(blocks)*10 + 100`)** silently truncates on convergence-resistant CFGs | `engine.py` | Big methods (Kotlin coroutines, generated parsers) just stop being analyzed mid-flight. Truncation is logged but findings are silently partial. |
| 3  | **Field sensitivity is shallow** — only one level: `iput` stamps `LABEL@field`, but two-level chains (`a.b.c = tainted`) don't model nested access paths | `engine.py` `iput`/`iget` blocks | Nested struct-style data loses taint on the second hop. |
| 4  | **No array element / map / list element tracking** — `aput`/`aget`/`Map.put`/`List.add` are not modeled | `engine.py` | `intent.getStringExtra("a")` taints the result, but `bundle.getString(key)` after `for (k : keys)` loses provenance. Container-routed flows are invisible. |
| 5  | **No reflection resolution** — `Class.forName(s).getMethod(m).invoke(...)` is just an obfuscation finding, not edge-augmenting | `obfuscation_detector.py` only flags it | Apex/DroidRA-style reflection resolution would let you trace through reflective dispatch. Without it, any obfuscated app is opaque. |
| 6  | **No string deobfuscation** — encrypted/decoded URLs and constants in `decrypt(byteArray)` patterns aren't unwrapped | nothing handles it | Modern packers (Bangcle, Tencent Legu, dex-protector, custom Base64+XOR) defeat secret/network/URL detectors entirely. |
| 7  | **No native taint** — JNI boundary is a black hole | `native_detector.py` only checks ELF flags | A `Java_com_app_Foo_decrypt` reading from a tainted source then returning to Java loses all provenance. JN-SAF / NDroid bridge this. |
| 8  | **Intra-block-only constant propagation** in WebView/intent detectors | `webview_detector.py` `bool_regs`/`int_regs` | `setJavaScriptEnabled(getConfigBool())` is invisible. State-of-the-art needs SSA-form const propagation or at least worklist over the CFG. |
| 9  | **Sanitizer model is binary** — `is_neutralized` is True/False; no notion of partial neutralisation beyond the explicit `neutralizes` set | `engine.py:679-682` | Multi-step sanitisation chains aren't modeled. |
| 10 | **Source/sink catalogue is still smaller than SuSi** — ships ~120 sources / ~80 sinks / ~15 sanitizers across modern Android stacks (Kotlin Flow/StateFlow, RxJava2, LiveData, DataStore, Compose, Volley, Apollo, Ktor, Bouncy Castle, Jsoup) | `sources.py`, `sinks.py`, `sanitizers.py` | FlowDroid ships ~12k SuSi-derived definitions. Coverage is good but not exhaustive. |

---

## 2. Detector blind spots

- **`crypto_detector.py`** can't follow algorithm strings across method boundaries; key-size detection requires the algo string to be in the same method as the keygen. Misses any factory-style cipher builder.
- **No detection of**: SafetyNet replay attacks, Play Integrity API result-not-validated-server-side, deprecated `signedConfig`, Auto-fill data-leak in `IMPORTANT_FOR_AUTOFILL`, Accessibility Service abuse, MediaProjection screen-cap, OverlayManager / `SYSTEM_ALERT_WINDOW`, Notification listener abuse, biometric `setUserAuthenticationRequired(false)`, KeyChain credential exposure, ContentResolver `query()` SQLi (you flag execSQL but not the more common pattern).
- **No JADX-style decompilation** — your bytecode IR can't recover lambdas/coroutine state machines cleanly. MobSF cheats by shelling out to JADX; you don't.
- **No AAB (Android App Bundle) support** — modern Play Store distribution is bundles. APKs are increasingly rare for first-party analysis.
- **No XAPK / split-APK / dynamic feature module support** — base.apk + N split apks aren't merged before analysis.

---

## 3. Rule engine gaps

- Smali patterns now support multi-line matching when the rule sets `multiline: true`, but there is still no way to express data-flow rules in YAML (Semgrep can, via `pattern-source`/`pattern-sink`).
- Rule-pack content is light: ~5 YAML files, ~600 lines total. Snyk Code, MobSF, Semgrep all ship hundreds of built-in rules.

---

## 4. Operational / production gaps

- **Web app**: ZIP magic check + optional bearer token + ScanStore-backed history are in place, but still **no CSRF token** on POST and **no rate limit**.
- **SQLite cache is single-machine** — no Redis/Postgres, no team sharing.
- **Native `.so` cap of 500 files**, byte-grep up to 64 MB per file — both are footguns: bigger apps with stacked ABIs (arm64-v8a + armeabi-v7a + x86_64 + x86) easily pass 500.
- **No incremental detector cache** — only the full-report cache. Change one rule and you re-scan the world.
- **No CI integration helpers** — no GitHub Action, no GitLab template, no exit-code matrix beyond `--fail-on` / `--fail-on-new`.

---

## 5. What MobSF / QARK / Quark / etc. have that you don't

| Capability | MobSF | QARK | Quark | AndroBugs | **APKAnalyzer** |
|---|---|---|---|---|---|
| **Tracker DB** (Exodus-Privacy 500+ trackers) | yes | no | no | no | **no** — your SDK catalogue has ~25 entries |
| **CVE lookup against bundled libs** (OWASP DC) | yes | no | no | no | **no** — no SBOM, no version detection |
| **Malware scoring** (Quark behavior weighting / threat-intel APIs) | partial | no | yes | no | **no** |
| **Dynamic analysis bridge** (Frida driver, MobSFy'd VM) | yes | no | no | no | partial — you generate hooks but don't run them |
| **MASVS-L1/L2 mapping** | yes | partial | no | no | **yes** (`--masvs L1\|L2\|R`) |
| **Decompilation (JADX)** | yes | yes | no | no | **no** |
| **Multi-tenant API + OpenAPI spec** | yes | no | no | no | no |
| **Diff/delta scan UI** | partial | no | no | no | **yes** — `diff_reporter.py` is good |
| **Inter-procedural taint** | no | no | no | no | **yes** — your competitive moat |
| **Per-finding CVSS + OWASP map** | partial | no | no | no | **yes** — really good here |
| **SARIF baseline (`baselineState`)** | no | no | no | no | **yes** — `--baseline` flows into SARIF results |
| **CHA-augmented virtual dispatch** | no | no | no | no | **yes** |
| **Resource scanner (strings.xml / raw / assets)** | yes | no | no | no | **yes** |

You **win** on taint quality, CVSS rigor, SARIF integration, and resource
coverage. You **lose** on decompilation, ecosystem data (CVE / trackers /
SBOM), and rule-pack content.

---

## Roadmap to surpass MobSF (priority-ordered)

### P1 — coverage breadth (4–8 weeks)

1. **AAB + split APK support**: merge base + config splits before analysis.
2. **JADX bridge** (subprocess, optional): when present, decompile to Java and run secondary checks for Kotlin lambdas / coroutine state machines that smali analysis loses.
3. **SBOM extraction**: read `META-INF/*.version`, manifest entries, classes.dex package signatures → emit CycloneDX SBOM → cross-ref OSV.dev / NVD for CVEs in bundled libs (this alone closes the biggest MobSF gap).
4. **Tracker DB**: import Exodus-Privacy ETIP signatures (open data, MIT-licensed).

### P2 — surpass MobSF (8–16 weeks)

5. **Reflection resolution** — DroidRA-style: track `Class.forName(stringConst).getMethod(stringConst).invoke(...)` patterns and add synthetic call-graph edges.
6. **String deobfuscation**: detect common XOR/Base64/RC4 wrapper patterns at the AST level and emulate them with a tiny Smali interpreter on constant inputs.
7. **JNI taint bridging**: parse JNI signatures from `RegisterNatives` and bound native blackboxes with summary specs (loaded from a YAML bestiary).
8. **Object/access-path-sensitive taint** (k=1 minimum) — closes the FP gap with FlowDroid.
9. **Rule pack ecosystem**: ship 200+ YAML rules out of the box (mine MobSF + Semgrep mobile rules), add Semgrep-style data-flow patterns.
10. **Per-finding triage UX**: web UI with "mark as FP", "suppress this rule for this class", baseline export → CI diff. This is where teams actually live.
11. **Multi-tenant API** with API keys, scan queue (Celery + Redis), Postgres backing, OpenAPI spec — replace the in-memory `_scans` dict.
12. **Frida runner**, not just generator: drive an emulator, replay your hooks, surface dynamic confirmations on the same finding.
13. **Continuous threat-intel feeds**: VirusTotal / Koodous / MalwareBazaar lookup of bundled `.so` SHA-256s; AbuseCh of contacted hosts.

### P3 — moat

14. **MaLDroid-style ML risk model** trained on your own ground truth (bytecode-feature CNN over your corpus). Pure pattern tools can't compete.
15. **Continuous APK monitoring** (Play Store crawler + diff alerts on watched packages) — that's a product, not a tool.

---

## TL;DR

The engine quality is genuinely strong. The remaining real gaps are
**reflection / deobfuscation, JNI bridging, AAB support, and SBOM/CVE
lookup** — those are what blocks the "better than MobSF on coverage" claim.
