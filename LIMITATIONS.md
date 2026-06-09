# APKAnalyzer — Limitations & Roadmap

This document is the canonical list of what APKAnalyzer **cannot** do today.
It is kept in sync with the code: items that get fixed are removed (not
crossed out), so anything still listed is still missing.

The architecture is solid — inter-procedural Kildall taint with method-summary
path replay, field-tagged `iput`/`iget`, container-element propagation
(`aput`/`aget`/`Map.put`/`List.add`/`Bundle.put`), tri-state sanitiser
neutralisation, static-field tracking, CHA-augmented virtual dispatch,
JNI native-summary bridging, **reflection edge synthesis** (`Class.forName`
→ `getMethod` → `invoke` resolved to synthetic call-graph edges so taint
can cross reflective dispatch), **best-effort string deobfuscation**
(Base64 / Hex / single-byte XOR / ROT / reverse, fed into both the secret
scanner and the reflection resolver so encoded class names resolve),
cross-block constant propagation in WebView / intent detectors,
cross-method algorithm tracking in the crypto detector, YAML data-flow
rules à la Semgrep, optional JADX bridge for Java-source rules, MASVS
profile gating, CVSS/OWASP enrichment, SARIF baselining, Quark-style
malware behaviour scoring, per-detector incremental cache, GitHub Action
+ GitLab CI templates, OpenAPI 3.1 spec, and an AST-sandboxed plugin
loader puts APKAnalyzer ahead of pattern-matching tools like MobSF/QARK
in raw analysis quality. The remaining gaps below are what blocks the
"better than MobSF on coverage" claim.

---

## 1. Taint engine — algorithmic gaps

| #  | Gap | File | Why it costs you accuracy |
|----|-----|------|---------------------------|
| 1  | **Context-insensitivity (k=0)** — every callee is summarized once, keyed by `desc.full_name`; all callers share the same summary | `analysis/taint/engine.py` `_method_summaries` | A method called from a sanitized path *and* an unsanitized path will conflate them. False positives in DI-heavy Kotlin apps. FlowDroid uses k-CFA / object-sensitive contexts. |
| 2  | **Bounded worklist (`len(blocks)*10 + 100`)** silently truncates on convergence-resistant CFGs | `engine.py` | Big methods (Kotlin coroutines, generated parsers) just stop being analyzed mid-flight. Truncation is logged but findings are silently partial. |
| 3  | **Field sensitivity is shallow** — only one level: `iput` stamps `LABEL@field`, but two-level chains (`a.b.c = tainted`) don't model nested access paths | `engine.py` `iput`/`iget` blocks | Nested struct-style data loses taint on the second hop. Container-element tracking has the same one-level limit (`LABEL@__elem__`). |
| 4  | **Reflection resolver is intra-block only** — the `Class.forName → getMethod → invoke` recogniser walks each basic block in source order with a per-block register state and does not propagate across CFG branches | `analysis/reflection.py` `_scan_method` | Realistic in-line `forName→invoke` chains resolve, but reflection that crosses an `if/try/catch` (move-result into a phi point, then invoke in a successor block) still goes unresolved. `MethodHandle` / `VarHandle` lookup APIs and field reflection are not modelled. |
| 5  | **String deobfuscator only covers static encodings** — Base64 (std + urlsafe), hex, single-byte XOR, ROT/Caesar, and `StringBuilder.reverse` | `utils/deobfuscate.py` | RC4, AES/CBC, multi-stage chains (Base64 → XOR → reverse), and table-driven custom encoders are not unwrapped. Modern commercial packers (DexProtector v11+, Bangcle, Tencent Legu) wrap their per-class string pools with multi-key XOR cascades that the single-byte search can't recover. |
| 6  | **JNI bridge relies on `Java_<Class>_<method>` naming + YAML bestiary** — `RegisterNatives` is not parsed, so dynamically-bound natives that use a different C symbol name aren't matched to their Java declaration | `analysis/taint/native_summaries.py` | Apps that publish their natives via `RegisterNatives(JNIEnv*, jclass, JNINativeMethod[])` (common in OpenSSL / Tink wrappers) get summarised only if the user adds an explicit YAML entry. Without parsing the `.so` rodata for the method table, automatic resolution is impossible. |
| 7  | **Source/sink catalogue is still smaller than SuSi** — ships ~130 sources / ~100 sinks / ~20 sanitizers across modern Android stacks (Kotlin Flow/StateFlow, RxJava2, LiveData, DataStore, Compose, Volley, Apollo, Ktor, Bouncy Castle, Jsoup) | `sources.py`, `sinks.py`, `sanitizers.py` | FlowDroid ships ~12k SuSi-derived definitions. Coverage is good but not exhaustive. |

---

## 2. Detector blind spots

- **AAB merge is dex-faithful but manifest-degraded** — `pipeline/extractor.py:_merge_aab` flattens an Android App Bundle (`base/dex/*.dex`, feature modules, `lib/<abi>/*.so`) into a single synthetic APK and analyses it. DEX content and native libs are recovered fully, but the bundle's manifest lives in protobuf form (`base/manifest/AndroidManifest.xml.pb`); androguard's APK loader sees opaque bytes for it, so manifest-derived findings (exported components, intent filters, `allowBackup`, NSC) are pessimistic on AAB inputs unless the resource table is also unpacked. AAB ships with `bundle_kind="aab"` and `merged_splits` in report metadata so consumers know they're looking at a synthesised APK.
- **No dynamic-feature `on-demand` install simulation** — XAPK / APKS / APKM (zip-of-APKs) and `bundle.json`-described install-time / on-demand modules are merged statically (every split's classes/lib glued into the base). We do not simulate runtime split installation order, so taint flows that span an `on-demand` module loaded *after* a manifest-declared callback are over-approximated as "always reachable".

---

## 3. Rule engine gaps

- Rule-pack content has grown to **8 YAML files / ~1450 lines / 105 rules** (covering attestation, accessibility/overlay abuse, biometric weak-auth, KeyChain exposure, ContentResolver SQLi, autofill leak, clipboard exfil, WebView Safe-Browsing/geolocation toggles, TLS trust-all and cleartext NSC, plus `data_flow:` Semgrep-style source/sink/sanitizer specs and 5 jadx-only Java-source rules), but Snyk Code, MobSF and Semgrep still ship hundreds more.

---

## 4. Operational / production gaps

- **SQLite cache is single-machine** — no Redis/Postgres, no team sharing.
- **Native `.so` defaults**: 500-file cap and 64 MB byte-grep are now overridable via `APKANALYZER_MAX_SO_FILES` / `APKANALYZER_MAX_SO_BYTES`, but the defaults still surprise users with stacked-ABI fat binaries.

---

## 5. What MobSF / QARK / Quark / etc. have that you don't

| Capability | MobSF | QARK | Quark | AndroBugs | **APKAnalyzer** |
|---|---|---|---|---|---|
| **Tracker DB** (Exodus-Privacy 500+ trackers) | yes | no | no | no | **yes** — `tracker_detector.py` (~120 entries from ETIP) |
| **CVE lookup against bundled libs** (OWASP DC) | yes | no | no | no | **yes** — `sbom_detector.py` (CycloneDX SBOM + offline CVE feed) |
| **Malware scoring** (Quark behavior weighting / threat-intel APIs) | partial | no | yes | no | **yes** — `scoring/behavior.py` (8 behaviours, MITRE-tagged); threat-intel still no |
| **Dynamic analysis bridge** (Frida driver, MobSFy'd VM) | yes | no | no | no | partial — you generate hooks but don't run them |
| **MASVS-L1/L2 mapping** | yes | partial | no | no | **yes** (`--masvs L1\|L2\|R`) |
| **Decompilation (JADX)** | yes | yes | no | no | **yes (optional, if jadx in PATH)** — `utils/jadx_bridge.py` |
| **Multi-tenant API + OpenAPI spec** | yes | no | no | no | partial — `web/openapi.yaml` ships, multi-tenant still no |
| **AAB / XAPK / APKS / APKM bundle ingest** | yes | no | no | no | **yes** — `pipeline/extractor.py` `_merge_aab` / `_merge_apk_zip` (dex-faithful; AAB proto-manifest is opaque, see §2) |
| **Diff/delta scan UI** | partial | no | no | no | **yes** — `diff_reporter.py` is good |
| **Inter-procedural taint** | no | no | no | no | **yes** — your competitive moat |
| **Container-aware taint** (Map/List/Bundle/array element) | no | no | no | no | **yes** — `LABEL@__elem__` propagation |
| **Per-finding CVSS + OWASP map** | partial | no | no | no | **yes** — really good here |
| **SARIF baseline (`baselineState`)** | no | no | no | no | **yes** — `--baseline` flows into SARIF results |
| **CHA-augmented virtual dispatch** | no | no | no | no | **yes** |
| **Resource scanner (strings.xml / raw / assets)** | yes | no | no | no | **yes** |
| **Reflection edge synthesis** (`forName`→`getMethod`→`invoke`) | no | no | no | no | **yes** — `analysis/reflection.py` (intra-block, deobfuscator-aware) |
| **Static string deobfuscation** (Base64 / Hex / single-byte XOR / ROT / reverse) | no | no | no | no | **yes** — `utils/deobfuscate.py`, fed into secret scanner + reflection resolver |
| **JNI native taint summaries** (Java→C boundary modelling) | no | no | no | no | **yes** — `analysis/taint/native_summaries.py` + `rules/native_summaries.yaml` bestiary |
| **CI integration helpers** (GitHub Action, GitLab template) | partial | no | no | no | **yes** — `.github/workflows/apkanalyzer.yml` + `.gitlab-ci.yml.template` |

You **win** on taint quality (inter-procedural + container-aware + reflection-
+ JNI-bridged), CVSS rigor, SARIF integration, decompilation plus Java-source
rules, malware behaviour scoring, AAB/XAPK packaging ingest, and CI ergonomics
— every pure pattern-matching tool in the table is now categorically behind on
call-graph fidelity once obfuscation enters the picture. You **lose** on raw
rule-pack breadth, ecosystem freshness (CVE feed needs a refresh loop),
AAB-proto-manifest fidelity, and team-scale operational features (multi-
tenancy, scan queue).

---

## Roadmap to surpass MobSF (priority-ordered)

### P1 — coverage breadth (4–8 weeks)

1. **AAB proto-manifest decoder**: bundle ingest already merges base + feature modules + native libs (`extractor.py:_merge_aab`), but the bundle's `AndroidManifest.xml.pb` is left in protobuf form so androguard treats it as opaque bytes. Plumb a tiny proto decoder (or shell out to `aapt2 dump xmltree`) so manifest-derived findings (exported components, intent filters, `allowBackup`, NSC) are as faithful on AAB as they are on plain APK.
2. **CVE-feed refresh loop**: SBOM extraction already ships, but the bundled OSV.dev feed is point-in-time. Add a cron-style refresh + `--cve-feed-max-age` gate so a stale feed is a CI warning instead of silently passing scans.
3. **`RegisterNatives` table extraction**: parse `JNI_OnLoad` / `RegisterNatives` from bundled `.so` rodata to auto-map dynamically-bound natives to their Java declarations, removing the per-app YAML bestiary requirement for non-`Java_*`-named exports.

### P2 — surpass MobSF (8–16 weeks)

4. **Cross-block reflection resolution**: extend `analysis/reflection.py` from intra-block scanning to a small CFG-aware register dataflow so reflection chains that span branches are recoverable (closes the residual gap with DroidRA).
5. **String deobfuscation v2**: add multi-stage and table-driven decoders (Base64→XOR pipelines, AES/CBC with embedded key constants, dictionary-substitution encoders) using a tiny Smali interpreter on constant inputs.
6. **Object/access-path-sensitive taint** (k=1 minimum) — closes the FP gap with FlowDroid; the current k=0 method-summary cache is the largest accuracy axis still on the table.
7. **Rule pack ecosystem**: grow from 105 → 200+ YAML rules (mine MobSF + Semgrep mobile rules); the data-flow Semgrep-style schema is already supported.
8. **Per-finding triage UX**: web UI with "mark as FP", "suppress this rule for this class", baseline export → CI diff. This is where teams actually live.
9. **Multi-tenant API** with API keys, scan queue (Celery + Redis), Postgres backing — replace the in-memory `_scans` dict. (OpenAPI spec already lives at `web/openapi.yaml`.)
10. **Frida runner**, not just generator: drive an emulator, replay your hooks, surface dynamic confirmations on the same finding.
11. **Continuous threat-intel feeds**: VirusTotal / Koodous / MalwareBazaar lookup of bundled `.so` SHA-256s; AbuseCh of contacted hosts.

### P3 — moat

12. **MaLDroid-style ML risk model** trained on your own ground truth (bytecode-feature CNN over your corpus). Pure pattern tools can't compete.
13. **Continuous APK monitoring** (Play Store crawler + diff alerts on watched packages) — that's a product, not a tool.

---

## TL;DR

The engine quality is genuinely strong, and reflection resolution + string
deobfuscation + JNI bridging + AAB/XAPK bundle ingest now ship — so the
"obfuscated app is opaque" and "modern Play Store packaging is unsupported"
classes of misses are largely closed. The remaining real gaps are
**AAB-proto-manifest fidelity, k=1 context-sensitive taint, rule-pack
breadth, and `RegisterNatives` table extraction for dynamically-bound JNI
exports** — those are what blocks the "better than MobSF on coverage" claim
in 2026.
