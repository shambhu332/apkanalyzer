# CI integration

APKAnalyzer ships ready-to-use CI templates for GitHub Actions and GitLab CI.
Both use the same exit-code matrix as the CLI so a single tuning of
`--fail-on` / `--fail-on-new` propagates everywhere.

## Exit codes

| Flags                           | Exit non-zero when                                              |
|---------------------------------|------------------------------------------------------------------|
| `--fail-on HIGH` (default)      | Any finding with severity ≥ HIGH                                 |
| `--fail-on CRITICAL`            | Any finding with severity = CRITICAL                             |
| `--fail-on NEVER`               | Never (always exit 0; useful for advisory-only stages)           |
| `--baseline foo.json --fail-on-new` | Only when a *new* finding above `--fail-on` appears vs baseline |

`--baseline` plays well with PR/MR pipelines: store the baseline file in the
default branch, and the gate only trips on regressions.

## GitHub Actions

The reusable workflow is at [`.github/workflows/apkanalyzer.yml`](../.github/workflows/apkanalyzer.yml).

* Trigger: `workflow_dispatch` (manual) or `pull_request` (auto, on APK / rule change).
* Uploads SARIF to GitHub Code Scanning under category `apkanalyzer`.
* Stores `report.json`, `report.html`, `report.sarif`, `sbom.cdx.json` as
  artifacts for 30 days.
* Permissions required: `security-events: write`.

Manual run example:

```bash
gh workflow run apkanalyzer.yml \
  -f apk=build/outputs/apk/release/app.apk \
  -f masvs=L2 \
  -f fail_on=HIGH
```

## GitLab CI

Copy [`.gitlab-ci.yml.template`](../.gitlab-ci.yml.template) to
`.gitlab-ci.yml` at the repo root, then override `APK_PATH` for your
project layout.

* Image: `python:3.11-slim` (no SDK dependency — APKAnalyzer is pure Python).
* Emits SARIF as `reports.sast` so GitLab's "Security & Compliance" UI
  surfaces findings inline on MRs.
* Auto-runs on MRs that touch APKs or rules; manual on the default branch.

## Tuning per environment

* **Speed**: turn off jadx (`--no-jadx`) to skip Java-source rules and the
  decompile cost. Keep the per-detector cache on (`--no-detector-cache`
  off) — first-run cost is the same, repeat scans are dramatically faster.
* **Strictness**: pin `--masvs L2` for high-assurance apps; this filters
  the report down to L2-relevant findings only.
* **Triage**: `--write-baseline baseline.json` after a clean review, then
  rely on `--fail-on-new` for incremental gating.
