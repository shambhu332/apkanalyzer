"""
APKAnalyzer Web UI — Flask application.

Routes
------
GET  /                   → upload page
POST /scan               → accept APK upload, start background scan, return scan_id
GET  /progress/<scan_id> → Server-Sent Events stream for live progress updates
GET  /result/<scan_id>   → return final JSON report
GET  /report/<scan_id>   → serve interactive HTML report
GET  /download/<scan_id> → download report.json
"""

from __future__ import annotations

import collections
import hmac
import html
import json
import logging
import os
import queue
import secrets
import shutil
import sys
import tempfile
import threading
import time
import uuid
from functools import wraps
from pathlib import Path

from flask import (
    Flask, Response, jsonify, make_response, render_template, request,
    send_file, stream_with_context,
)

# Make sure the project root is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from web.scan_store import ScanStore  # noqa: E402

app = Flask(__name__)
# Default 150 MB cap. Override via APKANALYZER_MAX_UPLOAD_MB for fat APKs
# (game binaries with bundled native blobs commonly run 300–500 MB).
try:
    _max_mb = int(os.environ.get("APKANALYZER_MAX_UPLOAD_MB", "150"))
except ValueError:
    _max_mb = 150
app.config["MAX_CONTENT_LENGTH"] = max(1, _max_mb) * 1024 * 1024

UPLOAD_DIR = Path(__file__).parent / "static" / "uploads"
REPORT_DIR = Path(__file__).parent / "static" / "reports"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger(__name__)

# ── Auth ──────────────────────────────────────────────────────────────────
# Optional bearer token. When unset, the app stays open (the existing default
# for local-only usage). When set, every endpoint *except* the static landing
# page requires the token in either:
#   Authorization: Bearer <token>      (preferred)
#   X-API-Token: <token>               (back-compat for simple curl)
_API_TOKEN = os.environ.get("APKANALYZER_API_TOKEN", "").strip()

def require_token(view):
    """Endpoint decorator. No-op when APKANALYZER_API_TOKEN is unset."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not _API_TOKEN:
            return view(*args, **kwargs)
        provided = request.headers.get("Authorization", "")
        if provided.startswith("Bearer "):
            provided = provided[len("Bearer "):]
        else:
            provided = request.headers.get("X-API-Token", "")
        if not hmac.compare_digest(provided, _API_TOKEN):
            return jsonify({"error": "Unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapper


# ── CSRF (double-submit cookie) ───────────────────────────────────────────
# The landing page issues a per-session cookie; mutating endpoints require the
# caller to echo it back via X-CSRF-Token. This blocks cross-origin form posts
# without a backing session store. Set APKANALYZER_DISABLE_CSRF=1 to bypass
# (e.g. for headless curl scripting that already authenticates via bearer
# token — the bearer check is independently sufficient there).
_CSRF_COOKIE = "apkanalyzer_csrf"
_CSRF_DISABLED = os.environ.get("APKANALYZER_DISABLE_CSRF", "").strip() == "1"


def _ensure_csrf_token() -> str:
    """Return the request's CSRF cookie value; mint a new one if absent."""
    tok = request.cookies.get(_CSRF_COOKIE)
    if tok and len(tok) >= 32:
        return tok
    return secrets.token_urlsafe(32)


def _csrf_check() -> bool:
    """True if the request's X-CSRF-Token header matches the cookie value."""
    if _CSRF_DISABLED:
        return True
    cookie_tok = request.cookies.get(_CSRF_COOKIE, "")
    header_tok = request.headers.get("X-CSRF-Token", "")
    if not cookie_tok or not header_tok:
        return False
    return hmac.compare_digest(cookie_tok, header_tok)


# ── Rate limiting (in-memory token bucket per IP) ─────────────────────────
# Lightweight per-IP request cap — avoids pulling in Flask-Limiter just for a
# single endpoint. Set APKANALYZER_RATE_LIMIT_PER_MIN=0 to disable. State is
# in-process so a multi-worker deployment will under-count by a factor of N
# (acceptable for the local-tooling threat model).
try:
    _RATE_LIMIT_PER_MIN = int(os.environ.get("APKANALYZER_RATE_LIMIT_PER_MIN", "10"))
except ValueError:
    _RATE_LIMIT_PER_MIN = 10
_RATE_LIMIT_HITS: dict[str, collections.deque] = {}
_RATE_LIMIT_LOCK = threading.Lock()


_TRUST_PROXY = os.environ.get("APKANALYZER_TRUST_PROXY", "").lower() in (
    "1", "true", "yes",
)


def _client_ip() -> str:
    # X-Forwarded-For is fully attacker-controllable when we're not behind a
    # trusted reverse proxy: anyone can spoof the header to dodge per-IP rate
    # limits. Honour it only when the operator opts in via APKANALYZER_TRUST_PROXY=1.
    if _TRUST_PROXY:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def _rate_limit_ok(ip: str) -> bool:
    """Return True if the caller is under the per-minute cap."""
    if _RATE_LIMIT_PER_MIN <= 0:
        return True
    now = time.time()
    cutoff = now - 60
    with _RATE_LIMIT_LOCK:
        hits = _RATE_LIMIT_HITS.setdefault(ip, collections.deque())
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= _RATE_LIMIT_PER_MIN:
            return False
        hits.append(now)
        # Opportunistic GC of stale keys so a long-running server doesn't
        # accumulate one entry per ever-seen IP.
        if len(_RATE_LIMIT_HITS) > 4096:
            for stale_ip in list(_RATE_LIMIT_HITS):
                if not _RATE_LIMIT_HITS[stale_ip]:
                    del _RATE_LIMIT_HITS[stale_ip]
        return True


# ── Persistent scan registry (SQLite) + live in-memory state ──────────────
# Live state (event queues, in-flight reports) can't be serialised so it
# stays in memory. Durable state (status, error, summary counters, on-disk
# report path) goes to SQLite so a server restart doesn't lose it.
_store = ScanStore()
_scans: dict[str, dict] = {}
_scans_lock = threading.Lock()


# ── APK magic-byte validation ─────────────────────────────────────────────
# An APK is a ZIP archive — local file headers start with PK\x03\x04, central
# directory with PK\x01\x02, EOCD with PK\x05\x06. We accept any of those
# at offset 0 (the first one is by far the most common).
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _validate_apk_upload(file_storage) -> tuple[bool, str]:
    """
    Stream-peek the uploaded file's first 4 bytes WITHOUT saving it to disk.
    Returns (ok, reason). On ok=True the file pointer is rewound so the
    subsequent .save(...) writes the full payload.
    """
    try:
        head = file_storage.stream.read(4)
    except Exception as exc:
        return False, f"could not read upload: {exc}"
    try:
        file_storage.stream.seek(0)
    except Exception:
        return False, "upload stream not seekable"
    if not any(head.startswith(magic[:4]) for magic in _ZIP_MAGIC):
        return False, f"not a ZIP/APK (magic={head!r})"
    return True, ""


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    token = _ensure_csrf_token()
    resp = make_response(render_template("index.html", csrf_token=token))
    # SameSite=Strict blocks the cookie from cross-site form posts entirely;
    # together with the header echo this is a complete double-submit defence.
    # httponly is False because the page JS needs to read the cookie to
    # populate the X-CSRF-Token header on /scan uploads.
    resp.set_cookie(
        _CSRF_COOKIE, token,
        max_age=86400, httponly=False, samesite="Strict",
        secure=request.is_secure,
    )
    return resp


@app.route("/scan", methods=["POST"])
@require_token
def start_scan():
    if not _rate_limit_ok(_client_ip()):
        return jsonify({"error": "Rate limit exceeded — try again in a minute"}), 429
    if not _csrf_check():
        return jsonify({"error": "Missing or invalid CSRF token"}), 403
    if "apk" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["apk"]
    _ACCEPTED_EXTS = (".apk", ".aab", ".xapk", ".apks", ".apkm")
    if not file.filename or Path(file.filename).suffix.lower() not in _ACCEPTED_EXTS:
        return jsonify({"error": f"Accepted formats: {', '.join(_ACCEPTED_EXTS)}"}), 400

    # Validate the magic bytes BEFORE writing the upload to disk. This stops
    # an attacker from briefly persisting arbitrary content under a .apk
    # filename, which would otherwise be world-readable until cleaned up.
    ok, reason = _validate_apk_upload(file)
    if not ok:
        return jsonify({"error": f"Invalid APK: {reason}"}), 400

    scan_id = str(uuid.uuid4())
    file_ext = Path(file.filename).suffix.lower() or ".apk"
    # Sanitize filename once at ingress — used in SSE events and JSON responses
    safe_filename = html.escape(Path(file.filename).name)
    apk_path = UPLOAD_DIR / f"{scan_id}{file_ext}"
    file.save(str(apk_path))

    confidence = request.form.get("confidence", "LOW").upper()
    if confidence not in ("HIGH", "MEDIUM", "LOW"):
        confidence = "LOW"
    from apkanalyzer import DEFAULT_TAINT_DEPTH
    try:
        taint_depth = max(
            1,
            min(20, int(request.form.get("taint_depth", str(DEFAULT_TAINT_DEPTH)))),
        )
    except (TypeError, ValueError):
        taint_depth = DEFAULT_TAINT_DEPTH

    q: queue.Queue = queue.Queue()

    started_at = int(time.time())
    with _scans_lock:
        _scans[scan_id] = {
            "status": "queued",
            "queue": q,
            "report": None,
            "error": None,
            "filename": safe_filename,
            "started_at": started_at,
        }
    _store.insert(scan_id, safe_filename, started_at)

    # Fast path: return cached result if same APK was scanned before
    try:
        from apkanalyzer.cache.scan_cache import ScanCache
        cached = ScanCache().get(str(apk_path))
        if cached:
            with _scans_lock:
                _scans[scan_id]["report"] = cached
                _scans[scan_id]["status"] = "done"
            cached_summary = cached.get("summary", {}) or {}
            cached_meta = cached.get("metadata", {}) or {}
            cached_sev = cached_summary.get("by_severity", {}) or {}
            try:
                _store.update_status(
                    scan_id,
                    status="done",
                    package=cached_meta.get("package"),
                    completed_at=int(time.time()),
                    total=cached_summary.get("total", 0),
                    critical=cached_sev.get("CRITICAL", 0),
                    high=cached_sev.get("HIGH", 0),
                    medium=cached_sev.get("MEDIUM", 0),
                    low=cached_sev.get("LOW", 0),
                    grade=cached_summary.get("risk_grade"),
                    target_sdk=str(cached_meta.get("target_sdk", "")),
                    min_sdk=str(cached_meta.get("min_sdk", "")),
                    duration=int(cached_meta.get("analysis_duration_seconds", 0) or 0),
                    by_owasp=json.dumps(cached_summary.get("by_owasp") or {}),
                )
            except Exception as exc:
                log.debug("ScanStore cache-hit update failed: %s", exc)
            _emit(scan_id, {"type": "progress", "stage": "Cache Hit", "detail": "Returning cached result", "pct": 100})
            _emit(scan_id, {"type": "done", "summary": cached_summary, "scan_id": scan_id})
            return jsonify({"scan_id": scan_id, "cache_hit": True})
    except Exception:
        pass

    t = threading.Thread(
        target=_run_scan,
        args=(scan_id, str(apk_path), confidence, taint_depth),
        daemon=True,
    )
    t.start()

    return jsonify({"scan_id": scan_id})


@app.route("/progress/<scan_id>")
def progress(scan_id: str):
    """Server-Sent Events stream — browser receives live stage updates."""
    with _scans_lock:
        entry = _scans.get(scan_id)
    if not entry:
        return jsonify({"error": "Unknown scan ID"}), 404

    def generate():
        q = entry["queue"]
        while True:
            try:
                msg = q.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") in ("done", "error"):
                    break
            except queue.Empty:
                # Heartbeat to keep the connection alive
                yield "data: {\"type\":\"ping\"}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/result/<scan_id>")
def result(scan_id: str):
    with _scans_lock:
        entry = _scans.get(scan_id)
    if not entry:
        return jsonify({"error": "Unknown scan ID"}), 404
    if entry["error"]:
        return jsonify({"error": entry["error"]}), 500
    if entry["report"] is None:
        return jsonify({"status": "running"}), 202
    return jsonify(entry["report"])


@app.route("/report/<scan_id>")
def html_report(scan_id: str):
    path = REPORT_DIR / scan_id / "report.html"
    if not path.exists():
        return "Report not ready yet", 404
    return path.read_text()


@app.route("/history")
def history():
    """List all completed scans — sourced from ScanStore (SQLite)."""
    rows = _store.list_recent(limit=500, status="done")
    entries = []
    for r in rows:
        ts = r.get("completed_at") or r.get("started_at") or 0
        entries.append({
            "scan_id": r["scan_id"],
            "package": r.get("package") or "unknown",
            "target_sdk": r.get("target_sdk") or "?",
            "total": r.get("total", 0),
            "critical": r.get("critical", 0),
            "high": r.get("high", 0),
            "risk_grade": r.get("grade") or "?",
            "duration": r.get("duration", 0),
            "scanned_at": time.strftime(
                "%Y-%m-%d %H:%M UTC", time.gmtime(ts)
            ) if ts else "—",
        })

    # Local accumulator is named `page` (not `html`) so it doesn't shadow the
    # stdlib `html` module we use below for escaping user-controlled fields.
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APKAnalyzer — Scan History</title>
<style>
  :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#c9d1d9;--muted:#8b949e;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{background:var(--bg);color:var(--text);font:14px/1.6 'Segoe UI',system-ui,sans-serif;}
  a{color:#58a6ff;text-decoration:none;}a:hover{text-decoration:underline;}
  header{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 32px;}
  header h1{font-size:20px;}
  .container{max-width:1100px;margin:0 auto;padding:24px 32px;}
  table{width:100%;border-collapse:collapse;}
  th{text-align:left;padding:10px 12px;font-size:11px;text-transform:uppercase;
     color:var(--muted);background:var(--surface);border-bottom:1px solid var(--border);}
  td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px;}
  tr:hover td{background:rgba(255,255,255,.02);}
  .grade{font-weight:700;}
  .grade-A{color:#00b894;} .grade-B{color:#00cec9;} .grade-C{color:#fdcb6e;}
  .grade-D{color:#e17055;} .grade-F{color:#d63031;}
  .empty{text-align:center;padding:48px;color:var(--muted);}
</style>
</head>
<body>
<header><h1>APKAnalyzer — Scan History</h1></header>
<div class="container">
"""
    if not entries:
        page += '<div class="empty">No completed scans yet.</div>'
    else:
        page += """<table>
<tr>
  <th>Package</th><th>Risk</th><th>Total</th><th>Critical</th>
  <th>High</th><th>SDK</th><th>Duration</th><th>Scanned</th><th>Actions</th>
</tr>"""
        for e in entries:
            # Every field below originates in user-controlled APK metadata
            # (package name, manifest SDK strings, etc). Without escaping a
            # crafted package name like `<script>...</script>` would execute
            # in the operator's browser the moment they open /history.
            grade = html.escape(str(e["risk_grade"]))
            esc = {
                "package":    html.escape(str(e["package"])),
                "total":      html.escape(str(e["total"])),
                "critical":   html.escape(str(e["critical"])),
                "high":       html.escape(str(e["high"])),
                "target_sdk": html.escape(str(e["target_sdk"])),
                "duration":   html.escape(str(e["duration"])),
                "scanned_at": html.escape(str(e["scanned_at"])),
                # scan_id is server-generated UUID4, but escape defensively
                # in case the schema is ever loosened.
                "scan_id":    html.escape(str(e["scan_id"])),
            }
            page += f"""<tr>
  <td>{esc['package']}</td>
  <td><span class="grade grade-{grade}">{grade}</span></td>
  <td>{esc['total']}</td>
  <td style="color:#d63031;">{esc['critical']}</td>
  <td style="color:#e17055;">{esc['high']}</td>
  <td>{esc['target_sdk']}</td>
  <td>{esc['duration']}s</td>
  <td>{esc['scanned_at']}</td>
  <td>
    <a href="/report/{esc['scan_id']}">HTML</a> &nbsp;
    <a href="/download/{esc['scan_id']}">JSON</a>
  </td>
</tr>"""
        page += "</table>"
    page += "</div></body></html>"
    return page


@app.route("/download/<scan_id>")
def download(scan_id: str):
    path = REPORT_DIR / scan_id / "report.json"
    if not path.exists():
        return "Report not found", 404
    return send_file(str(path), as_attachment=True, download_name="apkanalyzer_report.json")


@app.route("/api/stats")
def api_stats():
    """Aggregate stats across every completed scan — sourced from ScanStore."""
    rows = _store.list_recent(limit=10000, status="done")

    total_scans = len(rows)
    total_findings = 0
    by_grade: dict = {}
    by_severity: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    by_owasp: dict = {}
    recent: list = []

    for r in rows:
        total_findings += r.get("total", 0)
        grade = r.get("grade") or "?"
        by_grade[grade] = by_grade.get(grade, 0) + 1
        by_severity["CRITICAL"] += r.get("critical", 0)
        by_severity["HIGH"] += r.get("high", 0)
        by_severity["MEDIUM"] += r.get("medium", 0)
        by_severity["LOW"] += r.get("low", 0)
        # by_owasp is stored as JSON in the row — best-effort decode.
        raw_owasp = r.get("by_owasp")
        if raw_owasp:
            try:
                for cat, n in (json.loads(raw_owasp) or {}).items():
                    by_owasp[cat] = by_owasp.get(cat, 0) + n
            except (ValueError, TypeError):
                pass
        if len(recent) < 8:
            ts = r.get("completed_at") or r.get("started_at") or 0
            recent.append({
                "scan_id": r["scan_id"],
                "package": r.get("package") or "unknown",
                "grade": grade,
                "total": r.get("total", 0),
                "scanned_at": time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "—",
            })

    return jsonify({
        "total_scans": total_scans,
        "total_findings": total_findings,
        "by_grade": by_grade,
        "by_severity": by_severity,
        "by_owasp": by_owasp,
        "recent": recent,
    })


@app.route("/api/scans")
def api_scans():
    """List every completed scan — sourced from ScanStore."""
    rows = _store.list_recent(limit=500, status="done")
    out = []
    for r in rows:
        ts = r.get("completed_at") or r.get("started_at") or 0
        out.append({
            "scan_id": r["scan_id"],
            "package": r.get("package") or "unknown",
            "filename": r.get("filename", ""),
            "target_sdk": r.get("target_sdk"),
            "min_sdk": r.get("min_sdk"),
            "grade": r.get("grade") or "?",
            "total": r.get("total", 0),
            "critical": r.get("critical", 0),
            "high": r.get("high", 0),
            "medium": r.get("medium", 0),
            "low": r.get("low", 0),
            "duration": r.get("duration", 0),
            "scanned_at": time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) if ts else "—",
        })
    return jsonify(out)


@app.route("/api/owasp")
def api_owasp():
    """Static OWASP MASVS / Mobile Top-10 reference table — used by the MASVS tab."""
    try:
        from apkanalyzer.scoring.owasp import OWASP_CATEGORIES
        items = [{"code": k, "title": v} for k, v in OWASP_CATEGORIES.items()]
    except Exception:
        items = []
    return jsonify(items)


# ── OpenAPI / Swagger UI ───────────────────────────────────────────────────
# Spec lives in web/openapi.yaml; loaded once at startup so the JSON endpoint
# is a constant-cost dict serialisation. Reload requires a process restart,
# matching how rules and other static config are handled in this app.
_OPENAPI_PATH = Path(__file__).parent / "openapi.yaml"
_OPENAPI_DOC: dict | None = None


def _load_openapi() -> dict:
    """Load and cache the OpenAPI document. Returns {} if PyYAML or the
    file is unavailable (the /docs UI degrades gracefully)."""
    global _OPENAPI_DOC
    if _OPENAPI_DOC is not None:
        return _OPENAPI_DOC
    try:
        import yaml  # PyYAML is already a hard dep via apkanalyzer/rules
        _OPENAPI_DOC = yaml.safe_load(_OPENAPI_PATH.read_text()) or {}
    except Exception as exc:
        log.warning("OpenAPI load failed: %s", exc)
        _OPENAPI_DOC = {}
    return _OPENAPI_DOC


@app.route("/openapi.json")
def openapi_json():
    """Serve the OpenAPI 3.1 spec as JSON for tooling that prefers JSON."""
    return jsonify(_load_openapi())


@app.route("/docs")
def docs():
    """Swagger UI rendered against /openapi.json. CDN-hosted bundle keeps
    the server payload tiny (~3 KB of HTML)."""
    return Response(
        """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>APKAnalyzer API — Swagger UI</title>
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body style="margin:0">
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: '/openapi.json',
      dom_id: '#swagger-ui',
      deepLinking: true,
    });
  </script>
</body>
</html>""",
        mimetype="text/html",
    )


@app.route("/sarif/<scan_id>")
def sarif_export(scan_id: str):
    """Export the scan in SARIF v2.1 format for Code Scanning ingestion."""
    path = REPORT_DIR / scan_id / "report.json"
    if not path.exists():
        return "Report not found", 404
    try:
        report = json.loads(path.read_text())
        from apkanalyzer.reporting.sarif_reporter import SARIFReporter
        sarif_path = REPORT_DIR / scan_id / "report.sarif"
        SARIFReporter().write(report, str(sarif_path))
        return send_file(str(sarif_path), as_attachment=True, download_name="apkanalyzer.sarif")
    except Exception as exc:
        log.error("SARIF export failed: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ── Background scanner ─────────────────────────────────────────────────────

def _emit(scan_id: str, msg: dict) -> None:
    with _scans_lock:
        entry = _scans.get(scan_id)
    if entry:
        entry["queue"].put(msg)


def _run_scan(scan_id: str, apk_path: str, confidence: str, taint_depth: int) -> None:
    """
    Run the full analysis pipeline in a background thread.

    All orchestration is delegated to AnalysisPipeline so the web UI stays in
    sync with CLI behaviour automatically when new detectors are added.
    Progress events are forwarded via the pipeline's progress_callback hook.
    """

    def emit_stage(stage: str, detail: str = "", pct: int = 0) -> None:
        _emit(scan_id, {
            "type": "progress",
            "stage": stage,
            "detail": detail,
            "pct": pct,
        })

    try:
        emit_stage("Starting", "Loading APK…", 5)

        from apkanalyzer.pipeline.orchestrator import AnalysisPipeline

        out_dir = REPORT_DIR / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)

        # Track manifest metadata as soon as it's available so the UI can
        # surface package/SDK info without waiting for the whole scan.
        meta_emitted = {"done": False}

        def progress_cb(stage: str, detail: str, pct: int) -> None:
            emit_stage(stage, detail, pct)
            # As soon as the pipeline parses the manifest, surface it.
            if not meta_emitted["done"] and stage == "Call Graph":
                pipeline_ctx = getattr(pipeline, "_ctx", None)
                if pipeline_ctx is not None and pipeline_ctx.manifest:
                    _emit(scan_id, {
                        "type": "meta",
                        "package": pipeline_ctx.manifest.get("package", "unknown"),
                        "target_sdk": pipeline_ctx.manifest.get("target_sdk", "?"),
                        "min_sdk": pipeline_ctx.manifest.get("min_sdk", "?"),
                    })
                    meta_emitted["done"] = True

        pipeline = AnalysisPipeline(
            apk_path=apk_path,
            output_dir=str(out_dir),
            min_confidence=confidence,
            run_apktool=True,
            taint_depth=taint_depth,
        )

        report = pipeline.run(progress_callback=progress_cb)

        with _scans_lock:
            _scans[scan_id]["report"] = report
            _scans[scan_id]["status"] = "done"

        summary = report.get("summary", {})
        meta = report.get("metadata", {})
        sev = summary.get("by_severity", {}) if isinstance(summary, dict) else {}
        _store.update_status(
            scan_id,
            status="done",
            package=meta.get("package"),
            completed_at=int(time.time()),
            total=summary.get("total", 0),
            critical=sev.get("CRITICAL", 0),
            high=sev.get("HIGH", 0),
            medium=sev.get("MEDIUM", 0),
            low=sev.get("LOW", 0),
            grade=summary.get("risk_grade"),
            target_sdk=str(meta.get("target_sdk", "")),
            min_sdk=str(meta.get("min_sdk", "")),
            duration=int(meta.get("analysis_duration_seconds", 0) or 0),
            by_owasp=json.dumps(summary.get("by_owasp") or {}),
            report_path=str(out_dir / "report.json"),
        )

        # Persist to the incremental scan cache so a re-upload of the same
        # APK returns instantly via the cache-hit fast path in /scan.
        try:
            from apkanalyzer.cache.scan_cache import ScanCache
            ScanCache().put(apk_path, report)
        except Exception as exc:
            log.debug("ScanCache put failed: %s", exc)

        _emit(scan_id, {"type": "done", "summary": summary, "scan_id": scan_id})

    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        log.error("Scan %s failed: %s\n%s", scan_id, exc, tb)
        with _scans_lock:
            if scan_id in _scans:
                _scans[scan_id]["error"] = str(exc)
                _scans[scan_id]["status"] = "error"
        try:
            _store.update_status(
                scan_id,
                status="error",
                error=str(exc),
                completed_at=int(time.time()),
            )
        except Exception:
            pass
        _emit(scan_id, {"type": "error", "message": str(exc)})
    finally:
        # Clean up the uploaded APK regardless of outcome.
        try:
            Path(apk_path).unlink(missing_ok=True)
        except OSError:
            pass
        # Evict completed/failed in-memory entry after a short TTL so the
        # live queue objects and cached report dict don't accumulate forever.
        # 300 s is enough for any SSE consumer to drain the queue and for
        # /result/<scan_id> to be called once; durable state lives in ScanStore.
        def _evict_later(sid: str, delay: int = 300) -> None:
            time.sleep(delay)
            with _scans_lock:
                _scans.pop(sid, None)
        threading.Thread(target=_evict_later, args=(scan_id,), daemon=True).start()


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5005, threaded=True)
