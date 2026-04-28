"""HTML dashboard reporter using Jinja2 templating."""

from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape


_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "templates"

_INLINE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APKAnalyzer Report — {{ metadata.package }}</title>
<style>
  :root {
    --critical: #d63031; --high: #e17055; --medium: #fdcb6e;
    --low: #00b894; --info: #74b9ff;
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font: 14px/1.6 'Segoe UI', system-ui, sans-serif; }
  a { color: #58a6ff; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 20px 32px; }
  header h1 { font-size: 20px; font-weight: 600; }
  header .meta { color: var(--muted); font-size: 12px; margin-top: 4px; }
  .container { max-width: 1280px; margin: 0 auto; padding: 24px 32px; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .badge { border-radius: 8px; padding: 16px; text-align: center; border: 1px solid var(--border); }
  .badge .count { font-size: 32px; font-weight: 700; }
  .badge .label { font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-top: 4px; }
  .badge.CRITICAL { border-color: var(--critical); color: var(--critical); }
  .badge.HIGH { border-color: var(--high); color: var(--high); }
  .badge.MEDIUM { border-color: var(--medium); color: var(--medium); }
  .badge.LOW { border-color: var(--low); color: var(--low); }
  .badge.TOTAL { border-color: var(--border); color: var(--text); }
  .risk-grade { display:inline-flex; align-items:center; justify-content:center;
                width:64px; height:64px; border-radius:50%; font-size:28px;
                font-weight:800; border:3px solid; margin-right:16px; }
  .risk-grade.A { border-color:var(--low); color:var(--low); }
  .risk-grade.B { border-color:#00cec9; color:#00cec9; }
  .risk-grade.C { border-color:var(--medium); color:var(--medium); }
  .risk-grade.D { border-color:var(--high); color:var(--high); }
  .risk-grade.F { border-color:var(--critical); color:var(--critical); }
  .filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .filter-btn { padding: 4px 12px; border-radius: 20px; border: 1px solid var(--border);
                background: transparent; color: var(--muted); cursor: pointer; font-size: 12px; }
  .filter-btn.active, .filter-btn:hover { background: var(--border); color: var(--text); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
             margin-bottom: 12px; overflow: hidden; }
  .finding-header { padding: 12px 16px; display: flex; align-items: center; gap: 12px;
                    cursor: pointer; user-select: none; }
  .finding-header:hover { background: rgba(255,255,255,0.03); }
  .sev { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px;
         text-transform: uppercase; letter-spacing: .05em; min-width: 70px; text-align: center; }
  .sev.CRITICAL { background: var(--critical); color: #fff; }
  .sev.HIGH { background: var(--high); color: #fff; }
  .sev.MEDIUM { background: var(--medium); color: #000; }
  .sev.LOW { background: var(--low); color: #fff; }
  .conf { font-size: 11px; color: var(--muted); }
  .finding-title { flex: 1; font-weight: 500; }
  .finding-body { padding: 16px; border-top: 1px solid var(--border); display: none; }
  .finding-body.open { display: block; }
  .finding-body .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .field-label { font-size: 11px; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 10px;
        font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .flow { font-size: 12px; color: var(--muted); }
  .flow span { color: var(--text); }
  .remediation { background: rgba(0,184,148,0.1); border: 1px solid var(--low);
                 border-radius: 4px; padding: 10px; font-size: 13px; }
  .perms { display: flex; flex-wrap: wrap; gap: 6px; }
  .perm { font-size: 11px; background: var(--border); padding: 2px 8px; border-radius: 4px; }
  .perm.danger { background: rgba(214,48,49,0.2); color: var(--critical); }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 32px; }
</style>
</head>
<body>
<header>
  <h1>APKAnalyzer Security Report</h1>
  <div class="meta">
    Package: <strong>{{ metadata.package }}</strong> &nbsp;|&nbsp;
    Target SDK: {{ metadata.target_sdk }} &nbsp;|&nbsp;
    Min SDK: {{ metadata.min_sdk }} &nbsp;|&nbsp;
    Analysis: {{ metadata.analysis_duration_seconds }}s
  </div>
</header>

<div class="container">

  <!-- Risk grade + summary -->
  <div style="display:flex;align-items:center;margin-bottom:16px;">
    <div class="risk-grade {{ summary.risk_grade }}" title="Overall Risk Grade">{{ summary.risk_grade }}</div>
    <div>
      <div style="font-size:13px;color:var(--muted);">Overall Risk Grade</div>
      <div style="font-size:11px;color:var(--muted);">A=clean · B=low · C=medium · D=high · F=critical</div>
    </div>
  </div>

  <!-- Summary badges -->
  <div class="summary-grid">
    <div class="badge TOTAL"><div class="count">{{ summary.total }}</div><div class="label">Total</div></div>
    {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW'] %}
    <div class="badge {{ sev }}">
      <div class="count">{{ summary.by_severity[sev] }}</div>
      <div class="label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  <!-- Permissions -->
  {% if metadata.dangerous_permissions %}
  <div style="margin-bottom:24px;">
    <div class="field-label" style="margin-bottom:8px;">Dangerous Permissions</div>
    <div class="perms">
      {% for p in metadata.dangerous_permissions %}
      <span class="perm danger">{{ p }}</span>
      {% endfor %}
      {% for p in metadata.permissions %}
      {% if p not in metadata.dangerous_permissions %}
      <span class="perm">{{ p }}</span>
      {% endif %}
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- Charts row -->
  <div style="display:grid;grid-template-columns:1fr 2fr 2fr;gap:16px;margin-bottom:24px;">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;">
      <div class="field-label" style="margin-bottom:8px;">Severity</div>
      <canvas id="sevChart" height="180"></canvas>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;">
      <div class="field-label" style="margin-bottom:8px;">Category Breakdown</div>
      <canvas id="catChart" height="180"></canvas>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;">
      <div class="field-label" style="margin-bottom:8px;">OWASP Mobile Top 10</div>
      <canvas id="owaspChart" height="180"></canvas>
    </div>
  </div>

  <!-- Severity filter -->
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px;">
    <span style="font-size:11px;color:var(--muted);text-transform:uppercase;">Severity:</span>
    <button class="filter-btn sev-btn active" onclick="filterBySev('ALL',this)">All</button>
    {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
    {% if summary.by_severity[sev] %}
    <button class="filter-btn sev-btn" onclick="filterBySev('{{ sev }}',this)">{{ sev }} ({{ summary.by_severity[sev] }})</button>
    {% endif %}
    {% endfor %}
  </div>

  <!-- Category filter -->
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:16px;">
    <span style="font-size:11px;color:var(--muted);text-transform:uppercase;">Category:</span>
    <button class="filter-btn cat-btn active" onclick="filterByCat('ALL',this)">All</button>
    {% for cat in summary.by_category.keys() %}
    <button class="filter-btn cat-btn" onclick="filterByCat('{{ cat }}', this)">{{ cat }} ({{ summary.by_category[cat] }})</button>
    {% endfor %}
  </div>

  <!-- Toolbar: search + sort + expand -->
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:16px;flex-wrap:wrap;">
    <input id="search-input" type="text" placeholder="Search findings…"
      style="background:var(--surface);border:1px solid var(--border);border-radius:6px;
             padding:6px 12px;color:var(--text);font-size:13px;flex:1;min-width:200px;">
    <span style="font-size:11px;color:var(--muted);">Sort by:</span>
    <button class="filter-btn" onclick="sortFindings('severity')">Severity</button>
    <button class="filter-btn" onclick="sortFindings('cvss')">CVSS</button>
    <button class="filter-btn" onclick="sortFindings('confidence')">Confidence</button>
    <button class="filter-btn" onclick="expandAll()">Expand all</button>
    <button class="filter-btn" onclick="collapseAll()">Collapse all</button>
  </div>

  <!-- Findings -->
  <div id="findings-list">
  {% for f in findings %}
  <div class="finding" data-category="{{ f.category }}" data-severity="{{ f.severity }}"
       data-confidence="{{ f.confidence }}" data-cvss="{{ f.cvss }}">
    <div class="finding-header" onclick="toggleBody(this)">
      <span class="sev {{ f.severity }}">{{ f.severity }}</span>
      <span class="finding-title">{{ f.title }}</span>
      <span class="conf">{{ f.confidence }}</span>
      {% if f.cvss %}<span style="font-size:11px;color:var(--muted);">CVSS {{ f.cvss }}</span>{% endif %}
      <span style="color:var(--muted);font-size:12px;">{{ f.category }}</span>
      {% if f.owasp_category %}<span style="font-size:10px;background:#30363d;padding:1px 6px;border-radius:4px;color:#a29bfe;">{{ f.owasp_category.split(':')[0] }}</span>{% endif %}
    </div>
    <div class="finding-body">
      <div class="grid">
        <div>
          <div class="field-label">Description</div>
          <p>{{ f.description }}</p>

          <div class="field-label" style="margin-top:12px;">Location</div>
          <p style="font-size:12px;font-family:monospace;">
            {{ f.location.class }}→{{ f.location.method }}<br>
            {% if f.location.file %}{{ f.location.file }}{% if f.location.line %}:{{ f.location.line }}{% endif %}{% endif %}
          </p>

          {% if f.taint_flow %}
          <div class="field-label" style="margin-top:12px;">Data Flow</div>
          <div class="flow">
            Source: <span>{{ f.taint_flow.source.label }}</span> @ {{ f.taint_flow.source.method }}<br>
            Sink: <span>{{ f.taint_flow.sink.label }}</span> @ {{ f.taint_flow.sink.method }}<br>
            {% if f.taint_flow.call_chain %}
            Chain: <span>{{ f.taint_flow.call_chain | join(' → ') }}</span>
            {% endif %}
          </div>
          {% endif %}

          {% if f.owasp_category %}
          <div class="field-label" style="margin-top:12px;">OWASP Mobile Top 10</div>
          <p style="font-size:12px;color:#a29bfe;">{{ f.owasp_category }}</p>
          {% endif %}
        </div>
        <div>
          <div class="field-label">Evidence</div>
          <pre>{{ f.evidence }}</pre>

          <div class="field-label" style="margin-top:12px;">Remediation</div>
          <div class="remediation">{{ f.remediation }}</div>

          <div style="margin-top:12px;font-size:12px;color:var(--muted);">
            Rule: {{ f.rule_id }} &nbsp;|&nbsp; CWE: {{ f.cwe_id }}
            {% if f.cvss %} &nbsp;|&nbsp; CVSS: {{ "%.1f"|format(f.cvss) }}{% endif %}
            {% if f.cvss_vector %}<br><span style="font-family:monospace;font-size:10px;">{{ f.cvss_vector }}</span>{% endif %}
          </div>
        </div>
      </div>
    </div>
  </div>
  {% else %}
  <div style="text-align:center;padding:48px;color:var(--muted);">No findings above threshold.</div>
  {% endfor %}
  </div>

</div>

<footer>Generated by APKAnalyzer &nbsp;·&nbsp; {{ metadata.package }}</footer>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
// ── Charts ───────────────────────────────────────────────────────────────────
(function() {
  const SEV_COLORS = {
    CRITICAL:'#d63031', HIGH:'#e17055', MEDIUM:'#fdcb6e', LOW:'#00b894', INFO:'#74b9ff'
  };
  const sevData = {{ summary.by_severity | tojson }};
  const catData = {{ summary.by_category | tojson }};
  const owaspData = {{ summary.by_owasp | tojson if summary.by_owasp else '{}' }};
  const confData = {{ summary.by_confidence | tojson }};

  // Severity donut
  const sevCtx = document.getElementById('sevChart');
  if (sevCtx) {
    const labels = Object.keys(sevData).filter(k => sevData[k] > 0);
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels,
        datasets:[{ data: labels.map(l=>sevData[l]),
          backgroundColor: labels.map(l=>SEV_COLORS[l]||'#999'), borderWidth:0 }]
      },
      options: { plugins:{ legend:{ labels:{ color:'#c9d1d9', font:{size:11} } } }, cutout:'65%' }
    });
  }

  // Category bar
  const catCtx = document.getElementById('catChart');
  if (catCtx) {
    const cats = Object.keys(catData);
    new Chart(catCtx, {
      type: 'bar',
      data: {
        labels: cats,
        datasets:[{ label:'Findings', data: cats.map(c=>catData[c]),
          backgroundColor:'#58a6ff', borderRadius:4 }]
      },
      options: {
        indexAxis:'y',
        plugins:{ legend:{display:false} },
        scales:{
          x:{ ticks:{color:'#8b949e'}, grid:{color:'#30363d'} },
          y:{ ticks:{color:'#c9d1d9'} }
        }
      }
    });
  }

  // OWASP bar
  const owaspCtx = document.getElementById('owaspChart');
  if (owaspCtx && Object.keys(owaspData).length) {
    const cats = Object.keys(owaspData);
    new Chart(owaspCtx, {
      type: 'bar',
      data: {
        labels: cats.map(c => c.split(':')[0]),  // M1, M2 ...
        datasets:[{ label:'Findings', data: cats.map(c=>owaspData[c]),
          backgroundColor:'#a29bfe', borderRadius:4 }]
      },
      options: {
        plugins:{ legend:{display:false},
          tooltip:{ callbacks:{ title: items => cats[items[0].dataIndex] } } },
        scales:{
          x:{ ticks:{color:'#c9d1d9'}, grid:{color:'#30363d'} },
          y:{ ticks:{color:'#8b949e'} }
        }
      }
    });
  }
})();

// ── Interactions ─────────────────────────────────────────────────────────────
function toggleBody(header) {
  header.nextElementSibling.classList.toggle('open');
}

let activeFilters = { sev: 'ALL', cat: 'ALL' };
function applyFilters() {
  document.querySelectorAll('.finding').forEach(f => {
    const sevOk = activeFilters.sev === 'ALL' || f.dataset.severity === activeFilters.sev;
    const catOk = activeFilters.cat === 'ALL' || f.dataset.category === activeFilters.cat;
    f.style.display = (sevOk && catOk) ? '' : 'none';
  });
}
function filterBySev(sev, btn) {
  activeFilters.sev = sev;
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}
function filterByCat(cat, btn) {
  activeFilters.cat = cat;
  document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}

// Sort findings
function sortFindings(key) {
  const container = document.getElementById('findings-list');
  const items = [...container.querySelectorAll('.finding')];
  const sevRank = {CRITICAL:5, HIGH:4, MEDIUM:3, LOW:2, INFO:1};
  const confRank = {HIGH:3, MEDIUM:2, LOW:1};
  items.sort((a, b) => {
    if (key === 'severity') return (sevRank[b.dataset.severity]||0) - (sevRank[a.dataset.severity]||0);
    if (key === 'confidence') return (confRank[b.dataset.confidence]||0) - (confRank[a.dataset.confidence]||0);
    if (key === 'cvss') return parseFloat(b.dataset.cvss||0) - parseFloat(a.dataset.cvss||0);
    return 0;
  });
  items.forEach(i => container.appendChild(i));
}

// Search
document.getElementById('search-input').addEventListener('input', function() {
  const q = this.value.toLowerCase();
  document.querySelectorAll('.finding').forEach(f => {
    f.style.display = f.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
});

// Expand / collapse all
function expandAll() { document.querySelectorAll('.finding-body').forEach(b => b.classList.add('open')); }
function collapseAll() { document.querySelectorAll('.finding-body').forEach(b => b.classList.remove('open')); }
</script>
</body>
</html>"""


class HTMLReporter:
    def write(self, report: dict, path: str) -> None:
        import json as _json

        def _tojson(val):
            return _json.dumps(val, default=str)

        # Try loading external template first; fall back to inline
        template_path = _TEMPLATE_DIR / "report.html"
        if template_path.exists():
            env = Environment(
                loader=FileSystemLoader(str(_TEMPLATE_DIR)),
                autoescape=select_autoescape(["html"]),
            )
        else:
            env = Environment(autoescape=select_autoescape(["html"]))
            env.globals["report"] = report
        env.filters["tojson"] = _tojson

        tmpl = (env.get_template("report.html")
                if template_path.exists()
                else env.from_string(_INLINE_TEMPLATE))

        # Ensure by_owasp is always present in summary
        report.setdefault("summary", {}).setdefault("by_owasp", {})

        html = tmpl.render(**report)
        Path(path).write_text(html, encoding="utf-8")
