#!/usr/bin/env python3
"""
EdgeIQ SMB Security Dashboard — MVP with real data endpoints.
Serves the dashboard UI and exposes security API endpoints
that aggregate from real scan JSON files.
"""
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# ── config ──────────────────────────────────────────────────────────────────────
PORT = int(os.getenv("PORT", "8113"))
SAMPLE_DIR = Path(Path(__file__).resolve().parents[1] / "sample-data")
UPGRADE_URL = "https://edgeiqlabs.com/#pricing"
PRO_TOKEN_ENV = "DASHBOARD_PRO_TOKEN"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RISK_LEVELS = {
    (80, 100): ("low", "Minimal Risk"),
    (60, 79): ("medium", "Moderate Risk"),
    (40, 59): ("high", "High Risk"),
    (0, 39): ("critical", "Critical Risk"),
}

HTML_TMPL = f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>EdgeIQ SMB Security Dashboard</title>
  <style>
    :root {{
      --bg: #0b0f14;
      --panel: #111827;
      --panel-2: #0f172a;
      --text: #e8eef7;
      --muted: #9fb0c7;
      --line: #243142;
      --accent: #3dd9ff;
      --ok: #4ade80;
      --warn: #f59e0b;
      --bad: #ef4444;
      --gold: #facc15;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, Arial, sans-serif;
    }}
    a {{ color: inherit; }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
    .topbar {{ display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom: 18px; }}
    h1 {{ margin: 0; font-size: 1.4rem; }}
    .muted {{ color: var(--muted); }}
    .search {{
      display:flex; gap:10px; margin-bottom:16px; flex-wrap: wrap;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
    }}
    .search input {{
      flex: 1;
      min-width: 220px;
      background: #0b1220;
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
    }}
    .search button, .btn {{
      background: var(--accent);
      color: #071018;
      border: 0;
      border-radius: 8px;
      padding: 10px 14px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }}
    .btn.secondary {{
      background: transparent;
      color: var(--text);
      border: 1px solid var(--line);
    }}
    .pro-banner {{
      background: linear-gradient(135deg, rgba(250,204,21,0.10), rgba(61,217,255,0.10));
      border: 1px solid rgba(250,204,21,0.28);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 16px;
      display: grid;
      gap: 10px;
    }}
    .pro-banner h2 {{ margin: 0; font-size: 1rem; }}
    .pro-banner p {{ margin: 0; color: var(--muted); }}
    .banner-row {{ display:flex; gap:10px; flex-wrap: wrap; align-items: center; }}
    .banner-row input {{
      min-width: 220px;
      flex: 1;
      background: #0b1220;
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px 12px;
    }}
    .banner-status {{ font-size: 0.92rem; color: var(--muted); }}
    .banner-status.ok {{ color: var(--ok); }}
    .banner-status.locked {{ color: var(--gold); }}
    .grid {{ display:grid; grid-template-columns: repeat(4,1fr); gap:12px; margin-bottom:12px; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
    }}
    .k {{ color: var(--muted); font-size: .82rem; margin-bottom: 6px; }}
    .v {{ font-size: 1.2rem; font-weight: 700; }}
    .v.small {{ font-size: .95rem; font-weight: 600; }}
    .row {{ display:grid; grid-template-columns: 1.3fr 1fr; gap:12px; margin-top:12px; }}
    .list {{ margin:0; padding-left: 18px; }}
    .sev {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }}
    .pill {{ border:1px solid var(--line); border-radius:999px; padding:3px 9px; font-size:.78rem; }}
    .critical {{ color:#fecaca; border-color:#7f1d1d; }}
    .high {{ color:#fca5a5; border-color:#991b1b; }}
    .medium {{ color:#fde68a; border-color:#854d0e; }}
    .low {{ color:#bbf7d0; border-color:#14532d; }}
    .info {{ color:#bfdbfe; border-color:#1e3a8a; }}
    .locked-card {{
      border-style: dashed;
      border-color: rgba(250,204,21,0.45);
      background: linear-gradient(180deg, rgba(17,24,39,1), rgba(17,24,39,0.92));
    }}
    .locked-state {{ display: grid; gap: 10px; color: var(--muted); }}
    .locked-state strong {{ color: var(--text); }}
    .cta-row {{ display:flex; gap:10px; flex-wrap: wrap; }}
    .inline-note {{ font-size: 0.85rem; color: var(--muted); }}
    @media (max-width: 940px) {{
      .grid {{ grid-template-columns: repeat(2,1fr); }}
      .row {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 640px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .topbar {{ align-items: flex-start; flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <div class='wrap'>
    <div class='topbar'>
      <div>
        <h1>SMB Security Dashboard</h1>
        <div class='muted'>Free score preview for any domain. Unlock the paid dashboard for alerts, summaries, and remediation guidance.</div>
      </div>
      <div id='last-updated' class='muted'>Ready</div>
    </div>

    <div class='pro-banner'>
      <div>
        <h2>Free preview live. Pro panels are locked.</h2>
        <p>Anyone can check score + risk. Paid customers can unlock summary, alerting, and recommendations with a Pro token.</p>
      </div>
      <div class='banner-row'>
        <input id='pro-token' type='password' placeholder='Optional Pro token to unlock paid panels'>
        <button id='unlock'>Unlock Pro</button>
        <a class='btn secondary' href='{UPGRADE_URL}' target='_blank' rel='noopener'>Upgrade</a>
      </div>
      <div id='pro-status' class='banner-status locked'>Paid panels are currently locked.</div>
    </div>

    <div class='search'>
      <input id='domain' value='example.com' placeholder='Enter domain (example.com)'>
      <button id='run'>Analyze Domain</button>
    </div>

    <div class='grid'>
      <div class='card'><div class='k'>Security Score</div><div class='v' id='score'>-</div></div>
      <div class='card'><div class='k'>Risk Level</div><div class='v' id='risk'>-</div></div>
      <div class='card' id='ports-card'><div class='k'>Open Ports</div><div class='v' id='ports'>-</div></div>
      <div class='card' id='alerts-card'><div class='k'>Active Alerts</div><div class='v' id='alerts'>-</div></div>
    </div>

    <div class='card'>
      <div class='k'>Severity Breakdown</div>
      <div class='sev'>
        <span class='pill critical'>Critical: <b id='sev-critical'>0</b></span>
        <span class='pill high'>High: <b id='sev-high'>0</b></span>
        <span class='pill medium'>Medium: <b id='sev-medium'>0</b></span>
        <span class='pill low'>Low: <b id='sev-low'>0</b></span>
        <span class='pill info'>Info: <b id='sev-info'>0</b></span>
      </div>
    </div>

    <div class='row'>
      <div class='card' id='recs-card'>
        <div class='k'>Top Recommendations</div>
        <ol class='list' id='recs'></ol>
      </div>
      <div class='card' id='alerts-list-card'>
        <div class='k'>Alerts</div>
        <ul class='list' id='alerts-list'></ul>
      </div>
    </div>
  </div>

  <script>
    const UPGRADE_URL = {json.dumps(UPGRADE_URL)};
    const $ = (id) => document.getElementById(id);

    function setText(id, val) {{ $(id).textContent = val == null ? '-' : String(val); }}

    function getToken() {{
      return ($('pro-token').value || '').trim();
    }}

    function buildHeaders() {{
      const token = getToken();
      return token ? {{ Authorization: `Bearer ${{token}}` }} : {{}};
    }}

    async function getJson(url, paid = false) {{
      const resp = await fetch(url, {{ headers: paid ? buildHeaders() : {{}} }});
      const data = await resp.json().catch(() => ({{}}));
      if (!resp.ok) {{
        const err = new Error(data.message || ('Request failed (' + resp.status + ')'));
        err.status = resp.status;
        err.payload = data;
        throw err;
      }}
      return data;
    }}

    function setLockedCard(cardId, valueId, label = 'Locked') {{
      const card = $(cardId);
      if (card) card.classList.add('locked-card');
      setText(valueId, label);
    }}

    function clearLockedCard(cardId) {{
      const card = $(cardId);
      if (card) card.classList.remove('locked-card');
    }}

    function lockedMarkup(title, message) {{
      return `
        <div class="locked-state">
          <div><strong>${{title}}</strong></div>
          <div>${{message}}</div>
          <div class="cta-row">
            <a class="btn" href="${{UPGRADE_URL}}" target="_blank" rel="noopener">Upgrade to Pro</a>
            <button class="btn secondary" type="button" onclick="document.getElementById('pro-token').focus()">Use token</button>
          </div>
        </div>
      `;
    }}

    function renderLockedPanels(message) {{
      const msg = message || 'Unlock the paid dashboard to view these panels.';
      setLockedCard('ports-card', 'ports');
      setLockedCard('alerts-card', 'alerts');
      $('recs').innerHTML = lockedMarkup('Recommendations are locked', msg);
      $('alerts-list').innerHTML = lockedMarkup('Alerts feed is locked', msg);
      $('pro-status').textContent = 'Paid panels are locked. Add a valid Pro token or upgrade to unlock everything.';
      $('pro-status').className = 'banner-status locked';
    }}

    function renderPaidPanels(summary, recs, alerts) {{
      clearLockedCard('ports-card');
      clearLockedCard('alerts-card');
      setText('ports', summary.network?.open_ports_count ?? '-');
      setText('alerts', summary.breach_alerts?.new_findings ?? '-');

      const recWrap = $('recs');
      recWrap.innerHTML = '';
      (recs.recommendations || []).slice(0, 8).forEach(r => {{
        const li = document.createElement('li');
        li.style.marginBottom = '6px';
        li.textContent = `[${{(r.severity || 'info').toUpperCase()}}] ${{r.title}}`;
        recWrap.appendChild(li);
      }});
      if (!recs.recommendations || recs.recommendations.length === 0) {{
        recWrap.innerHTML = '<li>No recommendations found.</li>';
      }}

      const alertsWrap = $('alerts-list');
      alertsWrap.innerHTML = '';
      (alerts.alerts || []).slice(0, 8).forEach(a => {{
        const li = document.createElement('li');
        li.style.marginBottom = '6px';
        li.textContent = `[${{(a.severity || 'info').toUpperCase()}}] ${{a.title}}`;
        alertsWrap.appendChild(li);
      }});
      if (!alerts.alerts || alerts.alerts.length === 0) {{
        alertsWrap.innerHTML = '<li>No alerts found.</li>';
      }}

      $('pro-status').textContent = getToken()
        ? 'Pro unlocked. Paid panels are live for this session.'
        : 'Paid panels loaded.';
      $('pro-status').className = 'banner-status ok';
    }}

    async function loadDashboard() {{
      const domain = ($('domain').value || 'example.com').trim();
      if (!domain) return;
      $('last-updated').textContent = `Loading ${{domain}}...`;

      try {{
        const score = await getJson(`/api/score?domain=${{encodeURIComponent(domain)}}`);
        setText('score', `${{score.score ?? '-'}} / 100`);
        setText('risk', (score.risk_level || '-').toUpperCase());

        const sev = score.severity_breakdown || {{}};
        setText('sev-critical', sev.critical ?? 0);
        setText('sev-high', sev.high ?? 0);
        setText('sev-medium', sev.medium ?? 0);
        setText('sev-low', sev.low ?? 0);
        setText('sev-info', sev.info ?? 0);
      }} catch (err) {{
        $('last-updated').textContent = err.message || 'Failed to load score';
        throw err;
      }}

      try {{
        const [summary, recs, alerts] = await Promise.all([
          getJson(`/api/summary?domain=${{encodeURIComponent(domain)}}`, true),
          getJson(`/api/recommendations?domain=${{encodeURIComponent(domain)}}`, true),
          getJson(`/api/alerts?domain=${{encodeURIComponent(domain)}}`, true)
        ]);
        renderPaidPanels(summary, recs, alerts);
      }} catch (err) {{
        if (err.status === 402) {{
          const message = err.payload?.message || 'Paid access is required.';
          renderLockedPanels(message);
        }} else {{
          $('recs').innerHTML = `<li>${{err.message || 'Failed to load recommendations.'}}</li>`;
          $('alerts-list').innerHTML = `<li>${{err.message || 'Failed to load alerts.'}}</li>`;
        }}
      }}

      $('last-updated').textContent = `Updated ${{new Date().toLocaleTimeString()}}`;
    }}

    $('run').addEventListener('click', loadDashboard);
    $('unlock').addEventListener('click', loadDashboard);
    $('domain').addEventListener('keydown', (e) => {{
      if (e.key === 'Enter') loadDashboard();
    }});
    $('pro-token').addEventListener('keydown', (e) => {{
      if (e.key === 'Enter') loadDashboard();
    }});

    const params = new URLSearchParams(window.location.search);
    if (params.get('token')) {{
      $('pro-token').value = params.get('token');
    }}

    renderLockedPanels('Use a Pro token or upgrade to unlock summary, alerts, and recommendations.');
    loadDashboard();
  </script>
</body>
</html>"""


# ── data loading helpers ────────────────────────────────────────────────────────

def _load_json(domain, prefix):
    """Load <prefix>_<domain>.json from sample-data dir, return {{}} if absent."""
    p = SAMPLE_DIR / f"{prefix}_{domain}.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def _aggregate_severity(domain):
    """Walk all scan files for a domain and return combined severity counts."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    xss = _load_json(domain, "xss")
    for f in xss.get("findings", []):
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    net = _load_json(domain, "network")
    for p in net.get("open_ports", []):
        sev = p.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
    for c in net.get("cves", []):
        sev = c.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    ssl = _load_json(domain, "ssl")
    for iss in ssl.get("issues", []):
        sev = iss.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    alrt = _load_json(domain, "alert")
    for a in alrt.get("alerts", []):
        sev = a.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    return counts


def _compute_score(domain):
    """Derive an aggregate 0-100 security score from severity breakdown."""
    counts = _aggregate_severity(domain)
    total = sum(counts.values())

    if total == 0:
        return 100, "low", counts

    penalty = (
        counts["critical"] * 40 +
        counts["high"] * 25 +
        counts["medium"] * 10 +
        counts["low"] * 3
    )
    worst = total * 40
    score = max(0, min(100, int(100 - (penalty / worst * 100))))

    for (lo, hi), (risk, _label) in RISK_LEVELS.items():
        if lo <= score <= hi:
            return score, risk, counts

    return score, "critical", counts


def _recommendations(domain):
    """Build priority-sorted list of remediation items from all scan types."""
    items = []

    xss = _load_json(domain, "xss")
    for f in xss.get("findings", []):
        items.append({
            "severity": f.get("severity", "info").lower(),
            "category": "XSS Scanner",
            "title": f.get("vulnerability", "Unknown"),
            "url": f.get("url", ""),
            "fix": f"Parameter '{f.get('parameter', '')}': {f.get('description', '')[:120]}",
        })

    net = _load_json(domain, "network")
    for p in net.get("open_ports", []):
        sev = p.get("severity", "low")
        if sev in ("high", "critical"):
            items.append({
                "severity": sev,
                "category": "Network Scanner",
                "title": f"Open port {p['port']} ({p.get('service', '')})",
                "url": "",
                "fix": p.get("risk", ""),
            })
    for c in net.get("cves", []):
        items.append({
            "severity": c.get("severity", "high").lower(),
            "category": "CVE",
            "title": f"{c.get('cve_id', '?')} — {c.get('description', '')[:80]}",
            "url": "",
            "fix": c.get("remediation", ""),
        })

    ssl = _load_json(domain, "ssl")
    for iss in ssl.get("issues", []):
        items.append({
            "severity": iss.get("severity", "medium").lower(),
            "category": "SSL Watcher",
            "title": iss.get("title", "SSL Issue"),
            "url": "",
            "fix": iss.get("remediation", ""),
        })

    alrt = _load_json(domain, "alert")
    for a in alrt.get("alerts", []):
        if not a.get("acknowledged", False):
            items.append({
                "severity": a.get("severity", "medium").lower(),
                "category": "Alert",
                "title": a.get("title", "Security Alert"),
                "url": "",
                "fix": a.get("description", "")[:120],
            })

    items.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 5), i["severity"]))
    return items


def _risk_label(risk_level):
    for _bounds, (risk, label) in RISK_LEVELS.items():
        if risk == risk_level:
            return label
    return "Unknown"


def _parse_request(path):
    parsed = urlparse(path)
    return parsed, parse_qs(parsed.query)


def _extract_bearer_token(headers):
    auth = headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return ""
    return auth.split(" ", 1)[1].strip()


def _is_paid_request(handler, qs):
    expected = os.getenv(PRO_TOKEN_ENV, "").strip()
    if not expected:
        return False

    query_token = (qs.get("token", [""])[0] or "").strip()
    header_token = _extract_bearer_token(handler.headers)
    return query_token == expected or header_token == expected


# ── HTTP handler ────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    paid_paths = {"/api/summary", "/api/alerts", "/api/recommendations"}

    def _json(self, code, payload):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _domain(self, qs):
        return qs.get("domain", ["example.com"])[0]

    def _paid_required(self):
        return self._json(402, {
            "error": "paid_required",
            "message": "This panel is part of the paid SMB dashboard. Upgrade for full summary, alerts, and remediation guidance.",
            "upgrade_url": UPGRADE_URL,
        })

    def _handle_head(self, path):
        known = {"/", "/health", "/api/summary", "/api/alerts", "/api/score", "/api/recommendations"}
        if path in known:
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        parsed, _qs = _parse_request(self.path)
        self._handle_head(parsed.path)

    def do_GET(self):
        parsed, qs = _parse_request(self.path)
        path = parsed.path
        domain = self._domain(qs)

        if path == "/health":
            return self._json(200, {"ok": True, "service": "smb-security-dashboard"})

        if path == "/":
            html = HTML_TMPL.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        if path in self.paid_paths and not _is_paid_request(self, qs):
            return self._paid_required()

        if path == "/api/summary":
            xss = _load_json(domain, "xss")
            net = _load_json(domain, "network")
            ssl = _load_json(domain, "ssl")
            alrt = _load_json(domain, "alert")
            score, risk_level, sev_counts = _compute_score(domain)

            ssl_issues = ssl.get("issues", [])
            days_exp = ssl.get("days_until_expiry", 0)
            ssl_ok = all(i.get("severity") not in ("critical", "high") for i in ssl_issues)
            active_alerts = [a for a in alrt.get("alerts", []) if not a.get("acknowledged")]
            new_findings = len(active_alerts)

            return self._json(200, {
                "domain": domain,
                "security_score": score,
                "risk_level": risk_level,
                "ssl": {
                    "grade": ssl.get("grade", "?"),
                    "days_until_expiry": days_exp,
                    "issues_count": len(ssl_issues),
                    "status": "ok" if ssl_ok else "action_required",
                },
                "network": {
                    "open_ports_count": len(net.get("open_ports", [])),
                    "cves_count": len(net.get("cves", [])),
                    "critical_services": [
                        {"port": p["port"], "service": p["service"]}
                        for p in net.get("open_ports", [])
                        if p.get("severity") in ("high", "critical")
                    ],
                },
                "xss": {
                    "findings_count": len(xss.get("findings", [])),
                    "critical_count": sum(1 for f in xss.get("findings", []) if f.get("severity") == "critical"),
                },
                "breach_alerts": {
                    "total": alrt.get("summary", {}).get("total_alerts", 0),
                    "new_findings": new_findings,
                    "status": "action_required" if new_findings > 0 else "ok",
                },
                "severity_breakdown": sev_counts,
                "scanned_at": {
                    "xss": xss.get("scanned_at", ""),
                    "network": net.get("scanned_at", ""),
                    "ssl": ssl.get("scanned_at", ""),
                    "alerts": alrt.get("period", ""),
                },
            })

        if path == "/api/alerts":
            alrt = _load_json(domain, "alert")
            alerts = alrt.get("alerts", [])
            return self._json(200, {
                "domain": domain,
                "total": len(alerts),
                "alerts": alerts,
                "summary": alrt.get("summary", {}),
            })

        if path == "/api/score":
            score, risk_level, sev_counts = _compute_score(domain)
            return self._json(200, {
                "domain": domain,
                "score": score,
                "risk_level": risk_level,
                "risk_label": _risk_label(risk_level),
                "severity_breakdown": sev_counts,
                "total_findings": sum(sev_counts.values()),
            })

        if path == "/api/recommendations":
            recs = _recommendations(domain)
            return self._json(200, {
                "domain": domain,
                "total": len(recs),
                "recommendations": recs,
            })

        return self._json(404, {"error": "not_found"})


# ── bootstrap ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[smb-security-dashboard] listening on 0.0.0.0:{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
