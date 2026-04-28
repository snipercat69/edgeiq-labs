#!/usr/bin/env python3
import io
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.getenv("REPORT_BUILDER_PORT", "8111"))
DEFAULT_SCAN_DIR = Path(
    os.getenv(
        "REPORT_SCAN_DATA_DIR",
        "/home/guy/.openclaw/workspace/apps/edgeiq-security-report-generator/sample-data",
    )
)
REPORT_PDF_SERVICE_URL = os.getenv(
    "REPORT_PDF_SERVICE_URL", "https://edgeiq-pdf3.onrender.com/generate"
)
REPORT_PDF_TIMEOUT_SECONDS = int(os.getenv("REPORT_PDF_TIMEOUT_SECONDS", "90"))

DEMO_HTML = """<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>White-Label Report Builder Demo</title>
  <style>
    body { font-family: Inter, Arial, sans-serif; background:#0b0f14; color:#e8eef7; margin:0; padding:24px; }
    .wrap { max-width:860px; margin:0 auto; }
    .card { background:#121923; border:1px solid #233142; border-radius:12px; padding:16px; margin-bottom:14px; }
    label { display:block; font-size:13px; color:#9fb0c7; margin:10px 0 6px; }
    input { width:100%; padding:10px; border-radius:8px; border:1px solid #233142; background:#0f1720; color:#e8eef7; }
    button { margin-top:12px; margin-right:8px; padding:10px 14px; border:0; border-radius:8px; font-weight:700; cursor:pointer; }
    .primary { background:#3dd9ff; color:#071018; }
    .secondary { background:#1f2a37; color:#e8eef7; border:1px solid #2c3f55; }
    pre { white-space:pre-wrap; background:#0f1720; border:1px solid #233142; border-radius:8px; padding:12px; color:#9fb0c7; max-height:280px; overflow:auto; }
    .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
    @media (max-width: 700px) { .row { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<div class='wrap'>
  <h1>White-Label Report Builder · Demo</h1>
  <div class='card'>
    <div class='row'>
      <div>
        <label>Brand</label>
        <input id='brand' value='Cypher Security' />
      </div>
      <div>
        <label>Domain</label>
        <input id='domain' value='example.com' />
      </div>
    </div>
    <label>Contact Email</label>
    <input id='contact_email' value='hello@edgeiqlabs.com' />
    <div>
      <button class='secondary' onclick='preview()'>Preview JSON</button>
      <button class='primary' onclick='downloadPdf()'>Download PDF</button>
    </div>
  </div>

  <div class='card'>
    <h3 style='margin-top:0'>API Result</h3>
    <pre id='out'>Ready.</pre>
  </div>
</div>
<script>
  function payload(){
    return {
      brand: document.getElementById('brand').value,
      domain: document.getElementById('domain').value,
      contact_email: document.getElementById('contact_email').value
    };
  }
  async function preview(){
    const r = await fetch('/api/report/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload())});
    const j = await r.json();
    document.getElementById('out').textContent = JSON.stringify({ok:j.ok, score:j.security_score, risk:j.risk_level, severity:j.severity, top_critical:j.critical_findings, coverage:j.coverage}, null, 2);
  }
  async function downloadPdf(){
    const r = await fetch('/api/report/generate-pdf', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload())});
    if(!r.ok){
      const t = await r.text();
      document.getElementById('out').textContent = 'PDF error: ' + t;
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'edgeiq-white-label-report.pdf';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    document.getElementById('out').textContent = 'PDF generated and download triggered.';
  }
</script>
</body>
</html>
"""


def _safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default


def _severity_counter(items, severity_key="severity"):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in items or []:
        sev = str(item.get(severity_key, "")).lower().strip()
        if sev in c:
            c[sev] += 1
    return c


def _score_from_counts(counts):
    # Lightweight scoring model for MVP
    penalty = (
        counts.get("critical", 0) * 14
        + counts.get("high", 0) * 7
        + counts.get("medium", 0) * 3
        + counts.get("low", 0) * 1
    )
    return max(0, min(100, 100 - penalty))


def _load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _resolve_scan_paths(domain: str, scan_dir: Path):
    d = domain.strip().lower().replace("https://", "").replace("http://", "")
    # expected pattern: <tool>_<domain>.json
    return {
        "xss": scan_dir / f"xss_{d}.json",
        "network": scan_dir / f"network_{d}.json",
        "ssl": scan_dir / f"ssl_{d}.json",
        "alert": scan_dir / f"alert_{d}.json",
    }


def _sev_title(sev: str) -> str:
    s = (sev or "info").strip().lower()
    if not s:
        s = "info"
    return s[:1].upper() + s[1:]


def _default_cvss_for_sev(sev: str) -> float:
    s = (sev or "").lower()
    return {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.2,
        "info": 0.0,
    }.get(s, 0.0)


def _build_pdf_findings(xss_findings, network_cves, network_ports, ssl_issues, alert_items):
    findings = []

    for f in xss_findings:
        sev = f.get("severity", "medium")
        findings.append(
            {
                "name": f.get("vulnerability", "XSS Finding"),
                "severity": _sev_title(sev),
                "cvss": _default_cvss_for_sev(sev),
                "description": f.get("description", ""),
                "remediation": "Apply output encoding and strict input validation; add WAF/XSS protections.",
            }
        )

    for c in network_cves:
        sev = c.get("severity", "high")
        findings.append(
            {
                "name": c.get("cve_id", "CVE Finding"),
                "severity": _sev_title(sev),
                "cvss": c.get("cvss", _default_cvss_for_sev(sev)),
                "description": c.get("description", ""),
                "remediation": c.get("remediation", "Patch affected service to fixed version."),
            }
        )

    for p in network_ports:
        sev = p.get("severity", "low")
        if str(sev).lower() in ("info", "low"):
            # keep noisy low/info port data out of PDF headline findings
            continue
        findings.append(
            {
                "name": f"Exposed Port {p.get('port', '?')} ({p.get('service', 'service')})",
                "severity": _sev_title(sev),
                "cvss": _default_cvss_for_sev(sev),
                "description": p.get("risk", "Internet-exposed service detected."),
                "remediation": "Restrict exposure via firewall/VPN and harden service config.",
            }
        )

    for i in ssl_issues:
        sev = i.get("severity", "medium")
        findings.append(
            {
                "name": i.get("title", "SSL Issue"),
                "severity": _sev_title(sev),
                "cvss": _default_cvss_for_sev(sev),
                "description": i.get("description", ""),
                "remediation": i.get("remediation", "Update TLS/certificate configuration."),
            }
        )

    for a in alert_items:
        sev = a.get("severity", "medium")
        findings.append(
            {
                "name": a.get("title", "Alert"),
                "severity": _sev_title(sev),
                "cvss": _default_cvss_for_sev(sev),
                "description": a.get("description", ""),
                "remediation": "Investigate trigger source and resolve root cause.",
            }
        )

    # Keep PDF concise and sorted by severity
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda x: sev_rank.get(x.get("severity", "Info"), 9))
    return findings[:30]


def _build_report(brand, domain, contact_email, scan_dir):
    paths = _resolve_scan_paths(domain, scan_dir)
    xss = _load_json(paths["xss"])
    network = _load_json(paths["network"])
    ssl = _load_json(paths["ssl"])
    alert = _load_json(paths["alert"])

    # Fallback to bundled sample names if domain files are absent
    if not xss:
        xss = _load_json(scan_dir / "xss_example.com.json")
    if not network:
        network = _load_json(scan_dir / "network_example.com.json")
    if not ssl:
        ssl = _load_json(scan_dir / "ssl_example.com.json")
    if not alert:
        alert = _load_json(scan_dir / "alert_example.com.json")

    xss_findings = xss.get("findings", [])
    network_cves = network.get("cves", [])
    network_ports = network.get("open_ports", [])
    ssl_issues = ssl.get("issues", [])
    alert_items = alert.get("alerts", [])

    combined = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for src in [
        _severity_counter(xss_findings),
        _severity_counter(network_cves),
        _severity_counter(network_ports),
        _severity_counter(ssl_issues),
        _severity_counter(alert_items),
    ]:
        for k, v in src.items():
            combined[k] += v

    score = _score_from_counts(combined)
    if score >= 90:
        risk_level = "Low"
    elif score >= 75:
        risk_level = "Moderate"
    elif score >= 55:
        risk_level = "High"
    else:
        risk_level = "Critical"

    critical_findings = []
    for item in xss_findings + network_cves + ssl_issues + alert_items:
        if str(item.get("severity", "")).lower() == "critical":
            critical_findings.append(
                item.get("title")
                or item.get("vulnerability")
                or item.get("description", "Critical issue")
            )

    generated_at = datetime.now(timezone.utc).isoformat()

    summary = (
        f"{domain} currently scores {score}/100 ({risk_level} risk). "
        f"Detected {combined['critical']} critical and {combined['high']} high-severity findings "
        f"across application, network, SSL, and alert telemetry."
    )

    html = f"""<!doctype html>
<html><head><meta charset='utf-8'><title>{brand} Security Report</title></head>
<body style='font-family:Inter,Arial,sans-serif;background:#f8fafc;color:#0f172a;padding:24px;'>
  <h1 style='margin:0 0 6px;'>{brand} Security Report</h1>
  <p style='margin:0 0 16px;color:#334155;'>Target: <b>{domain}</b> · Generated: {generated_at}</p>
  <div style='border:1px solid #cbd5e1;border-radius:10px;padding:14px;background:#fff;'>
    <h2 style='margin:0 0 8px;'>Executive Summary</h2>
    <p style='margin:0 0 8px;'>{summary}</p>
    <p style='margin:0;'><b>Security score:</b> {score}/100 · <b>Risk level:</b> {risk_level}</p>
  </div>

  <h3 style='margin:18px 0 8px;'>Severity Breakdown</h3>
  <ul>
    <li>Critical: {combined['critical']}</li>
    <li>High: {combined['high']}</li>
    <li>Medium: {combined['medium']}</li>
    <li>Low: {combined['low']}</li>
  </ul>

  <h3 style='margin:18px 0 8px;'>Top Critical Findings</h3>
  <ol>
    {''.join(f'<li>{f}</li>' for f in (critical_findings[:5] or ['No critical findings in sampled data']))}
  </ol>

  <h3 style='margin:18px 0 8px;'>Coverage</h3>
  <ul>
    <li>XSS findings analyzed: {len(xss_findings)}</li>
    <li>Open ports analyzed: {len(network_ports)}</li>
    <li>CVEs analyzed: {len(network_cves)}</li>
    <li>SSL issues analyzed: {len(ssl_issues)}</li>
    <li>Alerts analyzed: {len(alert_items)}</li>
  </ul>

  <p style='margin-top:24px;color:#334155;'>Prepared by {brand}. Contact: {contact_email or 'N/A'}</p>
</body></html>"""

    pdf_scan_data = {
        "target": domain,
        "client_name": brand,
        "consultant": "EdgeIQ Labs",
        "date": generated_at.split("T")[0],
        "scan_type": "White-label blended security assessment",
        "summary": summary,
        "findings": _build_pdf_findings(
            xss_findings, network_cves, network_ports, ssl_issues, alert_items
        ),
    }

    return {
        "ok": True,
        "brand": brand,
        "domain": domain,
        "contact_email": contact_email,
        "generated_at": generated_at,
        "security_score": score,
        "risk_level": risk_level,
        "summary": summary,
        "severity": combined,
        "critical_findings": critical_findings[:5],
        "coverage": {
            "xss_findings": len(xss_findings),
            "open_ports": len(network_ports),
            "cves": len(network_cves),
            "ssl_issues": len(ssl_issues),
            "alerts": len(alert_items),
        },
        "source_paths": {k: str(v) for k, v in paths.items()},
        "html_preview": html,
        "pdf_scan_data": pdf_scan_data,
    }


def _request_pdf_bytes(report_payload, session_id="", recipient_email="", delivery_token=""):
    req_payload = {
        "scan_data": report_payload["pdf_scan_data"],
        "session_id": session_id or "white-label-direct",
        "recipient_email": recipient_email or "",
        "delivery_token": delivery_token or "",
    }
    req = urllib.request.Request(
        REPORT_PDF_SERVICE_URL,
        data=json.dumps(req_payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=REPORT_PDF_TIMEOUT_SECONDS) as resp:
        content_type = resp.headers.get("Content-Type", "")
        status = getattr(resp, "status", 200)
        body = resp.read()
        if status != 200:
            raise RuntimeError(f"PDF service returned status {status}")
        if "application/pdf" not in content_type:
            # try parse JSON error for better diagnostics
            try:
                detail = json.loads(body.decode("utf-8", errors="ignore"))
            except Exception:
                detail = body.decode("utf-8", errors="ignore")[:500]
            raise RuntimeError(f"PDF service did not return PDF: {detail}")
        return body


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_pdf(self, pdf_bytes: bytes, filename: str):
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(pdf_bytes)))
        self.end_headers()
        self.wfile.write(pdf_bytes)

    def _send_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self.path in ("/", "/demo"):
            return self._send_html(DEMO_HTML)
        if self.path == "/health":
            return self._send(
                200,
                {
                    "ok": True,
                    "service": "white-label-report-builder",
                    "scan_data_dir": str(DEFAULT_SCAN_DIR),
                    "pdf_service_url": REPORT_PDF_SERVICE_URL,
                },
            )
        return self._send(404, {"error": "not_found"})

    def do_POST(self):
        if self.path not in (
            "/api/report/preview",
            "/api/report/generate",
            "/api/report/generate-pdf",
        ):
            return self._send(404, {"error": "not_found"})

        try:
            length = _safe_int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid_json"})

        brand = (data.get("brand") or "EdgeIQ Partner").strip()
        domain = (data.get("domain") or "example.com").strip()
        contact_email = (data.get("contact_email") or "").strip()
        scan_dir = Path(data.get("scan_data_dir") or DEFAULT_SCAN_DIR)

        if not domain:
            return self._send(400, {"error": "domain_required"})

        report = _build_report(brand, domain, contact_email, scan_dir)

        if self.path == "/api/report/generate-pdf":
            session_id = (data.get("session_id") or "white-label-direct").strip()
            recipient_email = (data.get("recipient_email") or contact_email).strip()
            delivery_token = (data.get("delivery_token") or "").strip()
            try:
                pdf_bytes = _request_pdf_bytes(
                    report,
                    session_id=session_id,
                    recipient_email=recipient_email,
                    delivery_token=delivery_token,
                )
                filename_domain = domain.replace("/", "_").replace(":", "_")
                return self._send_pdf(
                    pdf_bytes, f"edgeiq-white-label-{filename_domain}.pdf"
                )
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
                return self._send(502, {"error": "pdf_backend_failed", "detail": detail[:800]})
            except Exception as e:
                return self._send(502, {"error": "pdf_generation_failed", "detail": str(e)})

        return self._send(200, report)


if __name__ == "__main__":
    print(f"[white-label-report-builder] listening on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
