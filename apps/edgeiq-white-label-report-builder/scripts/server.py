#!/usr/bin/env python3
import io
import json
import os
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PORT = int(os.getenv("PORT", "8111"))
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

# Stripe
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")

# Auth
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# Mailgun (optional)
MAILGUN_API_KEY = os.getenv("MAILGUN_API_KEY", "")
MAILGUN_DOMAIN = os.getenv("MAILGUN_DOMAIN", "")

# Data paths (relative to the app root)
APP_ROOT = Path(__file__).parent.parent
DATA_DIR = APP_ROOT / "data"
ACCOUNTS_FILE = DATA_DIR / "accounts.json"
USERS_FILE = DATA_DIR / "users.json"
USAGES_FILE = DATA_DIR / "usages.json"

# Plan quotas (monthly)
PLAN_QUOTAS = {
    "solo": 10,
    "agency": 50,
    "pro": 150,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default


def _load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_json(path, data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _load_accounts():
    return _load_json(ACCOUNTS_FILE)


def _save_accounts(accounts):
    _save_json(ACCOUNTS_FILE, accounts)


def _load_users():
    return _load_json(USERS_FILE)


def _save_users(users):
    _save_json(USERS_FILE, users)


def _load_usages():
    return _load_json(USAGES_FILE)


def _save_usages(usages):
    _save_json(USAGES_FILE, usages)


def _current_month():
    now = datetime.now(timezone.utc)
    return f"{now.year}-{now.month:02d}"


def _init_default_admin():
    """Seed default admin user from ADMIN_PASSWORD env var if no users exist."""
    users = _load_users()
    if not users:
        # admin is always a solo plan for the admin account
        admin_hash = ADMIN_PASSWORD  # plain password comparison for MVP simplicity
        if admin_hash:
            users["admin"] = {
                "email": "admin@edgeiq.io",
                "password": admin_hash,
                "plan": "admin",
                "stripe_customer_id": "",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            _save_users(users)


def _verify_basic_auth():
    """After init, ensure default admin exists."""
    _init_default_admin()


def _monthly_usage(email: str) -> int:
    usages = _load_usages()
    month = _current_month()
    key = f"{email}:{month}"
    return usages.get(key, 0)


def _increment_usage(email: str):
    usages = _load_usages()
    month = _current_month()
    key = f"{email}:{month}"
    usages[key] = usages.get(key, 0) + 1
    _save_usages(usages)


def _plan_quota(plan: str) -> int:
    return PLAN_QUOTAS.get(plan.lower(), 0)


def _send_mailgun_email(to_email: str, subject: str, html: str):
    """Send email via Mailgun API. No-op if MAILGUN_API_KEY or MAILGUN_DOMAIN not set."""
    if not MAILGUN_API_KEY or not MAILGUN_DOMAIN:
        return
    import urllib.request
    data = urllib.parse.urlencode({
        "from": f"EdgeIQ Report Builder <noreply@{MAILGUN_DOMAIN}>",
        "to": [to_email],
        "subject": subject,
        "html": html,
    }).encode()
    req = urllib.request.Request(
        f"https://api.mailgun.net/v3/{MAILGUN_DOMAIN}/messages",
        data=data,
        headers={
            "Authorization": f"Basic {__import__('base64').b64encode(b'api:{MAILGUN_API_KEY}').decode()}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


def _parse_stripe_signature(body: bytes, sig_header: str) -> dict:
    """Parse Stripe webhook signature. Returns payload dict or raises."""
    import hmac, hashlib
    if not sig_header or not STRIPE_WEBHOOK_SECRET:
        raise ValueError("Missing Stripe signature or webhook secret")
    parts = dict(item.split("=", 1) for item in sig_header.split(",") if "=" in item)
    timestamp = parts.get("t", "")
    expected = hmac.new(
        STRIPE_WEBHOOK_SECRET.encode(),
        f"{timestamp}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    actual = parts.get("v1", "")
    if not hmac.compare_digest(expected, actual):
        raise ValueError("Stripe signature mismatch")
    import time
    if abs(time.time() - int(timestamp)) > 300:
        raise ValueError("Stripe signature timestamp too old")
    return json.loads(body.decode())


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def _authenticate(handler):
    """Read Bearer token from Authorization header and set handler._auth_user."""
    auth = handler.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    accounts = _load_accounts()
    for account in accounts.values():
        if account.get("session_token") == token:
            return account
    return None


def _require_auth(f):
    @wraps(f)
    def wrapper(handler, *args, **kwargs):
        account = _authenticate(handler)
        if not account:
            handler._send(401, {"error": "unauthorized"})
            return
        handler._auth_user = account
        return f(handler, *args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Report building (existing logic preserved)
# ---------------------------------------------------------------------------

def _severity_counter(items, severity_key="severity"):
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in items or []:
        sev = str(item.get(severity_key, "")).lower().strip()
        if sev in c:
            c[sev] += 1
    return c


def _score_from_counts(counts):
    penalty = (
        counts.get("critical", 0) * 14
        + counts.get("high", 0) * 7
        + counts.get("medium", 0) * 3
        + counts.get("low", 0) * 1
    )
    return max(0, min(100, 100 - penalty))


def _resolve_scan_paths(domain: str, scan_dir: Path):
    d = domain.strip().lower().replace("https://", "").replace("http://", "")
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
        findings.append({
            "name": f.get("vulnerability", "XSS Finding"),
            "severity": _sev_title(sev),
            "cvss": _default_cvss_for_sev(sev),
            "description": f.get("description", ""),
            "remediation": "Apply output encoding and strict input validation; add WAF/XSS protections.",
        })
    for c in network_cves:
        sev = c.get("severity", "high")
        findings.append({
            "name": c.get("cve_id", "CVE Finding"),
            "severity": _sev_title(sev),
            "cvss": c.get("cvss", _default_cvss_for_sev(sev)),
            "description": c.get("description", ""),
            "remediation": c.get("remediation", "Patch affected service to fixed version."),
        })
    for p in network_ports:
        sev = p.get("severity", "low")
        if str(sev).lower() in ("info", "low"):
            continue
        findings.append({
            "name": f"Exposed Port {p.get('port', '?')} ({p.get('service', 'service')})",
            "severity": _sev_title(sev),
            "cvss": _default_cvss_for_sev(sev),
            "description": p.get("risk", "Internet-exposed service detected."),
            "remediation": "Restrict exposure via firewall/VPN and harden service config.",
        })
    for i in ssl_issues:
        sev = i.get("severity", "medium")
        findings.append({
            "name": i.get("title", "SSL Issue"),
            "severity": _sev_title(sev),
            "cvss": _default_cvss_for_sev(sev),
            "description": i.get("description", ""),
            "remediation": i.get("remediation", "Update TLS/certificate configuration."),
        })
    for a in alert_items:
        sev = a.get("severity", "medium")
        findings.append({
            "name": a.get("title", "Alert"),
            "severity": _sev_title(sev),
            "cvss": _default_cvss_for_sev(sev),
            "description": a.get("description", ""),
            "remediation": "Investigate trigger source and resolve root cause.",
        })
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda x: sev_rank.get(x.get("severity", "Info"), 9))
    return findings[:30]


def _build_report(brand, domain, contact_email, scan_dir):
    paths = _resolve_scan_paths(domain, scan_dir)
    xss = _load_json(paths["xss"])
    network = _load_json(paths["network"])
    ssl = _load_json(paths["ssl"])
    alert = _load_json(paths["alert"])

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
            try:
                detail = json.loads(body.decode("utf-8", errors="ignore"))
            except Exception:
                detail = body.decode("utf-8", errors="ignore")[:500]
            raise RuntimeError(f"PDF service did not return PDF: {detail}")
        return body


# ---------------------------------------------------------------------------
# Request Handler
# ---------------------------------------------------------------------------

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

    def _read_body(self):
        try:
            length = _safe_int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
            return data
        except Exception:
            return None

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    # -------------------------------------------------------------------------
    # Public GET routes
    # -------------------------------------------------------------------------

    def do_HEAD(self):
        if self.path in ("/", "/demo", "/health"):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        # Demo UI
        if self.path in ("/", "/demo"):
            return self._send_html(DEMO_HTML)

        # Health check
        if self.path == "/health":
            return self._send(200, {
                "ok": True,
                "service": "white-label-report-builder",
                "scan_data_dir": str(DEFAULT_SCAN_DIR),
                "pdf_service_url": REPORT_PDF_SERVICE_URL,
            })

        # Onboarding token lookup
        if self.path.startswith("/api/onboarding/"):
            token = self.path[len("/api/onboarding/"):].strip()
            if not token:
                return self._send(400, {"error": "missing_token"})
            accounts = _load_accounts()
            for account in accounts.values():
                if account.get("account_token") == token:
                    return self._send(200, {
                        "ok": True,
                        "email": account.get("email", ""),
                        "plan": account.get("plan", ""),
                        "status": account.get("status", "pending"),
                        "created_at": account.get("created_at", ""),
                    })
            return self._send(404, {"error": "token_not_found"})

        # Account info (authenticated)
        if self.path == "/api/account":
            account = _authenticate(self)
            if not account:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {
                "ok": True,
                "email": account.get("email", ""),
                "plan": account.get("plan", ""),
                "status": account.get("status", ""),
                "created_at": account.get("created_at", ""),
                "stripe_customer_id": account.get("stripe_customer_id", ""),
            })

        return self._send(404, {"error": "not_found"})

    # -------------------------------------------------------------------------
    # Public POST routes
    # -------------------------------------------------------------------------

    def do_POST(self):
        # Initialize default admin on first request if needed
        _init_default_admin()

        # Stripe webhook
        if self.path == "/api/webhooks/stripe":
            return self._handle_stripe_webhook()

        # Login
        if self.path == "/api/auth/login":
            return self._handle_login()

        # Report generation (authenticated)
        if self.path in (
            "/api/report/generate",
            "/api/report/generate-pdf",
            "/api/report/preview",
        ):
            return self._handle_report_generate()

        return self._send(404, {"error": "not_found"})

    # -------------------------------------------------------------------------
    # Stripe webhook
    # -------------------------------------------------------------------------

    def _handle_stripe_webhook(self):
        if not STRIPE_WEBHOOK_SECRET:
            # Stripe not configured — log and return 200 to avoid retries
            print("[stripe] WEBHOOK_SECRET not set, skipping validation")
            return self._send(200, {"ok": True, "note": "stripe_not_configured"})

        sig = self.headers.get("Stripe-Signature", "")
        length = _safe_int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) or b"{}"

        try:
            event = _parse_stripe_signature(body, sig)
        except Exception as e:
            print(f"[stripe] signature validation failed: {e}")
            return self._send(400, {"error": "invalid_signature", "detail": str(e)})

        if event.get("type") != "checkout.session.completed":
            # Acknowledge other event types without processing
            return self._send(200, {"ok": True, "type": event.get("type", "unknown")})

        session = event.get("data", {}).get("object", {})
        customer_email = session.get("customer_email", "") or session.get("customer_details", {}).get("email", "")
        plan_tier = (session.get("metadata") or {}).get("package", "solo")
        stripe_customer_id = session.get("customer", "") or session.get("id", "")

        if not customer_email:
            print("[stripe] no customer_email in session, skipping")
            return self._send(200, {"ok": True, "note": "no_email"})

        # Generate onboarding token
        account_token = secrets.token_hex(16)
        now = datetime.now(timezone.utc).isoformat()

        # Load existing accounts
        accounts = _load_accounts()

        # Check if account already exists for this email/customer
        existing = None
        for acc in accounts.values():
            if acc.get("email") == customer_email:
                existing = acc
                break

        if existing:
            existing["account_token"] = account_token
            existing["status"] = "pending"
            existing["plan"] = plan_tier
            existing["stripe_customer_id"] = stripe_customer_id
            existing["updated_at"] = now
        else:
            accounts[account_token] = {
                "account_token": account_token,
                "email": customer_email,
                "plan": plan_tier,
                "stripe_customer_id": stripe_customer_id,
                "status": "pending",
                "created_at": now,
                "updated_at": now,
            }

        _save_accounts(accounts)

        # Send onboarding email via Mailgun if configured
        onboarding_url = f"https://edgeiq.io/onboarding/{account_token}"
        html_body = f"""
        <html><body style='font-family:Inter,Arial,sans-serif;background:#f8fafc;color:#0f172a;padding:24px;'>
          <h2>Welcome to EdgeIQ Report Builder</h2>
          <p>Your account is ready. Choose your plan: <strong>{plan_tier}</strong>.</p>
          <p>Click below to set up your account and start generating branded security reports.</p>
          <a href='{onboarding_url}' style='display:inline-block;padding:12px 24px;background:#3dd9ff;color:#071018;border-radius:8px;font-weight:700;text-decoration:none;'>Complete Setup</a>
          <p style='margin-top:20px;color:#64748b;'>Token: {account_token}</p>
        </body></html>
        """
        try:
            _send_mailgun_email(
                customer_email,
                f"EdgeIQ Report Builder — Your account is ready ({plan_tier} plan)",
                html_body,
            )
            print(f"[stripe] onboarding email sent to {customer_email}")
        except Exception as e:
            print(f"[stripe] failed to send onboarding email: {e}")

        print(f"[stripe] account created/updated for {customer_email} ({plan_tier})")
        return self._send(200, {"ok": True, "account_token": account_token})

    # -------------------------------------------------------------------------
    # Login
    # -------------------------------------------------------------------------

    def _handle_login(self):
        data = self._read_body()
        if not data:
            return self._send(400, {"error": "invalid_json"})
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "").strip()
        if not email or not password:
            return self._send(400, {"error": "email_and_password_required"})

        users = _load_users()
        account = None

        # Check users.json first
        for u_email, u_data in users.items():
            if u_email == email and u_data.get("password") == password:
                account = u_data.copy()
                account["email"] = u_email
                break

        # Also check accounts.json for Stripe-created accounts (password = account_token)
        if not account:
            accounts = _load_accounts()
            for acc in accounts.values():
                if acc.get("email", "").lower() == email and acc.get("account_token") == password:
                    account = acc.copy()
                    break

        if not account:
            return self._send(401, {"error": "invalid_credentials"})

        # Generate session token
        session_token = secrets.token_hex(24)
        account["session_token"] = session_token
        account["status"] = "active"

        # Update accounts
        accounts = _load_accounts()
        for key, acc in accounts.items():
            if acc.get("email", "").lower() == email:
                accounts[key]["session_token"] = session_token
                accounts[key]["status"] = "active"
                break
        _save_accounts(accounts)

        return self._send(200, {
            "ok": True,
            "session_token": session_token,
            "email": account.get("email", ""),
            "plan": account.get("plan", "solo"),
            "status": account.get("status", "active"),
        })

    # -------------------------------------------------------------------------
    # Report generation (authenticated, quota-enforced)
    # -------------------------------------------------------------------------

    def _handle_report_generate(self):
        account = _authenticate(self)
        if not account:
            return self._send(401, {"error": "unauthorized"})

        email = account.get("email", "")
        plan = (account.get("plan") or "solo").lower()
        quota = _plan_quota(plan)
        usage = _monthly_usage(email)

        if quota > 0 and usage >= quota:
            return self._send(429, {
                "error": "quota_exceeded",
                "plan": plan,
                "quota": quota,
                "used": usage,
                "reset_at": f"{_current_month()}-01",
            })

        data = self._read_body()
        if not data:
            return self._send(400, {"error": "invalid_json"})

        brand = (data.get("brand") or "EdgeIQ Partner").strip()
        domain = (data.get("domain") or "example.com").strip()
        contact_email = (data.get("contact_email") or email).strip()
        scan_dir = Path(data.get("scan_data_dir") or DEFAULT_SCAN_DIR)

        if not domain:
            return self._send(400, {"error": "domain_required"})

        # Build report
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
                # Increment usage after successful PDF generation
                _increment_usage(email)
                return self._send_pdf(
                    pdf_bytes, f"edgeiq-white-label-{filename_domain}.pdf"
                )
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
                return self._send(502, {"error": "pdf_backend_failed", "detail": detail[:800]})
            except Exception as e:
                return self._send(502, {"error": "pdf_generation_failed", "detail": str(e)})

        # JSON report — increment usage
        _increment_usage(email)

        report["quota"] = {"used": usage + 1, "limit": quota, "plan": plan}
        return self._send(200, report)


# ---------------------------------------------------------------------------
# Bootstrap HTML (moved above main block for clarity)
# ---------------------------------------------------------------------------

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


if __name__ == "__main__":
    import urllib.parse
    print(f"[white-label-report-builder] listening on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()