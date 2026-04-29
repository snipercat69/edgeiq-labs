# EdgeIQ SMB Security Dashboard

Single-pane dashboard for SMB owners with a **free score preview** and **paid dashboard unlock**.

## Free vs Paid

### Free teaser mode
Available without auth:
- `/` dashboard UI
- `/health`
- `/api/score`

The homepage always loads the free score + risk preview.

### Paid unlock
Protected endpoints:
- `/api/summary`
- `/api/alerts`
- `/api/recommendations`

If a request does not include valid paid auth, the API returns HTTP `402`:

```json
{
  "error": "paid_required",
  "message": "This panel is part of the paid SMB dashboard. Upgrade for full summary, alerts, and remediation guidance.",
  "upgrade_url": "https://edgeiqlabs.com/#pricing"
}
```

The frontend detects that response and shows locked panels with upgrade CTAs.

## Auth

Set a paid token with the `DASHBOARD_PRO_TOKEN` environment variable.

```bash
export DASHBOARD_PRO_TOKEN='your-secret-pro-token'
```

You can pass the token either way:

### Bearer token
```bash
curl -H "Authorization: Bearer your-secret-pro-token" \
  "http://localhost:8113/api/summary?domain=example.com"
```

### Query parameter
```bash
curl "http://localhost:8113/api/summary?domain=example.com&token=your-secret-pro-token"
```

The dashboard UI also includes an optional token input so paid customers can unlock the panels live in-browser.

## Run

```bash
cd apps/edgeiq-smb-security-dashboard
python3 scripts/server.py
```

Render-compatible port binding is enabled through `PORT`.

Server:
- local default: `http://localhost:8113`
- Render: `http://0.0.0.0:$PORT`

## Routes

### Dashboard
| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard HTML page with free teaser + paid unlock UI |
| HEAD | `/` | Lightweight health/load-balancer probe |
| GET | `/health` | Health check |
| HEAD | `/health` | Health check probe |

### API Endpoints
All endpoints accept an optional `?domain=<domain>` query param (defaults to `example.com`).

| Method | Path | Access | Description |
|--------|------|--------|-------------|
| GET | `/api/score` | Free | Aggregate score (0–100), risk level, and severity breakdown |
| GET | `/api/summary` | Paid | Aggregate security posture from all scan types |
| GET | `/api/alerts` | Paid | Active (unacknowledged) alerts for the domain |
| GET | `/api/recommendations` | Paid | Top remediation items sorted by severity |

## API Examples

```bash
# Health check
curl http://localhost:8113/health

# Free score preview (no token required)
curl "http://localhost:8113/api/score?domain=example.com"

# Paid summary without token -> 402
curl -i "http://localhost:8113/api/summary?domain=example.com"

# Paid summary with token -> 200
curl -H "Authorization: Bearer your-secret-pro-token" \
  "http://localhost:8113/api/summary?domain=example.com"
```

## Data Model

The dashboard aggregates from four scan types located in:

```text
apps/edgeiq-smb-security-dashboard/sample-data/
  ├── xss_<domain>.json       XSS scanner findings
  ├── network_<domain>.json   Open ports + CVE list
  ├── ssl_<domain>.json       SSL certificate + cipher issues
  └── alert_<domain>.json     Alerting system events
```

The **security score** is derived from the combined severity breakdown of all findings:
- `critical` → −40 pts per finding
- `high`     → −25 pts per finding
- `medium`   → −10 pts per finding
- `low`      → −3 pts per finding

Score mapping:
- `80–100` → low risk
- `60–79` → moderate risk
- `40–59` → high risk
- `0–39` → critical risk
