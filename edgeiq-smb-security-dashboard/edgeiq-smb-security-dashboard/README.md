# EdgeIQ SMB Security Dashboard

Single-pane dashboard for non-technical SMB owners — backed by real scan data.

## Run
```bash
cd apps/edgeiq-smb-security-dashboard
python3 scripts/server.py
```
Server: `http://localhost:8113`

## Routes

### Dashboard
| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard HTML page |
| GET | `/health` | Health check |

### API Endpoints
All endpoints accept an optional `?domain=<domain>` query param (defaults to `example.com`).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/summary` | Aggregate security posture from all scan types |
| GET | `/api/alerts` | Active (unacknowledged) alerts for the domain |
| GET | `/api/score` | Aggregate score (0–100), risk level, and severity breakdown |
| GET | `/api/recommendations` | Top remediation items sorted by severity |

## API Examples

```bash
# Health check
curl http://localhost:8113/health

# Security posture summary
curl "http://localhost:8113/api/summary?domain=example.com"

# Active alerts
curl "http://localhost:8113/api/alerts?domain=example.com"

# Aggregate security score
curl "http://localhost:8113/api/score?domain=example.com"

# Prioritized remediation items
curl "http://localhost:8113/api/recommendations?domain=example.com"
```

## Data Model

The dashboard aggregates from four scan types located in:
```
apps/edgeiq-security-report-generator/sample-data/
  ├── xss_<domain>.json      XSS scanner findings
  ├── network_<domain>.json   Open ports + CVE list
  ├── ssl_<domain>.json       SSL certificate + cipher issues
  └── alert_<domain>.json     Alerting system events
```

The **security score** is derived from the combined severity breakdown of all findings:
- `critical` → −40 pts per finding
- `high`     → −25 pts per finding
- `medium`   → −10 pts per finding
- `low`      → −3  pts per finding

Score 80–100 = low risk, 60–79 = moderate, 40–59 = high, 0–39 = critical.

## MVP Goals
- ✅ Show SSL status, uptime, domain expiry, breach flags, and summary risk score
- ✅ Aggregate real scan data (XSS, network, SSL, alerts) via `/api/*`
- ✅ Compute severity breakdown from actual JSON scan files
- ✅ Prioritized remediation recommendations sorted by severity
- ✅ Simple daily-updated JSON data model; minimal auth can be added next