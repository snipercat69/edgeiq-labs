# EdgeIQ Instant Security Audit Widget (MVP Scaffold)

Embeddable widget for partner sites to capture domains, attribute referrals, and return a basic security score.

## MVP goals
- One-line embed script for partner websites
- Basic score endpoint + CTA back to EdgeIQ
- Partner ID for referral attribution
- Persistent JSONL event tracking for partner analytics

## Run
```bash
cd apps/edgeiq-instant-security-audit-widget
python3 scripts/server.py
```
Server: `http://localhost:8112`

## Data storage
Tracked events are appended to `data/events.jsonl` automatically. The server creates the `data/` directory on first run.

Event schema:
- `ts_utc`
- `event_type`
- `partner`
- `domain` (optional)
- `score` (optional)
- `cta_url` (optional)
- `request_ip` (optional)
- `ua` (optional)

## Routes
- `GET /widget.js?partner=<id>`
- `GET /api/score?domain=<domain>&partner=<id>`
- `POST /api/track`
- `GET /api/partners/<partner>/stats`
- `GET /api/partners/<partner>/events?limit=100`
- `GET /health`

## Attribution behavior
The widget now emits partner tracking events for:
- `widget_load`
- `score_check`
- `score_result`
- `cta_click`

CTA links include both the partner referral (`ref`) and the checked `domain`.

## curl examples
Health check:
```bash
curl http://localhost:8112/health
```

Track a partner event:
```bash
curl -X POST http://localhost:8112/api/track \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"widget_load","partner":"demo-partner"}'
```

Get a score:
```bash
curl 'http://localhost:8112/api/score?domain=example.com&partner=demo-partner'
```

Get partner stats:
```bash
curl http://localhost:8112/api/partners/demo-partner/stats
```

Get recent partner events:
```bash
curl 'http://localhost:8112/api/partners/demo-partner/events?limit=5'
```

## Embed example
```html
<script src="http://localhost:8112/widget.js?partner=demo-partner"></script>
```
