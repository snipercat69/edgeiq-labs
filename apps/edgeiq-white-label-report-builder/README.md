# EdgeIQ White-Label Security Report Builder (MVP Scaffold)

Generate client-branded security reports for MSPs/consultants.

## Run
```bash
cd apps/edgeiq-white-label-report-builder
python3 scripts/server.py
```
Server: `http://localhost:8111`
Demo UI: `http://localhost:8111/demo`

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Server port (default: `8111`) |
| `REPORT_SCAN_DATA_DIR` | No | Path to scan JSON files (default: EdgeIQ scanner sample data dir) |
| `REPORT_PDF_SERVICE_URL` | No | PDF generation backend URL (default: EdgeIQ PDF service) |
| `REPORT_PDF_TIMEOUT_SECONDS` | No | PDF service timeout (default: 90) |
| `STRIPE_WEBHOOK_SECRET` | **Yes** | Stripe webhook signing secret (`wh_live_...`) from `~/.config/openclaw-secrets/stripe-webhook-secret.env` |
| `STRIPE_SECRET_KEY` | Recommended | Stripe secret key for payment intents (default: reads from `~/.config/openclaw-secrets/edgeiq-stripe-live.env`) |
| `ADMIN_PASSWORD` | Recommended | Password for the default admin login (`admin@edgeiq.io`) |
| `MAILGUN_API_KEY` | No | Mailgun API key — onboarding emails sent only when set |
| `MAILGUN_DOMAIN` | No | Mailgun domain — required for email sending |

### Loading secrets from files (recommended)
```bash
export STRIPE_WEBHOOK_SECRET=$(cat ~/.config/openclaw-secrets/stripe-webhook-secret.env | grep STRIPE_WEBHOOK_SECRET | cut -d= -f2)
export ADMIN_PASSWORD="your-strong-password"
python3 scripts/server.py
```

---

## API Endpoints

### Health
```
GET /health
```
Returns service status and configuration.

---

### Stripe Webhook
```
POST /api/webhooks/stripe
Header: Stripe-Signature: t=...,v1=...
```
Validates Stripe webhook signature and handles `checkout.session.completed`:

1. Extracts `customer_email`, `package` (plan tier from metadata), `stripe_customer_id`
2. Generates a 32-char `account_token` via `secrets.token_hex(16)`
3. Stores account in `data/accounts.json`
4. Sends onboarding email via Mailgun (if `MAILGUN_API_KEY` + `MAILGUN_DOMAIN` configured)
5. Returns `200` to acknowledge to Stripe

**Response:** `{"ok": true, "account_token": "<hex>"}`

---

### Onboarding Token Lookup
```
GET /api/onboarding/<token>
```
Look up a Stripe-created account by its onboarding token.

**Response (200):**
```json
{"ok": true, "email": "user@example.com", "plan": "agency", "status": "pending", "created_at": "..."}
```
**Response (404):** `{"error": "token_not_found"}`

---

### Login
```
POST /api/auth/login
Content-Type: application/json

{"email": "user@example.com", "password": "..."}
```

Authenticates against `data/users.json` (default admin from `ADMIN_PASSWORD`) or Stripe-created accounts in `data/accounts.json`.

**Response (200):**
```json
{
  "ok": true,
  "session_token": "<hex>",
  "email": "user@example.com",
  "plan": "agency",
  "status": "active"
}
```
**Response (401):** `{"error": "invalid_credentials"}`

---

### Account Info (Authenticated)
```
GET /api/account
Authorization: Bearer <session_token>
```
Returns the authenticated account's details.

**Response (200):**
```json
{
  "ok": true,
  "email": "user@example.com",
  "plan": "agency",
  "status": "active",
  "created_at": "...",
  "stripe_customer_id": "cus_..."
}
```
**Response (401):** `{"error": "unauthorized"}`

---

### Report Generation (Authenticated + Quota-Enforced)

```
POST /api/report/preview
POST /api/report/generate
POST /api/report/generate-pdf
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "brand": "Acme Security",
  "domain": "example.com",
  "contact_email": "security@acme.com"
}
```

**Plan quotas (monthly):**
| Plan | Reports/Month |
|---|---|
| `solo` | 10 |
| `agency` | 50 |
| `pro` | 150 |

Usage is tracked in `data/usages.json` keyed by `email:YYYY-MM`. If quota is exceeded, returns `429`:
```json
{"error": "quota_exceeded", "plan": "solo", "quota": 10, "used": 10, "reset_at": "2026-04-01"}
```

On success, `/api/report/generate` returns the full report JSON. `/api/report/generate-pdf` streams a PDF download.

---

## Data Files

| File | Purpose |
|---|---|
| `data/accounts.json` | Stripe-created accounts (onboarding tokens, email, plan, stripe_customer_id) |
| `data/users.json` | Admin/user credentials seeded from `ADMIN_PASSWORD` |
| `data/usages.json` | Monthly usage counters per email (`email:YYYY-MM` -> count) |

---

## Stripe Integration

Stripe checkout sessions should include metadata:
```json
{
  "metadata": {
    "package": "agency"
  }
}
```

Supported plan tiers: `solo`, `agency`, `pro`.

Webhook endpoint: `POST /api/webhooks/stripe`

---

## Example: Simulate Checkout Completed

```bash
# Build a mock checkout.session.completed event
PAYLOAD='{
  "id": "evt_test_123",
  "type": "checkout.session.completed",
  "data": {
    "object": {
      "customer_email": "test@example.com",
      "customer": "cus_test123",
      "metadata": {"package": "agency"}
    }
  }
}'

# Get current timestamp for signature
TS=$(date +%s)

# Sign using Stripe webhook secret
SECRET="wh_live_..."
SIGNATURE=$(echo -n "${TS}."${PAYLOAD} | openssl dgst -sha256 -hmac "$SECRET" | sed 's/.* //')

# Send to webhook
curl -X POST http://localhost:8111/api/webhooks/stripe \
  -H "Content-Type: application/json" \
  -H "Stripe-Signature: t=${TS},v1=${SIGNATURE}" \
  -d "$PAYLOAD"
```

After running, check `data/accounts.json` for the new entry and test the onboarding token.

---

## Example cURL Commands

### Login
```bash
curl -X POST http://localhost:8111/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@edgeiq.io","password":"your-admin-password"}'
```

### Look up onboarding token
```bash
curl http://localhost:8111/api/onboarding/<your_token>
```

### Generate report (authenticated)
```bash
curl -X POST http://localhost:8111/api/report/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <session_token>" \
  -d '{"brand":"Acme Security","domain":"example.com","contact_email":"security@acme.com"}'
```

### Download PDF report
```bash
curl -X POST http://localhost:8111/api/report/generate-pdf \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <session_token>" \
  -d '{"brand":"Acme Security","domain":"example.com"}' \
  --output acme-security-report.pdf
```

### Check account info
```bash
curl http://localhost:8111/api/account \
  -H "Authorization: Bearer <session_token>"
```

---

## Next
- Add password hashing (bcrypt) for user credentials
- Add plan upgrade/downgrade webhook handling
- Add session refresh token rotation
- Add per-client project management
- Add report history and export