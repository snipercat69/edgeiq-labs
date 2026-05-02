# EdgeIQ White-Label Security Report Builder (MVP Scaffold)

Generate client-branded security reports for MSPs/consultants.

## MVP goals
- Input: domain + brand name + logo URL + contact
- Output: branded HTML report (PDF pipeline can be wired next)
- API route for automation and dashboard integration

## Run
```bash
cd apps/edgeiq-white-label-report-builder
python3 scripts/server.py
```
Server: `http://localhost:8111`
Demo UI: `http://localhost:8111/demo`

## Routes
- `GET /health`
- `POST /api/report/preview` -> builds a branded report payload from scan JSON + returns HTML preview
- `POST /api/report/generate` -> returns structured JSON + HTML preview + `pdf_scan_data`
- `POST /api/report/generate-pdf` -> one-shot PDF stream via `edgeiq-report-worker` PDF backend

### Example JSON generation
```bash
curl -X POST http://localhost:8111/api/report/generate \
  -H "Content-Type: application/json" \
  -d '{
    "brand":"Acme Security",
    "domain":"example.com",
    "contact_email":"security@acme.com"
  }'
```

### Example direct PDF generation
```bash
curl -X POST http://localhost:8111/api/report/generate-pdf \
  -H "Content-Type: application/json" \
  -d '{
    "brand":"Acme Security",
    "domain":"example.com",
    "contact_email":"security@acme.com"
  }' \
  --output acme-security-report.pdf
```

## Next
- Wire existing EdgeIQ scanner outputs into findings section
- Add PDF render hook to `edgeiq-report-worker`
- Add agency auth + client/project saves
