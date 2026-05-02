#!/usr/bin/env python3
import json
import os
import random
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

PORT = int(os.getenv("PORT", "8112"))
CTA_URL = os.getenv("WIDGET_CTA_URL", "https://edgeiqlabs.com/#pricing")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(BASE_DIR, "..", "data"))
EVENTS_PATH = os.path.join(DATA_DIR, "events.jsonl")
EVENT_LOCK = threading.Lock()
ALLOWED_EVENT_TYPES = {"widget_load", "score_check", "score_result", "cta_click"}


def now_utc_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def normalize_str(value, default=""):
    if value is None:
        return default
    return str(value).strip()


def clean_optional(value):
    value = normalize_str(value)
    return value or None


def clean_score(value):
    if value in (None, ""):
        return None
    try:
        if isinstance(value, str) and value.strip() == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def client_ip(handler):
    forwarded = handler.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if handler.client_address:
        return handler.client_address[0]
    return None


def append_query(url, params):
    parsed = urlparse(url)
    merged = parse_qs(parsed.query)
    for key, value in params.items():
        if value is not None:
            merged[key] = [str(value)]
    query = urlencode(merged, doseq=True)
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    base = parsed._replace(query="", fragment="").geturl()
    if fragment and "#" in base:
        base = base.split("#", 1)[0]
    return f"{base}?{query}{fragment}" if query else f"{base}{fragment}"


def normalize_event(payload, handler=None):
    event_type = normalize_str(payload.get("event_type"))
    partner = normalize_str(payload.get("partner") or "direct") or "direct"
    event = {
        "ts_utc": now_utc_iso(),
        "event_type": event_type,
        "partner": partner,
        "domain": clean_optional(payload.get("domain")),
        "score": clean_score(payload.get("score")),
        "cta_url": clean_optional(payload.get("cta_url")),
        "request_ip": clean_optional(payload.get("request_ip")),
        "ua": clean_optional(payload.get("ua")),
    }
    if handler is not None:
        event["request_ip"] = event["request_ip"] or client_ip(handler)
        event["ua"] = event["ua"] or clean_optional(handler.headers.get("User-Agent"))
    return event


def log_event(payload, handler=None):
    event = normalize_event(payload, handler)
    if not event["event_type"]:
        raise ValueError("event_type_required")
    ensure_data_dir()
    with EVENT_LOCK:
        with open(EVENTS_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, separators=(",", ":")) + "\n")
    return event


def read_events(partner=None):
    if not os.path.exists(EVENTS_PATH):
        return []
    rows = []
    with open(EVENTS_PATH, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if partner and event.get("partner") != partner:
                continue
            rows.append(event)
    return rows


def partner_stats(partner):
    events = read_events(partner=partner)
    score_result_domains = {
        (event.get("domain") or "").strip().lower()
        for event in events
        if event.get("event_type") == "score_result" and event.get("domain")
    }
    return {
        "partner": partner,
        "totals": {
            "widget_loads": sum(1 for event in events if event.get("event_type") == "widget_load"),
            "score_checks": sum(1 for event in events if event.get("event_type") == "score_check"),
            "score_results": sum(1 for event in events if event.get("event_type") == "score_result"),
            "cta_clicks": sum(1 for event in events if event.get("event_type") == "cta_click"),
            "unique_domains_checked": len(score_result_domains),
        },
    }


def build_widget_js(handler):
    base_url = f"http://{handler.headers.get('Host', f'localhost:{PORT}') }"
    return f"""
(function(){{
  const script = document.currentScript;
  const scriptUrl = new URL(script.src, window.location.href);
  const apiBase = scriptUrl.origin || {json.dumps(base_url)};
  const partner = scriptUrl.searchParams.get('partner') || 'direct';

  function postJson(path, payload, keepalive) {{
    return fetch(apiBase + path, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload),
      keepalive: !!keepalive,
      credentials: 'omit'
    }}).catch(function(){{}});
  }}

  function trackEvent(payload, keepalive) {{
    payload = Object.assign({{ partner: partner }}, payload || {{}});
    if (navigator.sendBeacon && keepalive) {{
      try {{
        const blob = new Blob([JSON.stringify(payload)], {{ type: 'application/json' }});
        navigator.sendBeacon(apiBase + '/api/track', blob);
        return Promise.resolve();
      }} catch (err) {{}}
    }}
    return postJson('/api/track', payload, keepalive);
  }}

  const box = document.createElement('div');
  box.style = 'border:1px solid #233142;padding:12px;border-radius:10px;font-family:Inter,Arial,sans-serif;background:#121923;color:#e8eef7;max-width:420px';
  box.innerHTML = '<strong>Free Security Snapshot</strong><div style="margin-top:8px"><input id="edgeiq-domain" placeholder="yourdomain.com" style="width:65%;padding:8px;border-radius:8px;border:1px solid #233142"/><button id="edgeiq-run" style="margin-left:8px;padding:8px 10px;border-radius:8px;border:0;background:#3dd9ff;color:#071018;font-weight:700">Check</button></div><div id="edgeiq-result" style="margin-top:8px;color:#9fb0c7"></div>';
  script.parentNode.insertBefore(box, script);

  trackEvent({{ event_type: 'widget_load' }}, true);

  box.querySelector('#edgeiq-run').onclick = async function() {{
    const d = box.querySelector('#edgeiq-domain').value.trim();
    if (!d) {{
      box.querySelector('#edgeiq-result').textContent = 'Enter a domain first';
      return;
    }}

    trackEvent({{ event_type: 'score_check', domain: d }}, true);
    const r = await fetch(apiBase + `/api/score?domain=${{encodeURIComponent(d)}}&partner=${{encodeURIComponent(partner)}}`);
    const j = await r.json();
    if (!r.ok || !j.ok) {{
      box.querySelector('#edgeiq-result').textContent = (j && j.error) ? j.error : 'Unable to score domain';
      return;
    }}

    await trackEvent({{ event_type: 'score_result', domain: j.domain, score: j.score, cta_url: j.cta_url }}, true);
    box.querySelector('#edgeiq-result').innerHTML = `Score: <b>${{j.score}}</b>/100 · <a href="${{j.cta_url}}" target="_blank" rel="noopener">Get full report</a>`;
    const link = box.querySelector('#edgeiq-result a');
    if (link) {{
      link.addEventListener('click', function(ev) {{
        ev.preventDefault();
        trackEvent({{ event_type: 'cta_click', domain: j.domain, score: j.score, cta_url: j.cta_url }}, true).finally(function() {{
          window.open(j.cta_url, '_blank', 'noopener');
        }});
      }});
    }}
  }};
}})();
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _set_headers(self, code, content_type, content_length):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(content_length))
        self.end_headers()

    def _json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self._set_headers(code, "application/json", len(body))
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._set_headers(204, "text/plain", 0)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)

        if u.path == "/health":
            return self._json(200, {"ok": True, "service": "instant-audit-widget"})

        if u.path == "/widget.js":
            body = build_widget_js(self).encode("utf-8")
            self._set_headers(200, "application/javascript", len(body))
            self.wfile.write(body)
            return

        if u.path == "/api/score":
            domain = normalize_str(q.get("domain", [""])[0]).lower()
            partner = normalize_str(q.get("partner", ["direct"])[0]) or "direct"
            if not domain:
                return self._json(400, {"error": "domain_required"})
            score = max(35, min(92, 70 + random.randint(-20, 20)))
            cta_url = append_query(CTA_URL, {"ref": partner, "domain": domain})
            return self._json(200, {
                "ok": True,
                "domain": domain,
                "partner": partner,
                "score": score,
                "cta_url": cta_url,
            })

        if u.path.startswith("/api/partners/"):
            parts = [part for part in u.path.split("/") if part]
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "partners":
                partner = parts[2]
                action = parts[3]
                if action == "stats":
                    return self._json(200, partner_stats(partner))
                if action == "events":
                    raw_limit = q.get("limit", ["100"])[0]
                    try:
                        limit = max(1, min(1000, int(raw_limit)))
                    except ValueError:
                        return self._json(400, {"error": "invalid_limit"})
                    events = read_events(partner=partner)
                    events.sort(key=lambda item: item.get("ts_utc", ""), reverse=True)
                    return self._json(200, {"partner": partner, "events": events[:limit]})

        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/api/track":
            return self._json(404, {"error": "not_found"})

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"error": "invalid_content_length"})

        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"error": "invalid_json"})

        if not isinstance(payload, dict):
            return self._json(400, {"error": "json_object_required"})

        try:
            event = log_event(payload, self)
        except ValueError as exc:
            return self._json(400, {"error": str(exc)})

        return self._json(200, {"ok": True, "event": event})


if __name__ == '__main__':
    ensure_data_dir()
    print(f"[instant-audit-widget] listening on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
