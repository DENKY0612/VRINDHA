# Vrin_TI API

Base URL is `http://127.0.0.1:8010`. Every HTTP and WebSocket operation requires
`VRINDHA_TI_API_KEY`. The service deliberately disables unauthenticated OpenAPI
and docs routes.

```bash
export TI=http://127.0.0.1:8010
export KEY='<service key>'
curl -H "X-Vrindha-Service-Token: $KEY" "$TI/threat-intel/health"
```

## Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/health/live` | authenticated process liveness |
| GET | `/threat-intel/health` | SOC, bus, feed and queue health |
| GET | `/threat-intel/status` | health plus metrics/feed state |
| POST | `/threat-intel/lookup` | normalized IOC lookup |
| GET | `/threat-intel/indicators/{indicator}` | path lookup (`POST` preferred for URLs) |
| POST | `/threat-intel/indicators` | ingest/update a validated IOC |
| POST | `/threat-intel/enrich` | local enrichment; external is opt-in |
| POST | `/threat-intel/sighting` | create SOC observation and correlate |
| GET | `/threat-intel/feeds` | feed status |
| POST | `/threat-intel/feeds/{feed}/sync` | bounded manual feed sync |
| GET | `/threat-intel/actors|campaigns|malware` | STIX entities |
| GET | `/threat-intel/vulnerabilities?kev_only=true` | CVE/KEV records |
| GET | `/threat-intel/mitre/{technique}` | ATT&CK lookup |
| GET | `/threat-intel/correlations|sightings|reports` | history |
| POST | `/threat-intel/reports/{indicator_id}` | evidence-backed report |
| GET | `/threat-intel/graph/{ref}?depth=3` | bounded graph traversal |
| POST | `/threat-intel/stix/import` | STIX 2.1 bundle/object |
| GET | `/threat-intel/stix/export/{indicator_id}` | internal → STIX indicator |
| POST | `/intelligence/events` | SOC event ingress |
| GET | `/threat-intel/integrations` | optional connector/tool states |
| POST | `/threat-intel/yara/scan` | safe allowed-root local file match |
| GET | `/threat-intel/sigma/rules` | validated Sigma metadata/ATT&CK mappings |
| GET | `/threat-intel/doctor` | dependency diagnosis |
| GET | `/metrics` | Prometheus text |
| WS | `/ws/threat-intelligence` | authenticated event stream/heartbeat |

## Examples

Lookup:

```bash
curl -sS -H "X-Vrindha-Service-Token: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"indicator":"8.8.8.8"}' "$TI/threat-intel/lookup"
```

Ingest:

```bash
curl -sS -H "X-Vrindha-Service-Token: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"indicator_type":"domain","indicator_value":"Example.COM.",
       "source":"analyst-import","source_reliability":0.8,"confidence":0.85,
       "tags":["phishing"],"ttl":86400}' \
  "$TI/threat-intel/indicators"
```

SOC event:

```bash
curl -sS -H "X-Vrindha-Service-Token: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"ioc_observation","timestamp":"2026-08-14T08:03:00Z",
       "source":"soc","indicator":{"type":"domain","value":"example.com"},
       "asset":{"id":"host-001","ip":"10.0.0.25","criticality":0.9},
       "context":{"kind":"dns connection"},"severity":"high","confidence":0.9}' \
  "$TI/intelligence/events"
```

## Errors and limits

- `401`: missing/wrong service token.
- `409`: duplicate event ID or timestamp outside replay window.
- `413`: request exceeds configured body limit.
- `422`: schema, IOC, STIX or Sigma validation failed.
- `429`: per-process rate limit.
- `503`: service auth not configured.

Indicators are limited to 4096 characters, event context to 64 KiB, IOC raw data
to 256 KiB and general HTTP bodies to 1 MiB. Feed/STIX import has separate
bounded object/response limits.

WebSocket clients pass the service token only as `X-Vrindha-Service-Token`;
query-string credentials are rejected so tokens cannot enter access-log URLs.
Messages are `{type:event,event:{...}}` or heartbeat objects. Clients should
reconnect with bounded exponential backoff
and stop after an operator-configured attempt limit.
