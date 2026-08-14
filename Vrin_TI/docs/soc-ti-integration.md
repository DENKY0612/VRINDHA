# SOC ↔ Vrin_TI integration

## Dual-system architecture

```text
Vrindha_SOC repository
├── vrin_SOC/     existing SOC (original directory name preserved)
└── Vrin_TI/      independent Threat Intelligence service
```

```text
Existing Vrindha SOC                         Independent Vrin_TI
API / SIEM / Threat Agent                    API :8010 / feeds / CTI DB
       |                                                |
       +---- core/intelligence_bus.py <----------------+
                 authenticated gateway
                 Redis > NATS > HTTPS > SQLite fallback
                              |
                       Correlation Engine
                              |
                  risk/incident recommendation
                              |
         existing Safety + Authorization + Dharma
                              |
                       Human approval
```

Neither side is merged into the other. SOC remains functional if TI is stopped.
TI remains usable from its API/CLI if SOC is stopped. They share a formal event
contract and, on one host, an independent TI SQLite database for durable outage
queueing.

## Routes and authentication

- TI receives SOC events at `POST :8010/intelligence/events`.
- SOC receives TI events at `POST :8000/intelligence/events`.
- `X-Vrindha-Service-Token` must equal `VRINDHA_TI_API_KEY` in constant time.
- Analyst-facing SOC proxy routes use the existing Bearer JWT.
- Remote URLs must use HTTPS with valid certificates. HTTP is accepted only for
  loopback service URLs.
- Event IDs, bounded timestamps and the database unique key prevent replay.
- Rate limits, body limits, strict schemas, audit logs and correlation IDs apply.

Example:

```json
{
  "event_type": "ioc_observation",
  "event_id": "f1696ac8-8017-4f6a-baaa-b6947fdfc37f",
  "timestamp": "2026-08-14T08:03:00Z",
  "source": "soc",
  "indicator": {"type": "ipv4", "value": "203.0.113.10"},
  "asset": {"id": "host-001", "ip": "10.0.0.25", "criticality": 0.9, "exposed": false},
  "context": {"sensor": "suricata", "kind": "connection"},
  "severity": "high",
  "confidence": 0.91,
  "correlation_id": "32c36831-4259-495e-95eb-271322908cd1",
  "schema_version": "1.0"
}
```

Supported event types include IOC observation/match/update, threat update/expiry/
enrichment, CVE/malware/actor/campaign update, ATT&CK mapping, sighting,
correlation, risk, incident and feed health.

## Flow

1. SOC creates a validated `IntelligenceEvent`.
2. Gateway sends over HTTPS. If TI is down, it inserts one `inbound` queue row.
3. TI's background consumer drains the queue after restart.
4. TI normalizes and looks up the indicator; unknown observations remain low
   confidence rather than being declared malicious.
5. A sighting records asset, timestamp, source and context.
6. Correlation combines TI score/provenance with SOC confidence, asset context,
   same-host 30-minute sightings and explicit malware/KEV/ATT&CK evidence.
7. TI returns an enriched alert and emits IOC-match/correlation events.
8. SOC records those events. It does **not** invoke response automation from the
   gateway. Incident events are recommendations requiring the existing safety,
   authorization and human approval chain.

## Redis/NATS failure

`TransportManager` attempts configured Redis Streams, NATS/JetStream and HTTP.
Connection or publish failure changes health to degraded and persists the event
in SQLite. Redis is not imported unless selected and never blocks startup.

## Existing SOC proxy

Authenticated users can use these routes on the existing port 8000:

- `GET /threat-intel/health|status|feeds|correlations|sightings|vulnerabilities|reports`
- `GET /threat-intel/indicators/{indicator}`
- `POST /threat-intel/lookup|sighting|events`
- administrator: `POST /threat-intel/feeds/{feed}/sync`

The existing dashboard has a Threat Intelligence pane using those routes. When
TI is down it displays degraded state while SOC operation continues.

## Future modules

The versioned event envelope deliberately uses neutral `source`, `event_type`,
`context`, `correlation_id`, auth and audit semantics. Future Analyst,
Infrastructure, Data Science, Knowledge, Compliance and Commander modules can
use the same transport abstraction with their own authorized event types. They
must not bypass Safety/Authorization/Human Approval.
