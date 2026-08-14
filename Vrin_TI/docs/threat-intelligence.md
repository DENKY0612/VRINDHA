# Vrindha Threat Intelligence (`Vrin_TI`)

## Scope

`Vrin_TI/` is an independent defensive CTI service. It owns its SQLite database,
feed schedules, IOC lifecycle, STIX conversion, enrichment, scoring, sightings,
graph and correlations. It does not replace the existing SOC. The SOC imports
only `core/intelligence_bus.py`, a thin gateway that sends observations and
receives enrichment.

TI can collect, normalize, analyze, enrich, correlate, alert and recommend. It
has no scanner/exploit/firewall/process execution interface. A correlation that
meets incident thresholds emits a **recommended** incident carrying
`requires_safety_authorization`, `requires_human_approval`, and
`defensive_action_executed: false`.

## Components

- `models.py`: strict IOC, sighting, feed and SOC↔TI Pydantic contracts.
- `database.py`: independent SQLite WAL schema, indexes, provenance, history,
  durable queues, graph edges, correlations and reports.
- `normalization.py`: deterministic `type + normalized_value` identity.
- `stix.py`: STIX 2.1 bundle validation and STIX ↔ internal indicators.
- `core/intelligence_bus.py`: Redis, NATS, HTTPS and durable local transports.
- `collectors/`: independent CISA KEV, NVD, MITRE, TAXII, Suricata and Zeek
  adapters with bounded fetches/retries.
- `enrichment/`: local-first enrichment; external providers are double opt-in.
- `scoring/`: separate 0–100 threat and 0–1 confidence scores.
- `correlation/`: event, threat and relationship correlation.
- `integrations/`: safe YARA file matching and official Sigma YAML metadata.
- `connectors/`: optional MISP and OpenCTI clients.
- `api.py`, `cli.py`: independent API/WebSocket and analyst CLI.

## IOC lifecycle and data

Supported normalized types are IPv4, IPv6, domain, URL, email, MD5, SHA1,
SHA256, file, mutex, certificate, CVE, MITRE technique/software, threat actor
and campaign. Lifecycle is `new → active → stale/expired/revoked/false_positive/
confirmed`. Expiry changes state but does not delete history.

The deterministic key is:

```text
indicator_type + ":" + normalized_value
```

`threat_sources`, `confidence_history`, and `threat_sightings` retain changing
provenance and observations. Raw objects are bounded to 256 KiB; duplicate raw
feed copies are not accumulated indefinitely.

## Scoring

Threat and confidence are intentionally separate. Threat score considers source
confidence/reliability, source diversity, recency, sightings, malware/campaign
relationships, ATT&CK evidence, CVSS plus KEV/exploitation context, and false
positive/age penalties. CVSS alone never sets priority. Classification:

| Score | Classification |
|---:|---|
| 0–19 | Informational |
| 20–39 | Low |
| 40–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

No score authorizes a host change. Source reliability can be adjusted from
historical correct/false-positive observations.

## Feeds

Defaults are in `Vrin_TI/config/threat_intelligence.yaml`. CISA KEV and MITRE
are enabled but `collect_on_start` is false, avoiding startup dependency on the
Internet. Schedulers fetch after their interval unless manually synchronized.
Enable NVD/TAXII/local telemetry explicitly.

```bash
./Vrin_TI/vrindha-ti feeds
./Vrin_TI/vrindha-ti sync cisa_kev
./Vrin_TI/vrindha-ti sync mitre_attack
```

HTTP collectors enforce HTTPS, hostname allowlists, DNS resolution checks,
redirect revalidation, certificate verification, timeouts and response limits.
Feed content is parsed as JSON/data and never evaluated or deserialized with
unsafe object loaders.

### Local telemetry

Set `SURICATA_EVE_PATH` and enable the Suricata feed to parse only alert, DNS,
HTTP, TLS, flow, anomaly and fileinfo records. Set `ZEEK_LOG_DIR` and enable the
Zeek feed for JSON-mode conn/dns/http/ssl/x509/ssh/files logs. Cursor offsets
survive restarts. Inputs are filtered into IOC observations instead of storing
all telemetry.

YARA uses `yara-python`, accepts only regular non-symlink files beneath
`VRINDHA_TI_ALLOWED_SCAN_PATHS`, and never executes samples. Sigma uses
`yaml.safe_load` and preserves official metadata/detection syntax.

## Privacy and external enrichment

Both must be true before an external lookup:

1. `VRINDHA_TI_EXTERNAL_ENRICHMENT=true`
2. `VRINDHA_TI_EXTERNAL_SUBMISSION=true`
3. the analyst uses `enrich --external` / `allow_external: true`
4. the privacy classifier marks the artifact public.

Private/link-local IPs, internal names, email/file artifacts and sensitive URLs
are denied. Provider keys come only from environment variables. Results use a
bounded TTL cache.

## CLI

```bash
./Vrin_TI/vrindha-ti status
./Vrin_TI/vrindha-ti feeds
./Vrin_TI/vrindha-ti sync [all|cisa_kev|mitre_attack|nvd|stix_taxii]
./Vrin_TI/vrindha-ti lookup 8.8.8.8
./Vrin_TI/vrindha-ti enrich example.org
./Vrin_TI/vrindha-ti sightings
./Vrin_TI/vrindha-ti correlations
./Vrin_TI/vrindha-ti mitre T1059
./Vrin_TI/vrindha-ti vulnerabilities --kev
./Vrin_TI/vrindha-ti report indicator--...
./Vrin_TI/vrindha-ti doctor
```

All output is structured JSON. `doctor` marks every dependency REQUIRED,
OPTIONAL, AVAILABLE, UNAVAILABLE, DISABLED or DEGRADED.

## Logging and metrics

Structured JSON logs rotate under `Vrin_TI/logs/threat_intelligence/`. API keys, tokens,
password and authorization fields are redacted. `/metrics` exposes authenticated
Prometheus text for indicator, correlation, feed, enrichment, SOC message and
queue metrics. Audit records are also stored in the TI database.

## Tests

```bash
(cd vrin_SOC && .venv/bin/python -m unittest discover -s tests -v)
Vrin_TI/.venv/bin/python -m unittest discover -s Vrin_TI/tests -v
```

Tests mock external dependencies and never need live feeds. See deployment and
integration documents for service setup and event flow.
