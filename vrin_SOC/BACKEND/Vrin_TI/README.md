# Vrin_TI

Independent Threat Intelligence service for Vrindha AI. It owns its storage,
feeds, scoring, enrichment and correlation lifecycle and communicates with the
existing SOC only through `core/intelligence_bus.py` and authenticated service
transport. See `docs/threat-intelligence.md` for operations and architecture.

From the repository root:

```bash
./Vrin_TI/vrindha-ti doctor
VRINDHA_TI_API_KEY='<secret>' Vrin_TI/.venv/bin/uvicorn Vrin_TI.api:app --host 127.0.0.1 --port 8010
```

Vrin_TI is defensive-only. Correlations can recommend incidents but never run
scans, exploits, firewall commands, process termination, or containment.
