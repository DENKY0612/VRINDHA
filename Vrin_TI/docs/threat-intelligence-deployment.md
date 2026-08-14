# Vrin_TI deployment on Kali Linux

## Local install

From the repository root containing sibling `vrin_SOC/` and `Vrin_TI/`:

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
# put output in VRINDHA_TI_API_KEY; configure SECRET_KEY separately
./Vrin_TI/scripts/install_threat_intelligence.sh
./Vrin_TI/vrindha-ti doctor
```

The installer creates an independent `Vrin_TI/.venv`, installs only TI Python
requirements, creates TI-owned writable directories and detects optional
components. It reuses the existing `vrin_SOC/.venv` only when installing the
optional SOC gateway service. It does not blindly install security tools or
silently escalate.

Manual development processes (not persistent), from the repository root:

```bash
set -a; . ./.env; set +a
Vrin_TI/.venv/bin/uvicorn Vrin_TI.api:app --host 127.0.0.1 --port 8010
vrin_SOC/.venv/bin/uvicorn --app-dir vrin_SOC api.main:app --host 127.0.0.1 --port 8000
```

## systemd

Choose an existing unprivileged service account that can read the checkout and
write `Vrin_TI/database/`, `Vrin_TI/logs/`, `Vrin_TI/quarantine/` and the
existing SOC runtime directories. Do not choose root.

```bash
sudo ./Vrin_TI/scripts/install_threat_intelligence.sh \
  --install-systemd --service-user "$USER"
sudoedit /etc/vrindha/vrindha-ti.env
sudo systemctl daemon-reload
sudo systemctl enable --now vrindha-threat-intelligence
sudo systemctl enable --now vrindha-soc-gateway
systemctl status vrindha-threat-intelligence
journalctl -u vrindha-threat-intelligence -f
```

Use `--enable` to install and enable in one explicit step. If the SOC API is
already managed by another unit/container, install or enable only the TI unit;
two processes cannot bind port 8000.

Supported controls:

```bash
systemctl start|stop|restart|status vrindha-threat-intelligence
systemctl start|stop|restart|status vrindha-soc-gateway
```

Units use `Restart=on-failure`, `NoNewPrivileges`, private temporary/device
namespaces, read-only system/home protections, a `0077` umask and narrow writable
paths. They survive terminal closure, logout and reboot after enablement.

## Required environment

```dotenv
VRINDHA_TI_ENABLED=true
VRINDHA_TI_API_KEY=<independent random service secret>
VRINDHA_TI_URL=http://127.0.0.1:8010
VRINDHA_SOC_URL=http://127.0.0.1:8000
VRINDHA_INTELLIGENCE_BUS=auto
SECRET_KEY=<existing SOC JWT secret>
```

Do not put secrets in YAML, service unit arguments or Git. The installer creates
`/etc/vrindha/vrindha-ti.env` mode 0600 when absent.

## Optional integrations

- Redis: install Python `redis`, set `VRINDHA_REDIS_URL`, provision TLS/auth for
  remote Redis. Failure falls back to SQLite.
- NATS: install `nats-py`, set `VRINDHA_NATS_URL`; provision JetStream for
  durability. Core NATS is not the only retained copy because SQLite remains.
- TAXII/NVD/VT/AbuseIPDB/MISP/OpenCTI: set only required credentials and opt in.
- Suricata/Zeek: enable feed in YAML and configure a readable log path.
- YARA: install `yara-python`, configure rules and allowed quarantine roots.
- Sigma: PyYAML is required; point to official rule YAML.

Missing optional integrations never prevent startup.

## Remote deployment

The application defaults to `127.0.0.1`. Do not bind publicly without an HTTPS
reverse proxy, certificate validation, strict allowed hosts, network firewall,
rate limiting and service authentication. Update `VRINDHA_TI_ALLOWED_HOSTS` and
service URLs explicitly. Plain HTTP is rejected for non-loopback SOC transport.

## Backups and migration

Back up `Vrin_TI/database/threat_intelligence.db` using SQLite's online backup
command or a filesystem snapshot that includes WAL state. Do not copy only the
DB file while actively writing. Test restore with `./Vrin_TI/vrindha-ti doctor`
before rotation.
Expired indicators are history; retention jobs should archive, not silently
remove evidence.

## Troubleshooting

- `gateway authentication DEGRADED`: set the same `VRINDHA_TI_API_KEY` for both
  services and restart both.
- `transport degraded`: inspect Redis/NATS/SOC health; queued events remain in
  `transport_queue`.
- feed `stale/error`: inspect structured logs, DNS/TLS/allowlist, then manual
  `./Vrin_TI/vrindha-ti sync <feed>`.
- `permission_error`: grant the unprivileged service user read access to the
  configured telemetry/rules path; never run the app as root.
- service loop: check port conflict and `/etc/vrindha/vrindha-ti.env` mode.
