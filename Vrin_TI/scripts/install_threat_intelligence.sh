#!/bin/sh
# Safe Vrin_TI installer: independent Python environment and optional systemd.
# It deliberately does not apt-install Suricata, Zeek, YARA, Redis, NATS, MISP,
# OpenCTI, or any security tool.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TI_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$TI_ROOT/.." && pwd)
SOC_ROOT="${VRINDHA_SOC_ROOT:-$REPOSITORY_ROOT/vrin_SOC}"
INSTALL_SYSTEMD=0
ENABLE=0
SERVICE_USER="${SUDO_USER:-$(id -un)}"
TI_VENV="$TI_ROOT/.venv"
SOC_VENV="$SOC_ROOT/.venv"

usage() {
  echo "Usage: $0 [--venv PATH] [--soc-venv PATH] [--install-systemd] [--enable] [--service-user USER]"
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --venv) TI_VENV=$2; shift 2 ;;
    --soc-venv) SOC_VENV=$2; shift 2 ;;
    --install-systemd) INSTALL_SYSTEMD=1; shift ;;
    --enable) INSTALL_SYSTEMD=1; ENABLE=1; shift ;;
    --service-user) SERVICE_USER=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null 2>&1 || { echo "REQUIRED: python3 is missing" >&2; exit 1; }
echo "Python: $(python3 --version 2>&1)"
echo "TI root: $TI_ROOT"
if [ -d "$SOC_ROOT" ]; then
  echo "SOC sibling detected: $SOC_ROOT"
else
  echo "OPTIONAL: SOC sibling not found; standalone TI installation remains available."
fi
if [ -r /etc/os-release ]; then
  . /etc/os-release
  echo "OS: ${PRETTY_NAME:-unknown}"
  [ "${ID:-}" = "kali" ] || echo "NOTE: Kali is the target; continuing on compatible Linux."
fi

if [ ! -x "$TI_VENV/bin/python" ]; then
  echo "Creating independent TI virtual environment: $TI_VENV"
  python3 -m venv "$TI_VENV"
fi
"$TI_VENV/bin/python" -m pip install --upgrade pip
"$TI_VENV/bin/python" -m pip install -r "$TI_ROOT/requirements.txt"
mkdir -p "$TI_ROOT/database" "$TI_ROOT/logs/threat_intelligence" "$TI_ROOT/quarantine"
chmod 700 "$TI_ROOT/database" "$TI_ROOT/logs/threat_intelligence" "$TI_ROOT/quarantine"
chmod +x "$TI_ROOT/vrindha-ti"

if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  [ -d "$SOC_ROOT" ] || { echo "SOC gateway service requested but sibling SOC is missing: $SOC_ROOT" >&2; exit 1; }
  [ "$(id -u)" -eq 0 ] || { echo "--install-systemd requires root; rerun explicitly with sudo." >&2; exit 1; }
  [ "$SERVICE_USER" != "root" ] || { echo "Refusing to run Vrindha Python services as root; use --service-user." >&2; exit 1; }
  id "$SERVICE_USER" >/dev/null 2>&1 || { echo "Service user does not exist: $SERVICE_USER" >&2; exit 1; }
  SERVICE_GROUP=$(id -gn "$SERVICE_USER")

  # The SOC remains independently dependency-managed. Reuse its environment;
  # create it only when the optional SOC gateway unit is being installed.
  if [ ! -x "$SOC_VENV/bin/python" ]; then
    echo "Creating SOC virtual environment required by the gateway unit: $SOC_VENV"
    python3 -m venv "$SOC_VENV"
    "$SOC_VENV/bin/python" -m pip install --upgrade pip
    "$SOC_VENV/bin/python" -m pip install -r "$SOC_ROOT/requirements.txt"
  fi

  install -d -m 700 /etc/vrindha
  if [ ! -e /etc/vrindha/vrindha-ti.env ]; then
    TOKEN=$("$TI_VENV/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')
    SECRET=$("$TI_VENV/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')
    umask 077
    cat > /etc/vrindha/vrindha-ti.env <<EOF
VRINDHA_TI_ENABLED=true
VRINDHA_TI_API_KEY=$TOKEN
VRINDHA_TI_URL=http://127.0.0.1:8010
VRINDHA_SOC_URL=http://127.0.0.1:8000
VRINDHA_INTELLIGENCE_BUS=auto
SECRET_KEY=$SECRET
EOF
    echo "Created /etc/vrindha/vrindha-ti.env with generated secrets (mode 0600)."
  fi
  chmod 600 /etc/vrindha/vrindha-ti.env
  for unit in vrindha-threat-intelligence.service vrindha-soc-gateway.service; do
    sed -e "s|@REPOSITORY_ROOT@|$REPOSITORY_ROOT|g" \
        -e "s|@TI_ROOT@|$TI_ROOT|g" -e "s|@SOC_ROOT@|$SOC_ROOT|g" \
        -e "s|@TI_PYTHON@|$TI_VENV/bin/python|g" -e "s|@SOC_PYTHON@|$SOC_VENV/bin/python|g" \
        -e "s|@SERVICE_USER@|$SERVICE_USER|g" -e "s|@SERVICE_GROUP@|$SERVICE_GROUP|g" \
        "$TI_ROOT/systemd/$unit" > "/etc/systemd/system/$unit"
  done
  mkdir -p "$SOC_ROOT/database" "$SOC_ROOT/logs" "$SOC_ROOT/data"
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$TI_ROOT/database" "$TI_ROOT/logs" "$TI_ROOT/quarantine"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$SOC_ROOT/database" "$SOC_ROOT/logs" "$SOC_ROOT/data"
  systemctl daemon-reload
  echo "Installed sibling TI and SOC gateway units. Do not run another manager on port 8000."
  if [ "$ENABLE" -eq 1 ]; then
    systemctl enable --now vrindha-threat-intelligence.service
    systemctl enable --now vrindha-soc-gateway.service
  fi
fi

cd "$REPOSITORY_ROOT"
"$TI_VENV/bin/python" -m Vrin_TI.cli doctor || true
echo "Installation complete. SOC and TI remain separate sibling systems."
