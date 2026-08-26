# Build from the repository root so both vrin_SOC and Vrin_TI are importable:
#   docker build -f vrin_SOC/Dockerfile .
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    VRINDHA_MODE=defensive \
    PYTHONPATH=/app
WORKDIR /app

# Security tools run without shell interpolation and under an unprivileged user.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip nmap whois nikto gobuster dirb tcpdump wireshark-common \
    snort suricata rkhunter chkrootkit fail2ban ufw curl net-tools iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY vrin_SOC/requirements.txt /tmp/soc-requirements.txt
COPY Vrin_TI/requirements.txt /tmp/ti-requirements.txt
RUN pip3 install --break-system-packages --no-cache-dir \
    -r /tmp/soc-requirements.txt -r /tmp/ti-requirements.txt
COPY . /app

RUN useradd --create-home --shell /usr/sbin/nologin vrindha \
    && mkdir -p vrin_SOC/logs vrin_SOC/database vrin_SOC/data \
    && chown -R vrindha:vrindha /app
USER vrindha

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/status || exit 1

# SECRET_KEY and ADMIN_PASSWORD must be supplied at runtime; no credentials are
# baked into the image. Use multiple workers only after moving confirmation
# state to a shared store.
CMD ["uvicorn", "vrin_SOC.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
