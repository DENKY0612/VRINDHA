# Dockerfile per DEPLOYMENT PROMPT Start Up.pdf
# Prepare Vrindha for deployment - Dockerize, env variables, secure API, future AWS/VPS Nginx HTTPS
FROM kalilinux/kali-rolling:latest

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV VRINDHA_MODE=defensive

WORKDIR /app

# Install system dependencies per tool stack
# Per blueprint advice: Don't install everything at once, start with nmap → nikto → wireshark → fail2ban
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    whois \
    nikto \
    gobuster \
    dirb \
    tcpdump \
    wireshark \
    snort \
    suricata \
    rkhunter \
    chkrootkit \
    fail2ban \
    ufw \
    curl \
    wget \
    git \
    vim \
    net-tools \
    iproute2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Optional: amass, sublist3r via pip/go
RUN pip3 install --break-system-packages sublist3r || pip3 install sublist3r || true

# Copy requirements
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt || pip3 install -r requirements.txt

# Copy project
COPY . .

# Create necessary directories
RUN mkdir -p logs database data

# Expose API port
EXPOSE 8000

# Environment variables example
ENV SECRET_KEY=vrindha-super-secret-change-me
ENV DATABASE_URL=sqlite:///./database/vrindha.db

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/status || exit 1

# Default command: Run FastAPI backend
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Alternative commands:
# For CLI: docker run -it vrindha python3 main.py
# For API: docker run -p 8000:8000 vrindha
