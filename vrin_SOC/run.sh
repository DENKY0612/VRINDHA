#!/bin/sh
# Vrindha AI SOC - Run Script per Deployment Prompt
# Resolve paths from this file so `./vrin_SOC/run.sh` also works from the
# repository root (and from a systemd/cron working directory).
set -eu

SOC_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SOC_ROOT"

if [ -n "${PYTHON:-}" ]; then
    PYTHON_BIN=$PYTHON
elif [ -x "$SOC_ROOT/.venv/bin/python" ]; then
    PYTHON_BIN="$SOC_ROOT/.venv/bin/python"
else
    PYTHON_BIN=python3
fi

# Fail with an actionable message instead of the less useful
# "uvicorn: command not found" or "No module named fastapi" halfway through
# startup. CLI and tool verification do not require FastAPI, so this check is
# performed only for API modes below.
require_api_dependencies() {
    if ! "$PYTHON_BIN" -c 'import fastapi, uvicorn, pydantic, jose, bcrypt, dotenv, pandas, numpy, sklearn, requests' >/dev/null 2>&1; then
        echo "FastAPI dependencies are missing for this Python interpreter: $PYTHON_BIN" >&2
        echo "Install them with: $PYTHON_BIN -m pip install -r requirements.txt" >&2
        return 1
    fi
}

start_api() {
    require_api_dependencies
    set -- -m uvicorn api.main:app --host "${API_HOST:-0.0.0.0}" --port "${API_PORT:-8000}"
    case "${API_RELOAD:-false}" in
        1|true|TRUE|yes|YES) set -- "$@" --reload ;;
    esac
    exec "$PYTHON_BIN" "$@"
}

echo "🛡️ Vrindha AI SOC System - Startup"
"$PYTHON_BIN" --version

# Database initialization is idempotent and now works regardless of the
# caller's current working directory.
"$PYTHON_BIN" -c "import database.db"

echo ""
echo "Choose mode:"
echo "1) CLI Mode (Terminal AI Assistant) - per Day 2-4"
echo "2) API Mode (FastAPI Backend + Dashboard) - per Day 24-26"
echo "3) Both (API in background + CLI)"
echo "4) Verify Tools"
echo "5) Show Help"

# A non-interactive caller can provide VRINDHA_RUN_OPTION; interactive use
# retains the original prompt.
if [ -n "${VRINDHA_RUN_OPTION:-}" ]; then
    opt=$VRINDHA_RUN_OPTION
else
    printf 'Option [1-5]: '
    read -r opt
fi

case $opt in
    1)
        echo "Starting CLI..."
        exec "$PYTHON_BIN" main.py
        ;;
    2)
        echo "Starting API on http://${API_HOST:-0.0.0.0}:${API_PORT:-8000}"
        echo "Dashboard: http://localhost:${API_PORT:-8000}/dashboard/"
        echo "Docs: http://localhost:${API_PORT:-8000}/docs"
        start_api
        ;;
    3)
        require_api_dependencies
        echo "Starting API in background..."
        "$PYTHON_BIN" -m uvicorn api.main:app --host "${API_HOST:-0.0.0.0}" --port "${API_PORT:-8000}" &
        api_pid=$!
        trap 'kill "$api_pid" 2>/dev/null || true' INT TERM EXIT
        sleep 2
        echo "Starting CLI..."
        "$PYTHON_BIN" main.py
        ;;
    4)
        exec "$PYTHON_BIN" -c "from tools.installer import verify_all_tools; import json; print(json.dumps(verify_all_tools(), indent=2))"
        ;;
    5)
        exec "$PYTHON_BIN" main.py <<'EOF'
help
exit
EOF
        ;;
    *)
        echo "Invalid option, starting CLI as default"
        exec "$PYTHON_BIN" main.py
        ;;
esac
