#!/bin/bash
# Vrindha AI SOC - Run Script per Deployment Prompt
echo "🛡️ Vrindha AI SOC System - Startup"

# Check Python
python3 --version

# Install dependencies if needed
if [ ! -f "database/vrindha.db" ]; then
    echo "Initializing database..."
    python3 -c "from database.db import init_db; init_db()"
fi

echo ""
echo "Choose mode:"
echo "1) CLI Mode (Terminal AI Assistant) - per Day 2-4"
echo "2) API Mode (FastAPI Backend + Dashboard) - per Day 24-26"
echo "3) Both (API in background + CLI)"
echo "4) Verify Tools"
echo "5) Show Help"

read -p "Option [1-5]: " opt

case $opt in
    1)
        echo "Starting CLI..."
        python3 main.py
        ;;
    2)
        echo "Starting API on http://localhost:8000"
        echo "Dashboard: http://localhost:8000/dashboard/"
        echo "Docs: http://localhost:8000/docs"
        uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
        ;;
    3)
        echo "Starting API in background..."
        uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload &
        sleep 2
        echo "Starting CLI..."
        python3 main.py
        ;;
    4)
        python3 -c "from tools.installer import verify_all_tools; import json; print(json.dumps(verify_all_tools(), indent=2))"
        ;;
    5)
        python3 main.py <<< "help"
        ;;
    *)
        echo "Invalid option, starting CLI as default"
        python3 main.py
        ;;
esac
