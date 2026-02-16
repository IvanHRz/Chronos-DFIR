#!/bin/bash

# Find and kill any showing Uvicorn process
echo "Stopping Chronos-DFIR Server..."
lsof -i :8000 | awk 'NR!=1 {print $2}' | xargs kill -9 2>/dev/null

echo "Starting Server..."
# Ensure we are in the right directory
cd "$(dirname "$0")"

# Activate venv if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run with reload, referencing local app.py
# Using nohup to keep it running if terminal closes, or just standard for visibility
# We use 'exec' to replace shell with python for cleaner signal handling
exec uvicorn app:app --reload --host 127.0.0.1 --port 8000 > server.log 2>&1
