#!/bin/bash
# =============================================
# Chronos-DFIR Clean Restart Script v124
# =============================================

echo "🔴 Killing all uvicorn/python processes on port 8000..."
lsof -ti:8000 | xargs kill -9 2>/dev/null
pkill -9 -f "uvicorn app:app" 2>/dev/null
pkill -9 -f "python.*app.py" 2>/dev/null
sleep 1

echo "✅ Port 8000 cleared."
echo "🚀 Starting Chronos-DFIR (fresh, latest code)..."

cd "$(dirname "$0")"

# Use venv uvicorn
source "$(dirname "$0")/venv/bin/activate"
uvicorn app:app \
  --host 0.0.0.0 \
  --port 8000 \
  --reload \
  --reload-dir static \
  --reload-dir templates \
  --reload-dir engine

