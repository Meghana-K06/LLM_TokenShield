#!/bin/bash

echo "🛡️ Starting TwinShield..."

# 1. Start Redis
docker start twinshield-redis
echo "✅ Redis started"

# 2. Start Ollama only if not already running
if ! pgrep -x "ollama" > /dev/null; then
    ollama serve &
    echo "✅ Ollama started"
    sleep 3
else
    echo "✅ Ollama already running"
fi

# 3. Set Python path
export PYTHONPATH=/home/meghana/Desktop/twinshield/backend
echo "✅ PYTHONPATH set"

export TIKTOKEN_CACHE_DIR=~/Desktop/twinshield/.tiktoken_cache
echo "Tiktoken path set"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Now open 2 more terminals and run:"
echo ""
echo "TERMINAL 2 — Backend:"
echo "  cd ~/Desktop/twinshield"
echo "  source venv/bin/activate"
echo "  export PYTHONPATH=/home/meghana/Desktop/twinshield/backend"
echo "  cd backend"
echo "  uvicorn main:app --host 0.0.0.0 --port 8000 --reload"
echo ""
echo "TERMINAL 3 — Dashboard:"
echo "  cd ~/Desktop/twinshield"
echo "  source venv/bin/activate"
echo "  cd dashboard"
echo "  streamlit run app.py --server.port 8501"
echo ""
echo "BROWSER:"
echo "  API:       http://localhost:8000/health"
echo "  Swagger:   http://localhost:8000/docs"
echo "  Dashboard: http://localhost:8501"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
