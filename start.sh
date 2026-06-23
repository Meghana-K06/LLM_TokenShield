#!/bin/bash

# Start Redis
docker start twinshield-redis

# Start Ollama only if not already running
if ! pgrep -x "ollama" > /dev/null; then
    ollama serve &
    echo "✅ Ollama started"
else
    echo "✅ Ollama already running"
fi

cd ~/Desktop/twinshield
source venv/bin/activate
echo "✅ TwinShield environment ready!"
