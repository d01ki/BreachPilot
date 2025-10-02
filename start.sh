#!/bin/bash
"""
BreachPilot Startup Script
Automatically finds available port and starts the application
"""

echo "======================================"
echo "BreachPilot Startup Script"
echo "======================================"
echo ""

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0  # Port is in use
    else
        return 1  # Port is available
    fi
}

# Function to find available port
find_available_port() {
    local start_port=$1
    local max_attempts=10
    local port=$start_port
    
    for ((i=0; i<max_attempts; i++)); do
        if ! check_port $port; then
            echo $port
            return 0
        fi
        port=$((port + 1))
    done
    
    return 1
}

# Default port
DEFAULT_PORT=8000
PORT=${1:-$DEFAULT_PORT}

echo "[*] Checking if port $PORT is available..."

if check_port $PORT; then
    echo "[!] Port $PORT is already in use"
    echo "[*] Finding available port..."
    
    AVAILABLE_PORT=$(find_available_port $PORT)
    
    if [ $? -eq 0 ]; then
        echo "[+] Found available port: $AVAILABLE_PORT"
        PORT=$AVAILABLE_PORT
    else
        echo "[!] Could not find available port"
        echo ""
        echo "Solutions:"
        echo "  1. Stop existing process:"
        echo "     lsof -i :$DEFAULT_PORT"
        echo "     kill -9 <PID>"
        echo ""
        echo "  2. Manually specify port:"
        echo "     ./start.sh 8001"
        exit 1
    fi
else
    echo "[+] Port $PORT is available"
fi

echo ""
echo "[*] Starting BreachPilot on port $PORT..."
echo ""

python3 app.py --port $PORT
