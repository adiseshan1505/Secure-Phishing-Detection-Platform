#!/bin/bash

# Quick start script - runs both backend and frontend

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "🔐 Starting Phishing Detection Platform..."
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
}

trap cleanup EXIT

# Start Backend
echo "Starting Backend (Flask)..."
cd "$SCRIPT_DIR/backend"
source ../../.venv/bin/activate
python3 run.py &
BACKEND_PID=$!
sleep 2

# Start Frontend
echo "Starting Frontend (React + Vite)..."
cd "$SCRIPT_DIR/frontend"
npm run dev &
FRONTEND_PID=$!
sleep 2

echo ""
echo "=========================================="
echo "✅ Application Started!"
echo "=========================================="
echo ""
echo "Frontend: http://localhost:5173"
echo "Backend:  http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop both servers"
echo "=========================================="

wait
