#!/bin/bash

# Development Server Startup Script

set -e

echo "🚀 Starting Censys Host Summarizer in development mode..."

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to start backend
start_backend() {
    echo "🔧 Starting backend server..."
    cd backend
    
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        echo "❌ Virtual environment not found. Please run setup.sh first."
        exit 1
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Check if port 8000 is in use
    if check_port 8000; then
        echo "⚠️  Port 8000 is already in use. Backend might already be running."
    else
        echo "Starting backend on http://localhost:8000"
        python -m uvicorn main:app --reload --port 8000 &
        BACKEND_PID=$!
        echo "Backend started with PID: $BACKEND_PID"
    fi
    
    cd ..
}

# Function to start frontend
start_frontend() {
    echo "🎨 Starting frontend server..."
    cd frontend
    
    # Check if node_modules exists
    if [ ! -d "node_modules" ]; then
        echo "❌ Node modules not found. Please run setup.sh first."
        exit 1
    fi
    
    # Check if port 3000 is in use
    if check_port 3000; then
        echo "⚠️  Port 3000 is already in use. Frontend might already be running."
    else
        echo "Starting frontend on http://localhost:3000"
        npm start &
        FRONTEND_PID=$!
        echo "Frontend started with PID: $FRONTEND_PID"
    fi
    
    cd ..
}

# Function to cleanup on exit
cleanup() {
    echo -e "\n🛑 Shutting down servers..."
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo "Backend stopped"
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
        echo "Frontend stopped"
    fi
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start services
start_backend
start_frontend

echo ""
echo "✅ Development servers started!"
echo "📱 Frontend: http://localhost:3000"
echo "🔧 Backend: http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all servers"

# Wait for user to stop
wait

