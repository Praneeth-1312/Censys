#!/bin/bash

# Censys Host Summarizer Setup Script

set -e

echo "🚀 Setting up Censys Host Summarizer..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is required but not installed."
    exit 1
fi

# Setup backend
echo "📦 Setting up backend..."
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Install test dependencies
if [ -f "requirements-test.txt" ]; then
    echo "Installing test dependencies..."
    pip install -r requirements-test.txt
fi

cd ..

# Setup frontend
echo "📦 Setting up frontend..."
cd frontend

# Install dependencies
echo "Installing Node.js dependencies..."
npm install

cd ..

# Setup E2E tests
echo "📦 Setting up E2E tests..."
cd e2e

# Install dependencies
echo "Installing E2E test dependencies..."
npm install

# Install Playwright browsers
echo "Installing Playwright browsers..."
npx playwright install

cd ..

echo "✅ Setup complete!"
echo ""
echo "To start the application:"
echo "1. Backend: cd backend && source venv/bin/activate && python -m uvicorn main:app --reload --port 8000"
echo "2. Frontend: cd frontend && npm start"
echo ""
echo "To run tests:"
echo "1. Backend tests: cd backend && source venv/bin/activate && pytest test_main.py -v"
echo "2. Frontend tests: cd frontend && npm test"
echo "3. E2E tests: cd e2e && npm test"
echo ""
echo "For Docker deployment:"
echo "docker-compose up --build"

