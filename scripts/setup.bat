@echo off
echo 🚀 Setting up Censys Host Summarizer...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed.
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Node.js is required but not installed.
    exit /b 1
)

REM Setup backend
echo 📦 Setting up backend...
cd backend

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating Python virtual environment...
    python -m venv venv
)

REM Activate virtual environment and install dependencies
echo Installing Python dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt

REM Install test dependencies
if exist "requirements-test.txt" (
    echo Installing test dependencies...
    pip install -r requirements-test.txt
)

cd ..

REM Setup frontend
echo 📦 Setting up frontend...
cd frontend

REM Install dependencies
echo Installing Node.js dependencies...
npm install

cd ..

REM Setup E2E tests
echo 📦 Setting up E2E tests...
cd e2e

REM Install dependencies
echo Installing E2E test dependencies...
npm install

REM Install Playwright browsers
echo Installing Playwright browsers...
npx playwright install

cd ..

echo ✅ Setup complete!
echo.
echo To start the application:
echo 1. Backend: cd backend ^&^& venv\Scripts\activate ^&^& python -m uvicorn main:app --reload --port 8000
echo 2. Frontend: cd frontend ^&^& npm start
echo.
echo To run tests:
echo 1. Backend tests: cd backend ^&^& venv\Scripts\activate ^&^& pytest test_main.py -v
echo 2. Frontend tests: cd frontend ^&^& npm test
echo 3. E2E tests: cd e2e ^&^& npm test
echo.
echo For Docker deployment:
echo docker-compose up --build

