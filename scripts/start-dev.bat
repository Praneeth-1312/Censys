@echo off
echo 🚀 Starting Censys Host Summarizer in development mode...

REM Start backend in a new window
echo 🔧 Starting backend server...
start "Backend Server" cmd /k "cd backend && venv\Scripts\activate && python -m uvicorn main:app --reload --port 8000"

REM Wait a moment for backend to start
timeout /t 3 /nobreak >nul

REM Start frontend in a new window
echo 🎨 Starting frontend server...
start "Frontend Server" cmd /k "cd frontend && npm start"

echo.
echo ✅ Development servers started!
echo 📱 Frontend: http://localhost:3000
echo 🔧 Backend: http://localhost:8000
echo 📚 API Docs: http://localhost:8000/docs
echo.
echo Both servers are running in separate windows.
echo Close the windows to stop the servers.
pause
