@echo off
echo 🧪 Running all tests for Censys Host Summarizer...

REM Get the project root directory
set "PROJECT_ROOT=%~dp0.."
cd /d "%PROJECT_ROOT%"

echo Project root: %PROJECT_ROOT%

REM Track overall success
set "overall_success=true"

echo.
echo === Backend Tests ===
cd backend

REM Try to activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo No virtual environment found, using system Python
)

REM Try different ways to run pytest
echo Running backend tests...
python -m pytest ..\tests\backend\test_main.py -v --tb=short
if errorlevel 1 (
    echo Trying alternative pytest command...
    C:\Users\Admin\AppData\Roaming\Python\Python312\Scripts\pytest.exe ..\tests\backend\test_main.py -v --tb=short
    if errorlevel 1 (
        echo ❌ Backend tests failed
        set "overall_success=false"
    ) else (
        echo ✅ Backend tests passed
    )
) else (
    echo ✅ Backend tests passed
)
cd ..

echo.
echo === Frontend Tests ===
cd frontend

REM Check if package.json exists
if not exist "package.json" (
    echo ❌ Frontend package.json not found
    set "overall_success=false"
) else (
    echo Running frontend tests...
    REM Set CI environment variable to prevent interactive mode
    set CI=true
    npm test -- --coverage --watchAll=false --passWithNoTests
    if errorlevel 1 (
        echo ❌ Frontend tests failed
        set "overall_success=false"
    ) else (
        echo ✅ Frontend tests passed
    )
)
cd ..

echo.
echo === E2E Tests ===
echo Checking if services are running for E2E tests...

REM Check if backend is running
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Backend is not running on http://localhost:8000
    echo To run E2E tests, start the backend with: cd backend ^&^& venv\Scripts\activate ^&^& python -m uvicorn main:app --reload --port 8000
) else (
    echo ✅ Backend is running on http://localhost:8000
    
    REM Check if frontend is running
    curl -s http://localhost:3000 >nul 2>&1
    if errorlevel 1 (
        echo ⚠️  Frontend is not running on http://localhost:3000
        echo To run E2E tests, start the frontend with: cd frontend ^&^& npm start
    ) else (
        echo ✅ Frontend is running on http://localhost:3000
        
        REM Run E2E tests
        cd tests\e2e
        npm install
        npm test
        if errorlevel 1 (
            echo ❌ E2E tests failed
            set "overall_success=false"
        ) else (
            echo ✅ E2E tests passed
        )
        cd ..\..
    )
)

echo.
echo === Test Summary ===
if "%overall_success%"=="true" (
    echo 🎉 All tests passed!
    echo ✅ Backend tests: PASSED
    echo ✅ Frontend tests: PASSED
    curl -s http://localhost:8000/health >nul 2>&1 && curl -s http://localhost:3000 >nul 2>&1
    if errorlevel 1 (
        echo ⚠️  E2E tests: SKIPPED (services not running)
    ) else (
        echo ✅ E2E tests: PASSED
    )
    exit /b 0
) else (
    echo 💥 Some tests failed. Check the output above for details.
    echo ❌ Check the test output above to identify which tests failed
    exit /b 1
)

