@echo off
echo 🧪 Running tests for Censys Host Summarizer...

REM Get the project root directory
set "PROJECT_ROOT=%~dp0.."
cd /d "%PROJECT_ROOT%"

echo Project root: %PROJECT_ROOT%

echo.
echo === Backend Tests ===
cd backend
echo Running backend tests...
python -m pytest ..\tests\backend\test_main.py -v --tb=short
if errorlevel 1 (
    echo Trying alternative pytest command...
    C:\Users\Admin\AppData\Roaming\Python\Python312\Scripts\pytest.exe ..\tests\backend\test_main.py -v --tb=short
)
cd ..

echo.
echo === Frontend Tests ===
cd frontend
if exist "package.json" (
    echo Running frontend tests...
    set CI=true
    npm test -- --coverage --watchAll=false --passWithNoTests
) else (
    echo Frontend package.json not found, skipping frontend tests
)
cd ..

echo.
echo === Test Summary ===
echo Tests completed. Check the output above for results.
pause
