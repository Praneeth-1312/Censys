@echo off
echo 🧪 Running tests from tests/ directory...

REM Get the project root directory (go up one level from tests/)
set "PROJECT_ROOT=%~dp0.."
cd /d "%PROJECT_ROOT%"

echo Project root: %PROJECT_ROOT%

echo.
echo === Backend Tests ===
cd backend
echo Running backend tests...
C:\Users\Admin\AppData\Roaming\Python\Python312\Scripts\pytest.exe ..\tests\backend\test_main.py -v --tb=short
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
echo === E2E Tests ===
cd tests\e2e
if exist "package.json" (
    echo Running E2E tests...
    npm install
    npm test
) else (
    echo E2E package.json not found, skipping E2E tests
)
cd ..\..

echo.
echo === Test Summary ===
echo Tests completed. Check the output above for results.
pause
