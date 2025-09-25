@echo off
echo 🧪 Running Frontend Tests...

REM Go to project root
cd ..\..

REM Go to frontend directory
cd frontend

REM Run tests
echo Running frontend tests...
set CI=true
npm test -- --coverage --watchAll=false --passWithNoTests

echo.
echo Frontend tests completed.
pause
