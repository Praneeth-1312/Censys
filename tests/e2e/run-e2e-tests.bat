@echo off
echo 🧪 Running E2E Tests...

REM Go to project root
cd ..\..

REM Go to e2e tests directory
cd tests\e2e

REM Install dependencies and run tests
echo Installing E2E test dependencies...
npm install

echo Running E2E tests...
npm test

echo.
echo E2E tests completed.
pause
