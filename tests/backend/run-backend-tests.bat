@echo off
echo 🧪 Running Backend Tests...

REM Go to project root
cd ..\..

REM Go to backend directory
cd backend

REM Run tests
echo Running backend tests...
C:\Users\Admin\AppData\Roaming\Python\Python312\Scripts\pytest.exe ..\tests\backend\test_main.py -v --tb=short

echo.
echo Backend tests completed.
pause
