@echo off
echo ============================================================
echo  PhishGuard AI - Full Setup and Launch
echo ============================================================

REM Get the directory where this batch file is located
set "PROJECT_DIR=%~dp0"

REM Step 1: npm install
echo [1/3] Installing frontend npm dependencies...
cd /d "%PROJECT_DIR%frontend"
call npm install
if errorlevel 1 (
    echo ERROR: npm install failed
    pause
    exit /b 1
)
echo npm install complete.

REM Step 2: Start FastAPI backend in new window
echo [2/3] Starting FastAPI backend on port 8000...
start "PhishGuard Backend" cmd /k "cd /d "%PROJECT_DIR%backend" && python -m uvicorn app:app --reload --port 8000"

REM Step 3: Wait a moment then start Vite frontend in new window
timeout /t 3 /nobreak >nul
echo [3/3] Starting Vite frontend on port 5173...
start "PhishGuard Frontend" cmd /k "cd /d "%PROJECT_DIR%frontend" && npm run dev"

echo.
echo ============================================================
echo  Both servers launching in separate windows!
echo  Backend:  http://localhost:8000
echo  Frontend: http://localhost:5173
echo  API Docs: http://localhost:8000/docs
echo ============================================================
timeout /t 5 /nobreak >nul
start "" "http://localhost:5173"
