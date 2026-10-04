@echo off
echo ============================================================
echo  PhishGuard AI - Frontend Setup + Start
echo ============================================================
echo.

cd /d "%~dp0frontend"

echo [1/2] Installing npm dependencies...
npm install
if errorlevel 1 (
    echo ERROR: npm install failed. Ensure Node.js 18+ is installed.
    pause
    exit /b 1
)

echo.
echo [2/2] Starting React frontend...
echo Frontend at: http://localhost:5173
echo Press Ctrl+C to stop.
echo.
npm run dev
pause
