@echo off
echo ============================================================
echo  PhishGuard AI - Starting Backend Server
echo ============================================================
echo.

cd /d "%~dp0backend"
call venv\Scripts\activate.bat

echo Backend starting at: http://localhost:8000
echo API docs at:         http://localhost:8000/docs
echo Press Ctrl+C to stop.
echo.
uvicorn app:app --reload --port 8000
pause
