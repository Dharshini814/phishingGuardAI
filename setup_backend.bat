@echo off
echo ============================================================
echo  PhishGuard AI - Backend Setup
echo ============================================================
echo.

cd /d "%~dp0backend"

echo [1/4] Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.11+
    pause
    exit /b 1
)

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat

echo [3/4] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed.
    pause
    exit /b 1
)

echo [4/4] Running setup (generate dataset + train models)...
python setup.py
if errorlevel 1 (
    echo ERROR: Setup script failed.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Backend setup complete!
echo  Now run: start_backend.bat
echo ============================================================
pause
