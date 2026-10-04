@echo off
set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%frontend"
echo Running npm install in %CD%
npm install
echo npm install exit code: %ERRORLEVEL%
if exist node_modules\react echo React installed OK
