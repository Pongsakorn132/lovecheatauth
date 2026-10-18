@echo off
title KawaiiAuth Server Gateway
cd /d "%~dp0\server"

echo ========================================================
echo   Starting KawaiiAuth Licensing Server
echo ========================================================

where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [-] Error: Node.js is not found in PATH.
    echo [*] Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

echo [*] Checking port 8080 availability...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8080 ^| findstr LISTENING') do (
    echo [*] Freeing port 8080 (Terminating existing PID: %%a)...
    taskkill /f /pid %%a >nul 2>nul
)

echo [+] Launching Web Dashboard in default browser...
start "" "http://localhost:8080/dashboard"

echo [+] Initializing server engine on port 8080...
node src\server.js

pause
