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
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"

echo [+] Launching Landing Portal in default browser...
start "" "http://localhost:8080/"

echo [+] Initializing server engine on port 8080...
node src\server.js

pause