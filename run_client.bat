@echo off
title KawaiiAuth Client Runner
cd /d "%~dp0"

if not exist "%~dp0\KawaiiClient.exe" (
    echo [*] KawaiiClient.exe not found. Triggering build script...
    call "%~dp0\build_client.bat"
)

if exist "%~dp0\KawaiiClient.exe" (
    echo [+] Executing KawaiiClient.exe...
    "%~dp0\KawaiiClient.exe"
) else (
    echo [-] Build failed or binary not found.
)

echo.
pause
