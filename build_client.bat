@echo off
setlocal enabledelayedexpansion
title KawaiiAuth C++ Client Compiler
cd /d "%~dp0"

echo ========================================================
echo   Compiling KawaiiAuth Native C++ Client
echo ========================================================

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" (
    set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
)

if not exist "!VSWHERE!" (
    echo [-] Error: Visual Studio Installer / vswhere not found.
    echo [*] Please install Visual Studio 2022/2026 with 'Desktop development with C++'.
    pause
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -property installationPath`) do (
    set "VS_PATH=%%i"
)

if not defined VS_PATH (
    echo [-] Error: No valid Visual Studio installation found.
    pause
    exit /b 1
)

echo [+] Found Visual Studio: !VS_PATH!
set "VCVARS=!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"

if not exist "!VCVARS!" (
    echo [-] Error: vcvars64.bat not found at !VCVARS!
    pause
    exit /b 1
)

echo [+] Loading MSVC x64 build environment...
call "!VCVARS!" >nul 2>&1

echo [*] Compiling C++20 Client with optimizations (/O2)...
cd "%~dp0\client_cpp"

cl.exe /std:c++20 /EHsc /O2 /W3 /I include src\kawaii_auth.cpp src\security.cpp src\main.cpp /Fe:"%~dp0\KawaiiClient.exe" /link wininet.lib bcrypt.lib crypt32.lib user32.lib >nul 2>&1

if %errorlevel% neq 0 (
    echo [-] Compilation failed. Running verbose build to display errors:
    cl.exe /std:c++20 /EHsc /O2 /W3 /I include src\kawaii_auth.cpp src\security.cpp src\main.cpp /Fe:"%~dp0\KawaiiClient.exe" /link wininet.lib bcrypt.lib crypt32.lib user32.lib
    pause
    exit /b 1
)

del /q *.obj >nul 2>&1
cd /d "%~dp0"

echo ========================================================
echo [+] Build Successful!
echo [+] Executable: %~dp0KawaiiClient.exe
echo ========================================================
echo.
pause
