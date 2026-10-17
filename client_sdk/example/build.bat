@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo   KawaiiAuth SDK - Standalone Example Builder
echo ================================================================
echo.

pushd "%~dp0"

where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] CMake is not found in PATH!
    echo Please install CMake or run from Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

echo [*] Configuring Example project...
cmake -B build -S . -A x64
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed!
    popd
    pause
    exit /b %errorlevel%
)

echo.
echo [*] Building KawaiiAuthExample (Release x64)...
cmake --build build --config Release
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    popd
    pause
    exit /b %errorlevel%
)

echo.
echo ================================================================
echo [SUCCESS] Example built successfully!
echo Executable: %~dp0KawaiiAuthExample.exe
echo ================================================================
popd
pause
