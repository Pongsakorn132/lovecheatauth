@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo   KawaiiAuth SDK - Static Library (.lib) Builder
echo ================================================================
echo.

where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] CMake is not found in PATH!
    echo Please install CMake or run from Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

pushd "%~dp0"

if not exist "build" mkdir "build"
if not exist "dist\include" mkdir "dist\include"
if not exist "dist\lib" mkdir "dist\lib"

echo [*] Configuring CMake project...
cmake -B build -S . -A x64
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed!
    popd
    pause
    exit /b %errorlevel%
)

echo.
echo [*] Building KawaiiAuth.lib (Release x64)...
cmake --build build --config Release --target KawaiiAuth
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    popd
    pause
    exit /b %errorlevel%
)

echo.
echo ================================================================
echo [SUCCESS] KawaiiAuth.lib has been built successfully!
echo ================================================================
echo Header : %~dp0dist\include\KawaiiAuth.h
echo Library: %~dp0dist\lib\KawaiiAuth.lib
echo.
echo You can now copy KawaiiAuth.h and KawaiiAuth.lib into your own
echo project and simply use:
echo.
echo   #include "KawaiiAuth.h"
echo.
echo ================================================================
popd
pause
