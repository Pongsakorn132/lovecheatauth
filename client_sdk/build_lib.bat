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

set BUILD_DIR=%~dp0build
set DIST_DIR=%~dp0dist

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%DIST_DIR%\include" mkdir "%DIST_DIR%\include"
if not exist "%DIST_DIR%\lib" mkdir "%DIST_DIR%\lib"

echo [*] Configuring CMake project...
cmake -B "%BUILD_DIR%" -S "%~dp0" -A x64
if %errorlevel% neq 0 (
    echo [ERROR] CMake configuration failed!
    pause
    exit /b %errorlevel%
)

echo.
echo [*] Building KawaiiAuth.lib (Release x64)...
cmake --build "%BUILD_DIR%" --config Release --target KawaiiAuth
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b %errorlevel%
)

echo.
echo ================================================================
echo [SUCCESS] KawaiiAuth.lib has been built successfully!
echo ================================================================
echo Header : %DIST_DIR%\include\KawaiiAuth.h
echo Library: %DIST_DIR%\lib\KawaiiAuth.lib
echo.
echo You can now copy KawaiiAuth.h and KawaiiAuth.lib into your own
echo project and simply use:
echo.
echo   #include "KawaiiAuth.h"
echo.
echo ================================================================
pause
