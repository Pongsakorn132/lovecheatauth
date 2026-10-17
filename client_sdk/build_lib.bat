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
    echo [ERROR] KawaiiAuth.lib build failed!
    popd
    pause
    exit /b %errorlevel%
)

echo.
echo [*] Syncing KawaiiAuth.h and KawaiiAuth.lib to example/ and dist/...
if not exist "example" mkdir "example"
copy /y "include\KawaiiAuth.h" "dist\include\KawaiiAuth.h" >nul
copy /y "build\lib\Release\KawaiiAuth.lib" "dist\lib\KawaiiAuth.lib" >nul
copy /y "include\KawaiiAuth.h" "example\KawaiiAuth.h" >nul
copy /y "build\lib\Release\KawaiiAuth.lib" "example\KawaiiAuth.lib" >nul

echo.
echo [*] Building KawaiiAuthExample (Release x64)...
cmake --build build --config Release --target KawaiiAuthExample
if %errorlevel% neq 0 (
    echo [ERROR] Example build failed!
    popd
    pause
    exit /b %errorlevel%
)

echo.
echo ================================================================
echo [SUCCESS] KawaiiAuth.lib and Example built successfully!
echo ================================================================
echo [1] Library Distribution:
echo     - Header : %~dp0dist\include\KawaiiAuth.h
echo     - Library: %~dp0dist\lib\KawaiiAuth.lib
echo.
echo [2] Standalone Example:
echo     - Directory : %~dp0example\
echo     - Header    : %~dp0example\KawaiiAuth.h
echo     - Library   : %~dp0example\KawaiiAuth.lib
echo     - Executable: %~dp0example\KawaiiAuthExample.exe
echo.
echo You can run the example directly from:
echo   %~dp0example\KawaiiAuthExample.exe
echo ================================================================
popd
pause
