@echo off
setlocal enabledelayedexpansion
title Git Safe Synchronizer [Pull-Before-Push]
cd /d "%~dp0"

echo ========================================================
echo   Git Safe Synchronizer (Pull-Verify-Push Pipeline)
echo ========================================================

:: 1. Verify Git Repository
if not exist ".git" (
    echo [-] Error: Not a git repository.
    pause
    exit /b 1
)

:: 2. Check for local modifications
git status --porcelain > "%TEMP%\git_status.tmp"
for %%R in ("%TEMP%\git_status.tmp") do (
    if %%~zR gtr 0 (
        set HAS_CHANGES=1
    ) else (
        set HAS_CHANGES=0
    )
)
del "%TEMP%\git_status.tmp" 2>nul

:: 3. Commit local changes if any exist
if "!HAS_CHANGES!"=="1" (
    echo [*] Detected uncommitted local changes.
    set /p "COMMIT_MSG=Enter commit message (Leave blank for auto-timestamp): "
    if "!COMMIT_MSG!"=="" (
        for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set dt=%%I
        set "COMMIT_MSG=chore: auto update !dt:~0,8!-!dt:~8,6!"
    )
    git add .
    git commit -m "!COMMIT_MSG!"
) else (
    echo [*] Working tree clean. Checking remote synchronization...
)

:: 4. Fetch upstream state to check for remote commits
echo [*] Fetching upstream state from origin/main...
git fetch origin main >nul 2>&1

:: 5. Compare commit differences
set BEHIND_COUNT=0
set AHEAD_COUNT=0

for /f %%i in ('git rev-list HEAD..origin/main --count 2^>nul') do set BEHIND_COUNT=%%i
for /f %%i in ('git rev-list origin/main..HEAD --count 2^>nul') do set AHEAD_COUNT=%%i

echo [+] Remote Status: !BEHIND_COUNT! commits behind, !AHEAD_COUNT! commits ahead.

:: 6. Pull with rebase if remote is ahead
if !BEHIND_COUNT! gtr 0 (
    echo [!] Remote has newer commits. Pulling upstream changes (git pull --rebase)...
    git pull --rebase origin main
    if !errorlevel! neq 0 (
        echo [-] Conflict detected during rebase.
        echo [*] Aborting rebase to preserve your working tree...
        git rebase --abort
        echo [-] Resolve conflicts manually, then re-run this script.
        pause
        exit /b 1
    )
    echo [+] Successfully merged remote commits.
)

:: 7. Push to origin main
echo [*] Pushing to origin/main...
git push origin main
if !errorlevel! equ 0 (
    echo ========================================================
    echo [+] Push Completed Successfully!
    echo ========================================================
) else (
    echo [-] Push failed. Check your network or GitHub permissions.
)

echo.
pause
