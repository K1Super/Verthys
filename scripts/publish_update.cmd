@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\release\publish_update.ps1" -NoPause %*
set "EXITCODE=%ERRORLEVEL%"
echo.
echo Exit code: %EXITCODE%
echo.
pause
exit /b %EXITCODE%
