@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ci\sync_version.ps1" %*
set "EXITCODE=%ERRORLEVEL%"
echo.
echo Exit code: %EXITCODE%
echo.
pause
exit /b %EXITCODE%
