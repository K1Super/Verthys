@echo off
chcp 65001 >nul
rem ---------------------------------------------------------------
rem  Verthys elevated verification window (English only).
rem  Runs the full core test suite in an elevated console with
rem  live output. Closes automatically on success, stays open on
rem  failure. Progress is also saved to .trae\elevated_verify.log
rem  (UTF-8) for audit / resume purposes.
rem ---------------------------------------------------------------
title Verthys Elevated Verification - DO NOT CLOSE
echo.
echo ============================================================
echo   Verthys elevated verification
echo   Running the full core test suite (about 2-3 minutes).
echo   Keep this window open. It closes by itself when done.
echo ============================================================
echo.

pushd "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -Command "$Host.UI.RawUI.WindowTitle='Verthys elevated verification - running'; & '.\scripts\build_core.dev.ps1' -NoPause 2>&1 | ForEach-Object { $_; $_ | Out-File -FilePath '.\.trae\elevated_verify.log' -Append -Encoding utf8 }"

if errorlevel 1 goto :fail

echo.
echo ============================================================
echo   VERIFICATION PASSED - window closes automatically.
echo ============================================================
timeout /t 3 >nul
exit /b 0

:fail
echo.
echo ============================================================
echo   VERIFICATION FAILED - review the output above.
echo   Press any key to close this window.
echo ============================================================
pause >nul
exit /b 1