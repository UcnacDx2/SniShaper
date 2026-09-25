@echo off
setlocal
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-snishaper-tline.ps1"
if errorlevel 1 (
  echo.
  echo Startup failed. Exit code: %errorlevel%
  pause
  exit /b %errorlevel%
)
echo.
pause