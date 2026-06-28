@echo off
setlocal
rem PactMesh installer launcher: elevates and runs install.ps1 from this folder.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

set "PS1=%~dp0install.ps1"
if not exist "%PS1%" (
    echo install.ps1 not found next to this launcher.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
echo.
pause
