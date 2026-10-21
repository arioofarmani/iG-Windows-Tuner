@echo off
rem iG Windows Tuner launcher.
rem Starts the GUI with the inbox Windows PowerShell 5.1 in a visible window (STA for WPF).
rem "-ExecutionPolicy Bypass" applies to this PowerShell process only; the machine and user
rem execution policies are never changed. iG Windows Tuner starts read-only; it asks for elevation
rem through the normal UAC prompt only when you choose to apply changes.
rem Pass parameters through, for example:  Start-iGWindowsTuner.cmd -Report
setlocal
set "IGWT_SCRIPT=%~dp0iGWindowsTuner.ps1"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -STA -File "%IGWT_SCRIPT%" %*
set "IGWT_EXIT=%ERRORLEVEL%"
endlocal & exit /b %IGWT_EXIT%