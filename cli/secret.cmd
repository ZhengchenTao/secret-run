@echo off
rem secret.cmd -- cmd / PowerShell shim for secret.ps1 (prefers pwsh, falls back to Windows PowerShell 5.1).
setlocal
set "SECRET_PS=powershell.exe"
rem pwsh only if it actually starts (Store alias is access-denied inside sshd sessions)
pwsh -NoProfile -NonInteractive -Command "exit 0" >nul 2>nul && set "SECRET_PS=pwsh"
"%SECRET_PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0secret.ps1" %*
exit /b %errorlevel%
