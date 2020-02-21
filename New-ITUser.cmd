@echo off
cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -File ".\New-ITUser.ps1"
pause