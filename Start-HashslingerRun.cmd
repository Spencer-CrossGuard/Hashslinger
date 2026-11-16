@echo off
rem Double-click launcher. Policy is bypassed for THIS launcher process only (your explicit run).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0powershell\Start-HashslingerRun.ps1"
