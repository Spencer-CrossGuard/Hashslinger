@echo off
rem Self-locating setup. Works from wherever this folder is dropped.
rem   Double-click (no arguments) : guided wizard (recommended).
rem   Advanced: Setup-Hashslinger.cmd -Phase Check|Local|Domain|All [-InitConfig path] [-WhatIf]
rem Policy is bypassed for the setup process only (your explicit run). Unblocks the folder first.
set "HERE=%~dp0"
if "%~1"=="" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%HERE%' -Recurse -File | Unblock-File; & '%HERE%powershell\Setup-Wizard.ps1'"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%HERE%' -Recurse -File | Unblock-File; & '%HERE%powershell\Setup-Hashslinger.ps1' %*"
pause
