@echo off
rem Self-locating setup. Works from wherever this folder is dropped.
rem Usage: Setup-Hashslinger.cmd [-Phase Check|Local|Domain|All] [-InitConfig path] [-WhatIf]
rem Policy is bypassed for the setup process only (your explicit run). Unblocks the folder first.
set "HERE=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath '%HERE%' -Recurse -File | Unblock-File; & '%HERE%powershell\Setup-Hashslinger.ps1' %*"
pause
